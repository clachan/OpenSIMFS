#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/buffer_head.h>
#include <linux/dax.h>
#include <linux/pfn_t.h>
#include <asm/page_types.h>
#include "opensimfs.h"

static ssize_t do_dax_mapping_read(
	struct file *filp,
	char __user *buf,
	size_t len,
	loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct opensimfs_inode_info *si = OPENSIMFS_I(inode);
	struct opensimfs_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct opensimfs_inode *pi;
	char *p;
	pte_t *ppte;
	unsigned long pfn;
	loff_t isize;

	isize = i_size_read(inode);
	if (*ppos >= isize)
		return 0;

	pi = opensimfs_get_inode(sb, inode);

	ppte = (pte_t *)opensimfs_get_block(sb,
		opensimfs_get_block_offset(sb, sih->pte_block, OPENSIMFS_BLOCK_TYPE_4K));
	pfn = pte_pfn(*ppte);
	p = (char *)opensimfs_get_block(sb,
		opensimfs_get_block_offset(sb, pfn - sbi->phys_addr, OPENSIMFS_BLOCK_TYPE_4K));

	p += *ppos;
	__copy_to_user(buf, p, len);
	*ppos += len;

	file_accessed(filp);
	return len;
}

ssize_t opensimfs_dax_file_read(
	struct file *filp,
	char __user *buf,
	size_t len,
	loff_t *ppos)
{
	return do_dax_mapping_read(filp, buf, len, ppos);
}

static void opensimfs_update_file_page_table(
	struct super_block *sb,
	struct opensimfs_inode_info_header *sih,
	unsigned long start_block,
	unsigned long blocknr,
	unsigned long num_blocks)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	unsigned long i;
	pte_t *p = (pte_t *)opensimfs_get_block(sb,
		opensimfs_get_block_offset(sb, sih->pte_block, OPENSIMFS_BLOCK_TYPE_4K));

	for (i = 0; i < num_blocks; i++) {
		*(p + start_block + i) = pfn_pte(sbi->phys_addr + blocknr + i, PAGE_SHARED);
	}
}

static void opensimfs_handle_head_tail_blocks(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	struct inode *inode,
	loff_t pos,
	size_t count,
	void *kmem)
{
	size_t offset, eblock_offset;
	unsigned long start_block, end_block, num_blocks;

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	offset = pos & (opensimfs_inode_blk_size(pi) - 1);
	start_block = pos >> sb->s_blocksize_bits;
	end_block = start_block + num_blocks - 1;

	if (offset != 0) {
		/* FIXME: should lookup for the original data block */
		memset(kmem, 0, offset);
		opensimfs_flush_buffer(kmem, offset, 0);
	}

	kmem = (void *)((char *)kmem + ((num_blocks - 1) << sb->s_blocksize_bits));
	eblock_offset = (pos + count) & (opensimfs_inode_blk_size(pi) - 1);
	if (eblock_offset != 0) {
		/* FIXME: should lookup for the original data block */
		memset(kmem + eblock_offset, 0, sb->s_blocksize - eblock_offset);
		opensimfs_flush_buffer(kmem + eblock_offset, sb->s_blocksize - eblock_offset, 0);
	}
}

ssize_t opensimfs_dax_file_write(
	struct file *filp,
	const char __user *buf,
	size_t len,
	loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct opensimfs_inode_info *si = OPENSIMFS_I(inode);
	struct opensimfs_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct opensimfs_inode *pi;
	struct opensimfs_file_write_entry entry_data;
	ssize_t written = 0;
	loff_t pos;
	size_t count, offset, copied, ret;
	unsigned long num_blocks;
	unsigned long start_block;
	unsigned long total_blocks;
	unsigned long blocknr = 0;
	unsigned long step = 0;
	unsigned int data_bits;
	long status = 0;
	size_t bytes;
	int allocated = 0;
	void *kmem;
	u32 time;
	u64 curr_entry;
	u64 temp_tail = 0, begin_tail = 0;

	if (len == 0)
		return 0;

	if (mapping_mapped(mapping))
		return -EACCES;

	sb_start_write(inode->i_sb);
	mutex_lock(&inode->i_mutex);

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;

	pi = opensimfs_get_inode(sb, inode);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;

	ret = file_remove_privs(filp);
	if (ret) {
		goto out;
	}
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;

	temp_tail = pi->log_tail;
	while (num_blocks > 0) {
		offset = pos & (opensimfs_inode_blk_size(pi) - 1);
		start_block = pos >> sb->s_blocksize_bits;

		allocated = opensimfs_new_data_blocks(sb, pi, &blocknr,
			num_blocks, 0);

		if (allocated <= 0) {
			ret = allocated;
			goto out;
		}

		step++;
		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		kmem = opensimfs_get_block(inode->i_sb,
			opensimfs_get_block_offset(sb, blocknr, pi->i_blk_type));

		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
				buf, bytes);

		if (offset || ((offset + bytes) & (PAGE_SIZE - 1)) != 0)
			opensimfs_handle_head_tail_blocks(sb, pi, inode, pos, bytes, kmem);

		opensimfs_update_file_page_table(sb, sih, start_block, blocknr, allocated);

		entry_data.pgoff = cpu_to_le64(start_block);
		entry_data.num_pages = cpu_to_le32(allocated);
		entry_data.invalid_pages = 0;
		entry_data.block = cpu_to_le64(opensimfs_get_block_offset(sb, blocknr, pi->i_blk_type));
		entry_data.mtime = cpu_to_le32(time);
		opensimfs_set_entry_type((void *)&entry_data, FILE_WRITE);

		if (pos + copied > inode->i_size)
			entry_data.size = cpu_to_le64(pos + copied);
		else
			entry_data.size = cpu_to_le64(inode->i_size);

		curr_entry = opensimfs_append_file_write_entry(sb, pi, inode,
			&entry_data, temp_tail);
		if (curr_entry == 0) {
			ret = -ENOSPC;
			goto out;
		}

		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			buf += copied;
			count -= copied;
			num_blocks -= allocated;
		}

		if (unlikely(copied != bytes)) {
			if (status >= 0)
				status = -EFAULT;
		}

		if (status < 0)
			break;

		if (begin_tail == 0)
			begin_tail = curr_entry;
		temp_tail = curr_entry + sizeof(struct opensimfs_file_write_entry);
	}

	data_bits = opensimfs_blk_type_to_shift[pi->i_blk_type];
	le64_add_cpu(&pi->i_blocks,
		(total_blocks << (data_bits - sb->s_blocksize_bits)));

	opensimfs_update_log_tail(pi, temp_tail);

	inode->i_blocks = le64_to_cpu(pi->i_blocks);

	ret = written;
	*ppos = pos;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		sih->i_size = pos;
	}

out:
	mutex_unlock(&inode->i_mutex);
	sb_end_write(inode->i_sb);
	return ret;
}

static int opensimfs_dax_fault(
	struct vm_area_struct *vma,
	struct vm_fault *vmf)
{
	return -EINVAL;
}

static int opensimfs_dax_pmd_fault(
	struct vm_area_struct *vma,
	unsigned long addr,
	pmd_t *pmd,
	unsigned int flags)
{
	return -EINVAL;
}

static int opensimfs_dax_pfn_mkwrite(
	struct vm_area_struct *vma,
	struct vm_fault *vmf)
{
	int ret = 0;

	return ret;
}

static const struct vm_operations_struct opensimfs_dax_vm_ops = {
	.fault = opensimfs_dax_fault,
	.pmd_fault = opensimfs_dax_pmd_fault,
	.page_mkwrite = opensimfs_dax_fault,
	.pfn_mkwrite = opensimfs_dax_pfn_mkwrite,
};

int opensimfs_dax_file_mmap(
	struct file *file,
	struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(vma->vm_file);
	struct super_block *sb = inode->i_sb;
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct opensimfs_inode_info *si = OPENSIMFS_I(inode);
	struct opensimfs_inode_info_header *sih = &si->header;
	unsigned long data_block;
	pfn_t pfn;
	int ret;

	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;
	vma->vm_ops = &opensimfs_dax_vm_ops;

	data_block = sih->data_block;
	pfn = pfn_to_pfn_t(sbi->phys_addr + data_block);
	ret = vm_insert_mixed(vma, vma->vm_start, pfn);

	return ret;
}
