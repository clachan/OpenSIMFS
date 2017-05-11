#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/buffer_head.h>
#include <linux/dax.h>
#include <linux/pfn_t.h>
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
	struct opensimfs_inode *pi;
	char *p;
	unsigned long *ppte;
	unsigned long pte;
	loff_t isize;

	isize = i_size_read(inode);
	if (*ppos >= isize)
		return 0;

	pi = opensimfs_get_inode(sb, inode);

	ppte = (unsigned long *)opensimfs_get_block(sb,
		opensimfs_get_block_offset(sb, sih->pte_block, OPENSIMFS_BLOCK_TYPE_4K));
	pte = *ppte;
	p = (char *)opensimfs_get_block(sb, opensimfs_get_block_offset(sb, pte, OPENSIMFS_BLOCK_TYPE_4K));

	__copy_to_user(buf, p, inode->i_size);
	*ppos += isize;

	file_accessed(filp);
	return isize;
}

ssize_t opensimfs_dax_file_read(
	struct file *filp,
	char __user *buf,
	size_t len,
	loff_t *ppos)
{
	return do_dax_mapping_read(filp, buf, len, ppos);
}

static void opensimfs_pseudo_file_write(
	const char __user *buf,
	size_t len,
	loff_t *ppos,
	struct super_block *sb,
	struct opensimfs_inode_info_header *sih)
{
	unsigned long *ppte;
	unsigned long pte;
	char *p;
	
	ppte = (unsigned long *)opensimfs_get_block(sb,
		opensimfs_get_block_offset(sb, sih->pte_block, OPENSIMFS_BLOCK_TYPE_4K));
	pte = sih->pfw_data_block;
	*ppte = pte;
	p = (char *)opensimfs_get_block(sb, opensimfs_get_block_offset(sb, *ppte, OPENSIMFS_BLOCK_TYPE_4K));
	memcpy_to_pmem_nocache(p, buf, len);
	opensimfs_flush_buffer(p, len, 0);
}

static void opensimfs_update_file_page_table(
	struct opensimfs_inode_info_header *sih)
{
	unsigned long temp;
	temp = sih->data_block;
	sih->data_block = sih->pfw_data_block;
	sih->pfw_data_block = temp;
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
	/*
	char *p;
	unsigned long *ppte;
	unsigned long pte;
	unsigned long temp;
	*/
	ssize_t written;

	pi = opensimfs_get_inode(sb, inode);

	/* simulate pseudo file write */
	/*
	ppte = (unsigned long *)opensimfs_get_block(sb, opensimfs_get_block_offset(sb, sih->pte_block));
	pte = sih->pfw_data_block;
	*ppte = pte;
	p = (char *)opensimfs_get_block(sb, opensimfs_get_block_offset(sb, *ppte));
	memcpy_to_pmem_nocache(p, buf, len);
	opensimfs_flush_buffer(p, len, 0);
	*/
	opensimfs_pseudo_file_write(buf, len, ppos, sb, sih);

	/* simulate update page table */
	/* rotation of data_block and pfw_data_block */
	/*
	temp = sih->data_block;
	sih->data_block = sih->pfw_data_block;
	sih->pfw_data_block = temp;
	*/
	opensimfs_update_file_page_table(sih);

	written = len;

	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	pi->i_blocks = 1;
	inode->i_blocks = le64_to_cpu(pi->i_blocks);
	i_size_write(inode, written);
	sih->i_size = written;

	return written;
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
