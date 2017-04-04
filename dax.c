#include <linux/fs.h>
#include <linux/mm.h>
#include "opensimfs.h"

static ssize_t do_dax_mapping_read(
	struct file *file,
	char __user *buf,
	size_t len,
	loff_t *ppos)
{
	return 0;
}

ssize_t opensimfs_dax_file_read(
	struct file *filp,
	char __user *buf,
	size_t len,
	loff_t *ppos)
{
	ssize_t res;

	res = do_dax_mapping_read(filp, buf, len, ppos);

	return res;
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
	char *p;
	ssize_t written;
	size_t ret;

	pi = opensimfs_get_inode(sb, inode);

	p = (char *)opensimfs_get_block(sb, opensimfs_get_block_offset(sb, sih->data_block));
	memcpy_to_pmem_nocache(p, buf, len);
	opensimfs_flush_buffer(p, len, 0);

	written = len;

	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	pi->i_blocks = 1;
	inode->i_blocks = le64_to_cpu(pi->i_blocks);
	i_size_write(inode, written);
	sih->i_size = written;

	ret = written;

	return ret;
}

static int opensimfs_dax_fault(
	struct vm_area_struct *vma,
	struct vm_fault *vmf)
{
	int ret = 0;
	
	return ret;
}

static int opensimfs_dax_pmd_fault(
	struct vm_area_struct *vma,
	unsigned long addr,
	pmd_t *pmd,
	unsigned int flags)
{
	int ret = 0;

	return ret;
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
	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;
	vma->vm_ops = &opensimfs_dax_vm_ops;

	return 0;
}
