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
	return len;	
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
