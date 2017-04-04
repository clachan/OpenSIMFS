#include <linux/fs.h>
#include "opensimfs.h"

static loff_t opensimfs_llseek(
	struct file *file,
	loff_t offset,
	int origin)
{
	return offset;
}

static int opensimfs_open(
	struct inode *inode,
	struct file *filp)
{
	return generic_file_open(inode, filp);
}

int opensimfs_fsync(
	struct file *file,
	loff_t start,
	loff_t end,
	int datasync)
{
	return 0;
}

static int opensimfs_flush(
	struct file *file, fl_owner_t id)
{
	PERSISTENT_BARRIER();
	return 0;
}

struct file_operations opensimfs_dax_file_operations = {
	.llseek		= opensimfs_llseek,
	.read		= opensimfs_dax_file_read,
	.write		= opensimfs_dax_file_write,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= opensimfs_dax_file_mmap,
	.open		= opensimfs_open,
	.fsync		= opensimfs_fsync,
	.flush		= opensimfs_flush,
	/*
	.unlocked_ioctl	= opensimfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= opensimfs_compat_ioctl,
#endif
	*/
};

struct inode_operations opensimfs_file_inode_operations = {
	.setattr 	= opensimfs_notify_change,
	.getattr 	= opensimfs_getattr,
	.get_acl 	= NULL,
};
