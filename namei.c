#include <linux/fs.h>
#include <linux/dcache.h>
#include "opensimfs.h"

struct dentry *opensimfs_get_parent(
	struct dentry *child)
{
	return NULL;
}

static int opensimfs_create(
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode,
	bool excl)
{
	return 0;
}

struct inode_operations opensimfs_dir_inode_operations = {
	.create		= opensimfs_create,
	.setattr	= opensimfs_notify_change,
	.get_acl	= NULL,
};

struct inode_operations opensimfs_special_inode_operations = {
	.setattr	= opensimfs_notify_change,
	.get_acl	= NULL,
};
