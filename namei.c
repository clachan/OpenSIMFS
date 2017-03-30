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

static struct dentry *opensimfs_lookup(
	struct inode *dir,
	struct dentry *dentry,
	unsigned int flags)
{
	return NULL;
}

struct inode_operations opensimfs_dir_inode_operations = {
	.create		= opensimfs_create,
	.lookup		= opensimfs_lookup,
	.setattr	= opensimfs_notify_change,
	.get_acl	= NULL,
};

struct inode_operations opensimfs_special_inode_operations = {
	.setattr	= opensimfs_notify_change,
	.get_acl	= NULL,
};
