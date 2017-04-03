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
	struct inode *inode = NULL;
	int err = PTR_ERR(inode);
	struct super_block *sb = dir->i_sb;
	struct opensimfs_inode *pidir;
	u64 ino;
	u64 pi_addr;

	pidir = opensimfs_get_inode(sb, dir);
	if (!pidir)
		goto out_err;

	ino = opensimfs_new_opensimfs_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	err = opensimfs_add_dentry(dentry, ino, 0);
	if (err)
		goto out_err;

	inode = opensimfs_new_vfs_inode(TYPE_CREATE,
		dir, pi_addr, ino, mode, 0, 0, &dentry->d_name);
	if (IS_ERR(inode))
		goto out_err;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	return err;
out_err:
	return err;
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
