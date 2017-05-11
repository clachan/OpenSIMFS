#include <linux/fs.h>
#include <linux/dcache.h>
#include "opensimfs.h"

struct dentry *opensimfs_get_parent(
	struct dentry *child)
{
	return NULL;
}

static void opensimfs_transaction_for_new_inode(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	struct opensimfs_inode *pidir,
	u64 pidir_tail)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct opensimfs_journal_entry entry;
	int cpu;
	u64 journal_tail;

	/* commit a transaction */
	memset(&entry, 0, sizeof(struct opensimfs_journal_entry));
	entry.addrs[0] = (u64)opensimfs_get_address_offset(sbi, &pidir->log_tail);
	entry.addrs[0] |= (u64)8 << 56;
	entry.values[0] = pidir->log_tail;

	entry.addrs[1] = (u64)opensimfs_get_address_offset(sbi, &pi->valid);
	entry.addrs[1] |= (u64) 1 << 56;
	entry.values[1] = pi->valid;

	/* cpu = smp_processor_id(); */
	cpu = 0;
	spin_lock(&sbi->journal_locks[cpu]);
	journal_tail = opensimfs_create_journal_transaction(sb, &entry, NULL, 1, cpu);

	pidir->log_tail = pidir_tail;
	opensimfs_flush_buffer(&pidir->log_tail, CACHELINE_SIZE, 0);
	pi->valid = 1;
	opensimfs_flush_buffer(&pi->valid, CACHELINE_SIZE, 0);
	PERSISTENT_BARRIER();

	opensimfs_commit_journal_transaction(sb, journal_tail, cpu);
	spin_unlock(&sbi->journal_locks[cpu]);
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
	struct opensimfs_inode *pidir, *pi;
	u64 ino;
	u64 pi_addr;
	u64 tail = 0;

	pidir = opensimfs_get_inode(sb, dir);
	if (!pidir)
		goto out_err;

	ino = opensimfs_new_opensimfs_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	err = opensimfs_add_dentry(dentry, ino, 0, 0, &tail);
	if (err)
		goto out_err;

	inode = opensimfs_new_vfs_inode(TYPE_CREATE,
		dir, pi_addr, ino, mode, 0, 0, &dentry->d_name);
	if (IS_ERR(inode))
		goto out_err;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	pi = opensimfs_get_block(sb, pi_addr);
	opensimfs_transaction_for_new_inode(sb, pi, pidir, tail);
	return err;
out_err:
	return err;
}

struct opensimfs_dentry *opensimfs_find_dentry(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	struct inode *inode,
	const char *name,
	unsigned long name_len)
{
	struct opensimfs_inode_info *si = OPENSIMFS_I(inode);
	struct opensimfs_inode_info_header *sih = &si->header;
	struct opensimfs_dentry *direntry;
	unsigned long hash;

	hash = BKDRHash(name, name_len);
	direntry = radix_tree_lookup(&sih->tree, hash);

	return direntry;
}

static ino_t opensimfs_inode_by_name(
	struct inode *dir,
	struct qstr *entry,
	struct opensimfs_dentry **res_entry)
{
	struct super_block *sb = dir->i_sb;
	struct opensimfs_dentry *direntry;

	direntry = opensimfs_find_dentry(sb, NULL, dir, entry->name, entry->len);
	if (direntry == NULL)
		return 0;

	*res_entry = direntry;
	return direntry->ino;
}

static struct dentry *opensimfs_lookup(
	struct inode *dir,
	struct dentry *dentry,
	unsigned int flags)
{
	struct inode *inode = NULL;
	struct opensimfs_dentry *de;
	ino_t ino;

	if (dentry->d_name.len > OPENSIMFS_NAME_LEN) {
		return ERR_PTR(-ENAMETOOLONG);
	}

	ino = opensimfs_inode_by_name(dir, &dentry->d_name, &de);
	if (ino) {
		inode = opensimfs_iget(dir->i_sb, ino);
		if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM)
			|| inode == ERR_PTR(-EACCES)) {
			return ERR_PTR(-EIO);
		}
	}

	return d_splice_alias(inode, dentry);
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
