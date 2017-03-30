#include <linux/fs.h>
#include <linux/radix-tree.h>
#include "opensimfs.h"

struct address_space_operations opensimfs_aops_dax = {
};

extern struct inode_operations opensimfs_file_inode_operations;
extern struct file_operations opensimfs_dax_file_operations;
extern struct inode_operations opensimfs_dir_inode_operations;
extern struct file_operations opensimfs_dir_operations;
extern const struct inode_operations opensimfs_symlink_inode_operations;
extern struct inode_operations opensimfs_special_inode_operations;

static int opensimfs_get_inode_address(
	struct super_block *sb,
	u64 ino,
	u64 *pi_addr,
	int extendable)
{
	*pi_addr =
		(OPENSIMFS_NORMAL_INODE_START - OPENSIMFS_ROOT_INO) * OPENSIMFS_INODE_SIZE;
	return 0;
}

static void opensimfs_set_inode_flags(
	struct inode *inode,
	struct opensimfs_inode *pi,
	unsigned int flags)
{
	inode->i_flags &=
		!(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	if (!pi->i_xattr)
		inode_has_no_xattr(inode);
	inode->i_flags |= S_DAX;
}

static int opensimfs_read_inode(
	struct super_block *sb,
	struct inode *inode,
	u64 pi_addr)
{
	struct opensimfs_inode_info *si = OPENSIMFS_I(inode);
	struct opensimfs_inode_info_header *sih = &si->header;
	struct opensimfs_inode *pi;
	int ret = -EIO;
	unsigned long ino;

	pi = (struct opensimfs_inode *)opensimfs_get_block(sb, pi_addr);
	inode->i_mode = sih->i_mode;
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
	inode->i_generation = le32_to_cpu(pi->i_generation);
	opensimfs_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
	ino = inode->i_ino;

	if (inode->i_mode == 0 || pi->valid == 0) {
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = le64_to_cpu(pi->i_blocks);
	inode->i_mapping->a_ops = &opensimfs_aops_dax;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &opensimfs_file_inode_operations;
		inode->i_fop = &opensimfs_dax_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &opensimfs_dir_inode_operations;
		inode->i_fop = &opensimfs_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &opensimfs_symlink_inode_operations;
		break;
	default:
		inode->i_op = &opensimfs_special_inode_operations;
		init_special_inode(inode, inode->i_mode,
			le32_to_cpu(pi->dev.rdev));
		break;
	}

	inode->i_size = le64_to_cpu(sih->i_size);
	inode->i_atime.tv_sec = le32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = le32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = le32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_ctime.tv_nsec =
		inode->i_mtime.tv_nsec = 0;
	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}

static void opensimfs_init_header(
	struct super_block *sb,
	struct opensimfs_inode_info_header *sih,
	u16 i_mode)
{
	sih->mmap_pages = 0;
	sih->i_size = 0;
	sih->pi_addr = 0;
	INIT_RADIX_TREE(&sih->tree, GFP_ATOMIC);
	INIT_RADIX_TREE(&sih->cache_tree, GFP_ATOMIC);
	sih->i_mode = i_mode;
}

struct inode *opensimfs_iget(
	struct super_block *sb,
	unsigned long ino)
{
	struct opensimfs_inode_info *si;
	struct opensimfs_inode_info_header *sih;
	struct opensimfs_inode *pi;
	struct inode *inode;
	u64 pi_addr;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	if (ino == OPENSIMFS_ROOT_INO) {
		pi_addr = OPENSIMFS_ROOT_INODE_START;
	}
	else {
		err = opensimfs_get_inode_address(sb, ino, &pi_addr, 0);
		if (err) {
			goto fail;
		}
	}

	if (pi_addr == 0) {
		err = -EACCES;
		goto fail;
	}

	pi = (struct opensimfs_inode *)opensimfs_get_block(sb, pi_addr);
	if (pi->valid == 0)
		return ERR_PTR(-EINVAL);

	si = OPENSIMFS_I(inode);
	sih = &si->header;

	opensimfs_init_header(sb, sih, __le16_to_cpu(pi->i_mode));
	sih->ino = ino;

	err = opensimfs_read_inode(sb, inode, pi_addr);
	if (unlikely(err))
		goto fail;
	inode->i_ino = ino;

	unlock_new_inode(inode);
	return inode;

fail:
	iget_failed(inode);
	return ERR_PTR(err);
}

int opensimfs_write_inode(
	struct inode *inode,
	struct writeback_control *wbc)
{
	return 0;
}

void opensimfs_dirty_inode(
	struct inode *inode,
	int flags)
{
}

void opensimfs_evict_inode(
	struct inode *inode)
{
}

int opensimfs_notify_change(
	struct dentry *dentry,
	struct iattr *attr)
{
	return 0;
}

int opensimfs_getattr(
	struct vfsmount *mount,
	struct dentry *dentry,
	struct kstat *stat)
{
	return 0;
}

static int opensimfs_new_blocks(
	struct super_block *sb,
	unsigned long *blocknr,
	unsigned int num,
	int zero)
{
	struct opensimfs_free_list *free_list;
	void *bp;
	unsigned long num_blocks = 0;
	unsigned long ret_blocks = 0;
	unsigned long new_blocknr = 0;
	struct rb_node *temp;
	struct opensimfs_range_node *first;

	num_blocks = num;
	if (num_blocks == 0)
		return -EINVAL;

	free_list = opensimfs_get_shared_free_list(sb);
	spin_lock(&free_list->s_lock);

	if (free_list->num_free_blocks < num_blocks ||
		!free_list->first_node) {
		if (free_list->num_free_blocks >= num_blocks) {
			temp = rb_first(&free_list->block_free_tree);
			first = container_of(temp, struct opensimfs_range_node, node);
			free_list->first_node = first;
		}
		else {
			spin_unlock(&free_list->s_lock);
			return -ENOSPC;
		}
	}

	ret_blocks = opensimfs_alloc_blocks_in_free_list(
		sb, free_list, num_blocks, &new_blocknr);

	free_list->alloc_data_count++;
	free_list->alloc_data_pages += ret_blocks;

	spin_unlock(&free_list->s_lock);

	if (ret_blocks <= 0 || new_blocknr == 0)
		return -ENOSPC;

	if (zero) {
		bp = opensimfs_get_block(
			sb,
			opensimfs_get_block_offset(sb, new_blocknr));
		memset_nt(bp, 0, PAGE_SIZE * ret_blocks);
	}
	*blocknr = new_blocknr;

	return ret_blocks / 1;
}

int opensimfs_allocate_inode_pages(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	unsigned long num_pages,
	u64 *new_block)
{
	unsigned long new_inode_blocknr;
	int allocated;
	int ret_pages = 0;

	allocated = opensimfs_new_blocks(sb, &new_inode_blocknr,
		num_pages, 0);

	if (allocated <= 0)
		return allocated;

	ret_pages += allocated;
	num_pages -= allocated;

	while (num_pages) {
		allocated = opensimfs_new_blocks(sb,
			&new_inode_blocknr, num_pages, 0);

		if (allocated <= 0) {
			break;
		}

		ret_pages += allocated;
		num_pages -= allocated;
	}

	*new_block = opensimfs_get_block_offset(sb,
		new_inode_blocknr);

	return ret_pages;
}
