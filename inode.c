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

int opensimfs_init_inode_inuse_list(
	struct super_block *sb)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct opensimfs_range_node *range_node;
	struct opensimfs_inode_map *inode_map;
	unsigned long range_high;
	int ret;

	sbi->s_inodes_used_count = OPENSIMFS_NORMAL_INODE_START;
	range_high = OPENSIMFS_NORMAL_INODE_START - 1;

	inode_map = &sbi->inode_map;
	mutex_init(&inode_map->inode_table_mutex);
	range_node = opensimfs_alloc_inode_node(sb);
	if (range_node == NULL)
		return -ENOMEM; /* FIXME: error handling */

	range_node->range_low = 0;
	range_node->range_high = range_high;
	ret = opensimfs_insert_inode_tree(sbi, range_node);
	if (ret) {
		opensimfs_free_inode_node(sb, range_node);
	}
	inode_map->num_range_node_inode = 1;
	inode_map->first_inode_range = range_node;

	return 0;
}

int opensimfs_init_inode_table(
	struct super_block *sb)
{
	struct opensimfs_inode *pi = opensimfs_get_special_inode(sb, OPENSIMFS_INODETABLE_INO);
	struct opensimfs_inode_table *inode_table;
	unsigned long blocknr;
	u64 block;
	int allocated;

	pi->i_mode = 0;
	pi->i_uid = 0;
	pi->i_gid = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_flags = 0;
	pi->opensimfs_ino = OPENSIMFS_INODETABLE_INO;
	opensimfs_flush_buffer(pi, sizeof(*pi), 0);

	inode_table = opensimfs_get_inode_table(sb);
	if (!inode_table)
		return -EINVAL;

	allocated = opensimfs_new_blocks(sb, &blocknr, 1, 1);
	if (allocated != 1 || blocknr == 0)
		return -ENOSPC;

	block = opensimfs_get_block_offset(sb, blocknr);
	inode_table->inode_block = block;
	opensimfs_flush_buffer(inode_table, CACHELINE_SIZE, 0);

	PERSISTENT_BARRIER();
	return 0;
}

int opensimfs_get_inode_address(
	struct super_block *sb,
	u64 ino,
	u64 *pi_addr,
	int extendable)
{
	struct opensimfs_inode *pi;
	struct opensimfs_inode_table *inode_table;
	unsigned int data_bits;
	unsigned int num_inodes_bits;
	unsigned int superpage_count;
	u64 internal_ino;
	unsigned int i = 0;
	unsigned int index;
	u64 curr;
	unsigned long curr_addr;
	unsigned long blocknr;
	int allocated;

	pi = opensimfs_get_special_inode(sb, OPENSIMFS_INODETABLE_INO);
	data_bits = 12;
	num_inodes_bits = data_bits - OPENSIMFS_INODE_BITS;

	internal_ino = ino;

	inode_table = opensimfs_get_inode_table(sb);
	superpage_count = internal_ino >> num_inodes_bits;
	index = internal_ino & ((1 << num_inodes_bits) - 1);

	curr = inode_table->inode_block;
	if (curr == 0)
		return -EINVAL;

	for (i = 0; i < superpage_count; i++) {
		if (curr == 0)
			return -EINVAL;

		curr_addr = (unsigned long)opensimfs_get_block(sb, curr);
		curr_addr += 4096 - 8;
		curr = *(u64 *)(curr_addr);

		if (curr == 0) {
			if (extendable == 0)
				return -EINVAL;

			allocated = opensimfs_new_blocks(sb, &blocknr, 1, 1);
			if (allocated != 1)
				return allocated;

			curr = opensimfs_get_block_offset(sb, blocknr);
			*(u64 *)(curr_addr) = curr;
			opensimfs_flush_buffer((void *)curr_addr, OPENSIMFS_INODE_SIZE, 1);
		}
	}

	*pi_addr = curr + index * OPENSIMFS_INODE_SIZE;

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
	sih->pi_addr = pi_addr;

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
	struct inode *inode;

	inode = dentry->d_inode;
	generic_fillattr(inode, stat);
	stat->blocks = (inode->i_blocks << inode->i_sb->s_blocksize_bits) >> 9;
	return 0;
}

int opensimfs_new_blocks(
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

static int opensimfs_alloc_unused_inode(
	struct super_block *sb,
	u64 *ino)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct opensimfs_inode_map *inode_map;
	struct opensimfs_range_node *i, *next_i;
	struct rb_node *temp, *next;
	unsigned long next_range_low;
	u64 new_ino;

	inode_map = &sbi->inode_map;
	i = inode_map->first_inode_range;
	temp = &i->node;
	next = rb_next(temp);

	if (!next) {
		next_i = NULL;
		next_range_low = 1UL << 31;
	} else {
		next_i = container_of(next, struct opensimfs_range_node, node);
		next_range_low = next_i->range_low;
	}

	new_ino = i->range_high + 1;

	if (next_i && new_ino == (next_range_low - 1)) {
		i->range_high = next_i->range_high;
		rb_erase(&next_i->node, &inode_map->inode_inuse_tree);
		opensimfs_free_inode_node(sb, next_i);
		inode_map->num_range_node_inode--;
	} else if (new_ino < (next_range_low - 1)) {
		i->range_high = new_ino;
	} else {
		return -ENOSPC;
	}

	*ino = new_ino;
	sbi->s_inodes_used_count++;
	inode_map->allocated++;

	return 0;
}

u64 opensimfs_new_opensimfs_inode(
	struct super_block *sb,
	u64 *pi_addr)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct opensimfs_inode_map *inode_map;
	u64 free_ino = 0;
	u64 ino = 0;
	int ret;

	inode_map = &sbi->inode_map;

	mutex_lock(&inode_map->inode_table_mutex);
	ret = opensimfs_alloc_unused_inode(sb, &free_ino);
	if (ret) {
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	ret = opensimfs_get_inode_address(sb, free_ino, pi_addr, 1);
	if (ret) {
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	mutex_unlock(&inode_map->inode_table_mutex);

	ino = free_ino;

	return ino;
}

static void opensimfs_get_inode_flags(
	struct inode *inode,
	struct opensimfs_inode *pi)
{
	unsigned int flags = inode->i_flags;
	unsigned int opensimfs_flags = le32_to_cpu(pi->i_flags);

	opensimfs_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
		FS_NOATIME_FL | FS_DIRSYNC_FL);
	if (flags & S_SYNC)
		opensimfs_flags |= FS_SYNC_FL;
	if (flags & S_APPEND)
		opensimfs_flags |= FS_APPEND_FL;
	if (flags & S_IMMUTABLE)
		opensimfs_flags |= FS_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		opensimfs_flags |= FS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		opensimfs_flags |= FS_DIRSYNC_FL;

	pi->i_flags = cpu_to_le32(opensimfs_flags);
}

static void opensimfs_update_inode(
	struct inode *inode,
	struct opensimfs_inode *pi)
{
	pi->i_mode = cpu_to_le16(inode->i_mode);
	pi->i_uid = cpu_to_le32(i_uid_read(inode));
	pi->i_gid = cpu_to_le32(i_gid_read(inode));
	pi->i_links_count = cpu_to_le16(inode->i_nlink);
	pi->i_size = cpu_to_le64(inode->i_size);
	pi->i_blocks = cpu_to_le64(inode->i_blocks);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	pi->i_generation = cpu_to_le32(inode->i_generation);
	opensimfs_get_inode_flags(inode, pi);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		pi->dev.rdev = cpu_to_le32(inode->i_rdev);
}

struct inode *opensimfs_new_vfs_inode(
	enum opensimfs_new_inode_type type,
	struct inode *dir,
	u64 pi_addr,
	u64 ino,
	umode_t mode,
	size_t size,
	dev_t rdev,
	const struct qstr *qstr)
{
	struct super_block *sb;
	struct opensimfs_super_block_info *sbi;
	struct inode *inode;
	struct opensimfs_inode *diri;
	struct opensimfs_inode *pi;
	struct opensimfs_inode_info *si;
	struct opensimfs_inode_info_header *sih;
	int errval;

	sb = dir->i_sb;
	sbi = OPENSIMFS_SB(sb);
	inode = new_inode(sb);
	if (!inode) {
		errval = -ENOMEM;
		goto fail2;
	}

	inode_init_owner(inode, dir, mode);
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_generation = atomic_add_return(1, &sbi->next_generation);
	inode->i_size = size;

	diri = opensimfs_get_inode(sb, dir);
	if (!diri) {
		errval = -EACCES;
		goto fail1;
	}

	pi = (struct opensimfs_inode *)opensimfs_get_block(sb, pi_addr);

	inode->i_ino = ino;

	switch (type) {
	case TYPE_CREATE:
		inode->i_op = &opensimfs_file_inode_operations;
		inode->i_mapping->a_ops = &opensimfs_aops_dax;
		inode->i_fop = &opensimfs_dax_file_operations;
		break;
	case TYPE_MKNOD:
		init_special_inode(inode, mode, rdev);
		inode->i_op = &opensimfs_special_inode_operations;
		break;
	case TYPE_SYMLINK:
		inode->i_op = &opensimfs_symlink_inode_operations;
		inode->i_mapping->a_ops = &opensimfs_aops_dax;
		break;
	case TYPE_MKDIR:
		inode->i_op = &opensimfs_dir_inode_operations;
		inode->i_fop = &opensimfs_dir_operations;
		inode->i_mapping->a_ops = &opensimfs_aops_dax;
		set_nlink(inode, 2);
		break;
	default:
		break;
	}

	pi->i_flags = opensimfs_mask_flags(mode, diri->i_flags);
	pi->opensimfs_ino = ino;

	si = OPENSIMFS_I(inode);
	sih = &si->header;
	opensimfs_init_header(sb, sih, inode->i_mode);
	sih->pi_addr = pi_addr;
	sih->ino = ino;

	opensimfs_update_inode(inode, pi);
	opensimfs_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));

	if (insert_inode_locked(inode) < 0) {
		errval = -EINVAL;
		goto fail1;
	}

	opensimfs_flush_buffer(&pi, OPENSIMFS_INODE_SIZE, 0);

	return inode;
fail1:
	make_bad_inode(inode);
	iput(inode);
fail2:
	return ERR_PTR(errval);
}
