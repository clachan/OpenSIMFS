#include <linux/fs.h>
#include "opensimfs.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

static u64 opensimfs_find_next_dentry_addr(
	struct super_block *sb,
	struct opensimfs_inode_info_header *sih,
	u64 pos)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct opensimfs_file_write_entry *entry = NULL;
	struct opensimfs_file_write_entry *entries[1];
	int nr_entries;
	u64 addr = 0;

	nr_entries = radix_tree_gang_lookup(&sih->tree,
		(void **)entries, pos, 1);
	if (nr_entries == 1) {
		entry = entries[0];
		addr = opensimfs_get_address_offset(sbi, entry);
	}

	return addr;
}

static int opensimfs_readdir(
	struct file *file,
	struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct opensimfs_inode *pidir;
	struct opensimfs_inode_info *si = OPENSIMFS_I(inode);
	struct opensimfs_inode_info_header *sih = &si->header;
	struct opensimfs_inode *child_pi;
	struct opensimfs_inode *prev_child_pi = NULL;
	struct opensimfs_dentry *entry = NULL;
	struct opensimfs_dentry *prev_entry = NULL;
	u64 pi_addr;
	unsigned long pos;
	u64 curr_p;
	unsigned short de_len;
	unsigned long ino;
	void *addr;
	u8 type;
	int ret;

	pidir = opensimfs_get_inode(sb, inode);

	if (pidir->log_head == 0) {
		BUG();
		return -EINVAL;
	}

#define READDIR_END (ULONG_MAX)
	pos = ctx->pos;
	if (pos == 0) {
		curr_p = pidir->log_head;
	} else if (pos == READDIR_END) {
		goto out;
	} else {
		curr_p = opensimfs_find_next_dentry_addr(sb, sih, pos);
		if (curr_p == 0)
			goto out;
	}

	while (curr_p != pidir->log_tail) {
		if (opensimfs_goto_next_log_page(sb, curr_p)) {
			curr_p = opensimfs_next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			BUG();
			return -EINVAL;
		}

		addr = (void *)opensimfs_get_block(sb, curr_p);
		type = opensimfs_get_log_entry_type(addr);

		switch (type) {
		case DIR_LOG:
			break;
		default:
			BUG();
			return -EINVAL;
		}

		entry = (struct opensimfs_dentry *)opensimfs_get_block(sb, curr_p);
		de_len = le16_to_cpu(entry->de_len);
		if (entry->ino > 0 && entry->invalid == 0) {
			ino = __le64_to_cpu(entry->ino);
			pos = BKDRHash(entry->name, entry->name_len);

			ret = opensimfs_get_inode_address(sb, ino, &pi_addr, 0);
			if (ret) {
				ctx->pos = READDIR_END;
				return ret;
			}

			child_pi = opensimfs_get_block(sb, pi_addr);
			if (prev_entry && !dir_emit(ctx, prev_entry->name,
				prev_entry->name_len, ino,
				IF2DT(le16_to_cpu(prev_child_pi->i_mode)))) {
				return 0;
			}
			prev_entry = entry;
			prev_child_pi = child_pi;
		}
		ctx->pos = pos;
		curr_p += de_len;
	}

	if (prev_entry && !dir_emit(ctx, prev_entry->name,
		prev_entry->name_len, ino,
		IF2DT(le16_to_cpu(prev_child_pi->i_mode))))
		return 0;

	ctx->pos = READDIR_END;
out:
	return 0;
}

struct file_operations opensimfs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= opensimfs_readdir,
	.fsync		= noop_fsync,
/*
	.unlocked_ioctl	= opensimfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= opensimfs_compact_ioctl,
#endif
*/
};

static u64 opensimfs_append_dir_inode_entry(
	struct super_block *sb,
	struct opensimfs_inode *pidir,
	struct inode *dir,
	u64 ino,
	struct dentry *dentry,
	unsigned short de_len,
	u64 tail,
	int link_change,
	u64 *curr_tail)
{
	struct opensimfs_inode_info *si = OPENSIMFS_I(dir);
	struct opensimfs_inode_info_header *sih = &si->header;
	struct opensimfs_dentry *entry;
	u64 curr_p;
	size_t size = de_len;
	int extended = 0;
	unsigned short links_count;

	curr_p = opensimfs_get_log_append_head(sb, pidir, sih, tail, size, &extended);
	if (curr_p == 0)
		BUG();

	entry = (struct opensimfs_dentry *)opensimfs_get_block(sb, curr_p);
	entry->entry_type = DIR_LOG;
	entry->ino = cpu_to_le64(ino);
	entry->name_len = dentry->d_name.len;
	memcpy_to_pmem_nocache(entry->name, dentry->d_name.name, dentry->d_name.len);
	entry->name[dentry->d_name.len] = '\0';
	entry->file_type = 0;
	entry->invalid = 0;
	entry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	entry->size = cpu_to_le64(dir->i_size);

	links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	entry->links_count = cpu_to_le16(links_count);

	entry->de_len = cpu_to_le16(de_len);

	opensimfs_flush_buffer(entry, de_len, 0);

	*curr_tail = curr_p + de_len;
	dir->i_blocks = pidir->i_blocks;

	return curr_p;
}

int opensimfs_append_dir_init_entries(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	u64 self_ino,
	u64 parent_ino)
{
	u64 new_block;
	u64 curr_p;
	struct opensimfs_dentry *de_entry;
	int allocated;

	allocated = opensimfs_allocate_inode_log_pages(sb, pi, 1, &new_block);
	if (allocated != 1) {
		return -ENOMEM;
	}
	pi->log_tail = pi->log_head = new_block;
	pi->i_blocks = 1;
	opensimfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	de_entry = (struct opensimfs_dentry*)opensimfs_get_block(sb, new_block);
	de_entry->entry_type = DIR_LOG;
	de_entry->ino = cpu_to_le64(self_ino);
	de_entry->name_len = 1;
	de_entry->de_len = cpu_to_le16(OPENSIMFS_DIR_LOG_REC_LEN(1));
	de_entry->mtime = CURRENT_TIME_SEC.tv_sec;
	de_entry->size = sb->s_blocksize;
	de_entry->links_count = 1;
	strncpy(de_entry->name, ".\0", 2);
	opensimfs_flush_buffer(de_entry, OPENSIMFS_DIR_LOG_REC_LEN(1), 0);

	curr_p = new_block + OPENSIMFS_DIR_LOG_REC_LEN(1);

	de_entry = (struct opensimfs_dentry*)((char *)de_entry + le16_to_cpu(de_entry->de_len));
	de_entry->entry_type = DIR_LOG;
	de_entry->ino = cpu_to_le64(parent_ino);
	de_entry->name_len = 2;
	de_entry->de_len = cpu_to_le16(OPENSIMFS_DIR_LOG_REC_LEN(2));
	de_entry->mtime = CURRENT_TIME_SEC.tv_sec;
	de_entry->size = sb->s_blocksize;
	de_entry->links_count = 1;
	strncpy(de_entry->name, "..\0", 3);
	opensimfs_flush_buffer(de_entry, OPENSIMFS_DIR_LOG_REC_LEN(2), 0);

	curr_p += OPENSIMFS_DIR_LOG_REC_LEN(2);
	opensimfs_update_log_tail(pi, curr_p);

	return 0;
}

static int opensimfs_insert_dir_radix_tree(
	struct super_block *sb,
	struct opensimfs_inode_info_header *sih,
	const char *name,
	int namelen,
	struct opensimfs_dentry *direntry)
{
	unsigned long hash;
	int ret;

	hash = BKDRHash(name, namelen);

	ret = radix_tree_insert(&sih->tree, hash, direntry);
	if (ret)
		; /* FIXME error handling */

	return ret;
}

int opensimfs_add_dentry(
	struct dentry *dentry,
	u64 ino,
	int inc_link,
	u64 tail,
	u64 *new_tail)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct opensimfs_inode_info *si = OPENSIMFS_I(dir);
	struct opensimfs_inode_info_header *sih = &si->header;
	struct opensimfs_inode *pidir;
	unsigned short loglen;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct opensimfs_dentry *direntry;
	u64 curr_entry, curr_tail;
	int ret;

	if (namelen == 0)
		return -EINVAL;

	pidir = opensimfs_get_inode(sb, dir);

	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;

	loglen = OPENSIMFS_DIR_LOG_REC_LEN(namelen);
	curr_entry = opensimfs_append_dir_inode_entry(
		sb, pidir, dir, ino, dentry, loglen, tail, inc_link, &curr_tail);

	direntry = (struct opensimfs_dentry *)opensimfs_get_block(sb, curr_entry);
	ret = opensimfs_insert_dir_radix_tree(sb, sih, name, namelen, direntry);
	*new_tail = curr_tail;
	return ret;
}
