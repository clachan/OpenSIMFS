#include <linux/fs.h>
#include "opensimfs.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

static int opensimfs_readdir(
	struct file *file,
	struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct opensimfs_inode *pidir;
	struct opensimfs_inode_info *si = OPENSIMFS_I(inode);
	struct opensimfs_inode_info_header *sih = &si->header;
	struct opensimfs_dentry *entry;
	u64 pi_addr;
	struct opensimfs_inode *pi;
	unsigned long pos;
	u64 curr_p;
	unsigned short de_len;
	unsigned long ino;

	pidir = opensimfs_get_inode(sb, inode);

	pos = ctx->pos;
	if (pos == ULONG_MAX)
		goto out;

	curr_p = opensimfs_get_block_offset(sb, sih->data_block);
	while (true) {
		entry = (struct opensimfs_dentry *)opensimfs_get_block(sb, curr_p);
		if (entry->entry_type == 0)
				break;

		de_len = le16_to_cpu(entry->de_len);
		if (entry->ino > 0 && entry->invalid == 0) {
			ino = __le64_to_cpu(entry->ino);
			pos = BKDRHash(entry->name, entry->name_len);
		
			/* FIXME: how about special inode? e.g. ., .. */
			opensimfs_get_inode_address(sb, ino, &pi_addr, 0);	
			pi = opensimfs_get_block(sb, pi_addr);

			if (!dir_emit(ctx, entry->name, entry->name_len,
				ino, IF2DT(le16_to_cpu(pi->i_mode))))
				return 0;
		}
		ctx->pos = pos;
		curr_p += de_len;
	}

	ctx->pos = ULONG_MAX;

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

int opensimfs_append_dir_init_entries(
	struct super_block *sb,
	struct inode *inode,
	u64 self_ino,
	u64 parent_ino)
{
	u64 new_block;
	struct opensimfs_dentry *de_entry;
	struct opensimfs_inode_info *si;
	struct opensimfs_inode_info_header *sih;

	/*allocated = opensimfs_allocate_inode_pages(sb, pi, 1, &new_block);
	if (allocated != 1) {
		return -ENOMEM;
	}*/

	si = OPENSIMFS_I(inode);
	sih = &si->header;
	new_block = opensimfs_get_block_offset(sb, sih->data_block);

	inode->i_blocks = 1;

	de_entry = (struct opensimfs_dentry*)opensimfs_get_block(sb, new_block);
	de_entry->entry_type = 2;
	de_entry->ino = cpu_to_le64(self_ino);
	de_entry->name_len = 1;
	de_entry->de_len = cpu_to_le16(OPENSIMFS_DIR_LOG_REC_LEN(1));
	de_entry->mtime = CURRENT_TIME_SEC.tv_sec;
	de_entry->size = sb->s_blocksize;
	de_entry->links_count = 1;
	strncpy(de_entry->name, ".\0", 2);
	opensimfs_flush_buffer(de_entry, OPENSIMFS_DIR_LOG_REC_LEN(1), 0);

	de_entry = (struct opensimfs_dentry*)((char *)de_entry + le16_to_cpu(de_entry->de_len));
	de_entry->entry_type = 2;
	de_entry->ino = cpu_to_le64(parent_ino);
	de_entry->name_len = 2;
	de_entry->de_len = cpu_to_le16(OPENSIMFS_DIR_LOG_REC_LEN(2));
	de_entry->mtime = CURRENT_TIME_SEC.tv_sec;
	de_entry->size = sb->s_blocksize;
	de_entry->links_count = 1;
	strncpy(de_entry->name, "..\0", 3);
	opensimfs_flush_buffer(de_entry, OPENSIMFS_DIR_LOG_REC_LEN(2), 0);

	return 0;
}

int opensimfs_add_dentry(
	struct dentry *dentry,
	u64 ino,
	int inc_link)
{
	/*
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct opensimfs_inode_info *si = OPENSIMFS_I(dir);
	struct opensimfs_inode_info_header *sih = &si->header;
	struct opensimfs_inode *pidir;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;

	pidir = opensimfs_get_inode(sb, dir);
	
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	*/

	return 0;
}
