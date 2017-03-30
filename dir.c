#include <linux/fs.h>
#include "opensimfs.h"

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

	pidir = opensimfs_get_inode(sb, inode);

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
	struct opensimfs_inode *pi,
	u64 self_ino,
	u64 parent_ino)
{
	int allocated;
	u64 new_block;
	struct opensimfs_dentry *de_entry;

	allocated = opensimfs_allocate_inode_pages(sb, pi, 1, &new_block);
	if (allocated != 1) {
		return -ENOMEM;
	}

	pi->i_blocks = 1;

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
