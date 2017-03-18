#include <linux/fs.h>
#include "opensimfs.h"

struct file_operations opensimfs_dir_operations = {
};

int opensimfs_append_dir_init_entries(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	u64 self_ino,
	u64 parent_ino)
{
	return 0;
}
