#include "opensimfs.h"

void opensimfs_init_header(
	struct super_block *sb,
	struct opensimfs_inode_info_header *sih,
	u16 i_mode)
{
	sih->num_log_pages = 0;
	sih->num_mmap_pages = 0;
        sih->i_size = 0;
	sih->pi_addr = 0;
	INIT_RADIX_TREE(&sih->tree, GFP_ATOMIC);
	INIT_RADIX_TREE(&sih->cache_tree, GFP_ATOMIC);
	sih->i_mode = i_mode;
}
