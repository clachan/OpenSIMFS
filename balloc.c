#include <linux/fs.h>
#include <linux/rbtree.h>
#include "opensimfs.h"

unsigned long opensimfs_count_free_blocks(
	struct super_block *sb)
{
	return 0;
}

static inline int opensimfs_rbtree_compare_range_node(
	struct opensimfs_range_node *curr,
	unsigned long range_low)
{
	if (range_low < curr->range_low)
		return -1;
	if (range_low > curr->range_high)
		return 1;

	return 0;
}

static int opensimfs_insert_range_node(
	struct opensimfs_super_block_info *sbi,
	struct rb_root *tree,
	struct opensimfs_range_node *new_node)
{
	struct opensimfs_range_node* curr;
	struct rb_node **temp, *parent;
	int compVal;

	temp = &(tree->rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct opensimfs_range_node, node);
		compVal = opensimfs_rbtree_compare_range_node(
			curr, new_node->range_low);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		}
		else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		}
		else {
			return -EINVAL;
		}
	}

	rb_link_node(&new_node->node, parent, temp);
	rb_insert_color(&new_node->node, tree);

	return 0;
}

static int opensimfs_find_range_node(
	struct opensimfs_super_block_info *sbi,
	struct rb_root *tree,
	unsigned long range_low,
	struct opensimfs_range_node **ret_node)
{
	struct opensimfs_range_node *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int ret = 0;

	temp = tree->rb_node;

	while (temp) {
		curr = container_of(temp, struct opensimfs_range_node, node);
		compVal = opensimfs_rbtree_compare_range_node(curr, range_low);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			ret = 1;
			break;
		}
	}

	*ret_node = curr;
	return ret;
}

inline int opensimfs_search_inode_tree(
	struct opensimfs_super_block_info *sbi,
	unsigned long ino,
	struct opensimfs_range_node **ret_node)
{
	struct rb_root *tree;

	tree = &sbi->inode_map.inode_inuse_tree;
	return opensimfs_find_range_node(sbi, tree, ino, ret_node);
}

inline int opensimfs_insert_block_tree(
	struct opensimfs_super_block_info *sbi,
	struct rb_root *tree,
	struct opensimfs_range_node *new_node)
{
	int ret;

	ret = opensimfs_insert_range_node(sbi, tree, new_node);
	if (ret)
		; /* FIXME: check error */

	return ret;
}

inline int opensimfs_insert_inode_tree(
	struct opensimfs_super_block_info *sbi,
	struct opensimfs_range_node *new_node)
{
	struct rb_root *tree;
	int ret;

	tree = &sbi->inode_map.inode_inuse_tree;
	ret = opensimfs_insert_range_node(sbi, tree, new_node);
	if (ret)
		; /* FIXME: error handling */

	return ret;
}

void opensimfs_init_blockmap(
	struct super_block *sb)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct rb_root *tree;
	unsigned long num_used_block;
	struct opensimfs_range_node *blknode;
	struct opensimfs_free_list *free_list;
	unsigned long per_list_blocks;
	int ret;

	num_used_block = sbi->reserved_blocks;
	per_list_blocks = sbi->num_blocks;
	free_list = opensimfs_get_shared_free_list(sb);
	tree = &(free_list->block_free_tree);
	free_list->block_start = 0;
	free_list->block_end = per_list_blocks - 1;

	free_list->num_free_blocks = per_list_blocks;
	free_list->block_start += num_used_block;
	free_list->num_free_blocks -= num_used_block;

	blknode = opensimfs_alloc_block_node(sb);
	if (blknode == NULL)
		return; /* FIXME: assertion */
	blknode->range_low = free_list->block_start;
	blknode->range_high = free_list->block_end;
	ret = opensimfs_insert_block_tree(sbi, tree, blknode);
	if (ret) {
		opensimfs_free_block_node(sb, blknode);
		return;
	}
	free_list->first_node = blknode;
	free_list->num_blocknode = 1;
}

unsigned long opensimfs_alloc_blocks_in_free_list(
	struct super_block *sb,
	struct opensimfs_free_list *free_list,
	unsigned long num_blocks,
	unsigned long *new_blocknr)
{
	struct rb_root *tree;
	struct opensimfs_range_node *curr, *next = NULL;
	struct rb_node *temp, *next_node;
	unsigned long curr_blocks;
	bool found = 0;

	tree = &(free_list->block_free_tree);
	temp = &(free_list->first_node->node);

	while (temp) {
		curr = container_of(temp, struct opensimfs_range_node, node);

		curr_blocks = curr->range_high - curr->range_low + 1;
		if (num_blocks >= curr_blocks) {
			if (curr == free_list->first_node) {
				next_node = rb_next(temp);
				if (next_node) {
					next = container_of(
						next_node,
						struct opensimfs_range_node,
						node);
					free_list->first_node = next;
				}

				rb_erase(&curr->node, tree);
				free_list->num_blocknode--;
				num_blocks = curr_blocks;
				*new_blocknr = curr->range_low;
				opensimfs_free_block_node(sb, curr);
				found = 1;
				break;
			}
		}

		*new_blocknr = curr->range_low;
		curr->range_low += num_blocks;
		found = 1;
		break;
	}

	if (found)
		free_list->num_free_blocks -= num_blocks;
	else
		return -ENOSPC;

	return num_blocks;
}

inline int opensimfs_new_log_blocks(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	unsigned long *new_blocknr,
	unsigned int num_blocks,
	int zero)
{
	int allocated;
	allocated = opensimfs_new_blocks(
		sb, new_blocknr, num_blocks,
		pi->i_blk_type, zero, LOG);
	return allocated;
}

inline int opensimfs_new_data_blocks(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	unsigned long *new_blocknr,
	unsigned int num_blocks,
	int zero)
{
	int allocated;
	allocated = opensimfs_new_blocks(
		sb, new_blocknr, num_blocks,
		pi->i_blk_type, zero, DATA);
	return allocated;
}
