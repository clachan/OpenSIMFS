#include <linux/slab.h>
#include "opensimfs.h"

int opensimfs_journal_soft_init(
	struct super_block *sb)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct journal_ptr_pair *pair;
	int i;

	sbi->journal_locks = kzalloc(sbi->cpus * sizeof(spinlock_t),
		GFP_KERNEL);
	if (!sbi->journal_locks)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++)
		spin_lock_init(&sbi->journal_locks[i]);

	for (i = 0; i < sbi->cpus; i++) {
		pair = opensimfs_get_journal_pointers(sb, i);
		if (pair->journal_head == pair->journal_tail)
			continue;

		/* FIXME consistence check */

		return -EINVAL;
	}

	return 0;
}

int opensimfs_journal_hard_init(
	struct super_block *sb)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct opensimfs_inode fake_pi;
	struct journal_ptr_pair *pair;
	unsigned long blocknr = 0;
	int allocated;
	int i;
	u64 block;

	fake_pi.opensimfs_ino = OPENSIMFS_JOURNAL_INO;
	fake_pi.i_blk_type = OPENSIMFS_BLOCK_TYPE_4K;

	for (i = 0; i < sbi->cpus; i++) {
		pair = opensimfs_get_journal_pointers(sb, i);
		if (!pair)
			return -EINVAL;

		allocated = opensimfs_new_log_blocks(sb, &fake_pi, &blocknr, 1, 1);
		if (allocated != 1 || blocknr == 0)
			return -ENOSPC;

		block = opensimfs_get_block_offset(sb, blocknr, fake_pi.i_blk_type);
		pair->journal_head = pair->journal_tail = block;
		opensimfs_flush_buffer(pair, CACHELINE_SIZE, 0);
	}

	PERSISTENT_BARRIER();
	return opensimfs_journal_soft_init(sb);
}

static u64 opensimfs_next_journal(
	u64 curr_p)
{
	size_t size = sizeof(struct opensimfs_journal_entry);

	if ((curr_p & (PAGE_SIZE - 1)) + size >= PAGE_SIZE)
		return (curr_p & PAGE_MASK);

	return curr_p + size;
}

u64 opensimfs_create_journal_transaction(
	struct super_block *sb,
	struct opensimfs_journal_entry *dram_entry1,
	struct opensimfs_journal_entry *dram_entry2,
	int entries,
	int cpu)
{
	struct journal_ptr_pair *pair;
	struct opensimfs_journal_entry *entry;
	size_t size = sizeof(struct opensimfs_journal_entry);
	u64 new_tail, temp;

	pair = opensimfs_get_journal_pointers(sb, cpu);
	if (!pair || pair->journal_head == 0 ||
		pair->journal_head != pair->journal_tail)
		BUG();

	temp = pair->journal_head;
	entry = (struct opensimfs_journal_entry *)opensimfs_get_block(
		sb, temp);

	memcpy_to_pmem_nocache(entry, dram_entry1, size);

	if (entries == 2) {
		temp = opensimfs_next_journal(temp);
		entry = (struct opensimfs_journal_entry *)opensimfs_get_block(sb, temp);
		memcpy_to_pmem_nocache(entry, dram_entry2, size);
	}

	new_tail = opensimfs_next_journal(temp);
	pair->journal_tail = new_tail;
	opensimfs_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	return new_tail;
}

void opensimfs_commit_journal_transaction(
	struct super_block *sb,
	u64 tail,
	int cpu)
{
	struct journal_ptr_pair *pair;
	
	pair = opensimfs_get_journal_pointers(sb, cpu);
	if (!pair || pair->journal_tail != tail)
		BUG();

	pair->journal_head = tail;
	opensimfs_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);
}
