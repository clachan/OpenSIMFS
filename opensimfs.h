#ifndef ___OPENSIMFS_H___
#define ___OPENSIMFS_H___

#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

#define OPENSIMFS_SUPER_MAGIC 0x4F53494D /* 'O' 'S' 'I' 'M' */

/*
 * mount options
 */
#define OPENSIMFS_MOUNT_PROTECT      0x000001	/* wprotect CR0.WP */
#define OPENSIMFS_MOUNT_XATTR_USER   0x000002	/* Extended user attributes */
#define OPENSIMFS_MOUNT_POSIX_ACL    0x000004	/* POSIX Access Control Lists */
#define OPENSIMFS_MOUNT_DAX          0x000008	/* Direct Access */
#define OPENSIMFS_MOUNT_ERRORS_CONT  0x000010	/* Continue on errors */
#define OPENSIMFS_MOUNT_ERRORS_RO    0x000020	/* Remount fs ro on errors */
#define OPENSIMFS_MOUNT_ERRORS_PANIC 0x000040	/* Panic on errors */
#define OPENSIMFS_MOUNT_HUGEMMAP     0x000080	/* Huge mappings with mmap */
#define OPENSIMFS_MOUNT_HUGEIOREMAP  0x000100	/* Huge mappings with ioremap */
#define OPENSIMFS_MOUNT_FORMAT       0x000200	/* was FS formatted on mount? */
#define OPENSIMFS_MOUNT_MOUNTING     0x000400	/* FS currently being mounted */

#define OPENSIMFS_DEF_BLOCK_SIZE_4K  4096
#define OPENSIMFS_SB_SIZE            512
#define OPENSIMFS_RESERVED_BLOCKS    3

/* The root inode follows immediately after the redundant super block */
#define OPENSIMFS_ROOT_INO           1
#define OPENSIMFS_INODETABLE_INO     2 /* Temporaty inode table */
#define OPENSIMFS_BLOCKNODE_INO      3
#define OPENSIMFS_INODELIST_INO      4
#define OPENSIMFS_JOURNAL_INO		5
#define OPENSIMFS_INODELIST1_INO     6

#define OPENSIMFS_ROOT_INODE_START   (OPENSIMFS_SB_SIZE * 2)

/* Normal inode starts at 16 */
#define OPENSIMFS_NORMAL_INODE_START (16)

#define OPENSIMFS_INODE_SIZE         128
#define OPENSIMFS_INODE_BITS         7

#define OPENSIMFS_NAME_LEN           255

/* OPENSIMFS suppoered data blocks */
#define OPENSIMFS_BLOCK_TYPE_4K 0
#define OPENSIMFS_BLOCK_TYPE_2M 1
#define OPENSIMFS_BLOCK_TYPE_1G 2
#define OPENSIMFS_BLOCK_TYPE_MAX 3

struct opensimfs_inode {
	__le16  i_reserved;
	u8	valid;
	u8	i_blk_type;
	__le32  i_flags;
	__le64  i_size;		 /* size */
	__le32  i_ctime;
	__le32  i_mtime;
	__le32  i_atime;
	__le16  i_mode;
	__le16  i_links_count;

	__le64  i_blocks;
	__le64  i_xattr;

	__le32  i_uid;
	__le32  i_gid;
	__le32	i_generation;
	__le32  padding;
	__le64  opensimfs_ino;

	__le64  log_head;
	__le64  log_tail;

	struct {
		__le32 rdev;
	} dev;
} __attribute((__packed__));

struct opensimfs_inode_info_header {
	struct radix_tree_root tree;
	struct radix_tree_root cache_tree;
	unsigned short i_mode;
	unsigned long num_log_pages;
	unsigned long i_size;
	unsigned long ino;
	unsigned long pi_addr;
	unsigned long num_mmap_pages;
	u64 last_setattr;
	u64 last_link_change;

	unsigned long pte_block;
	unsigned long data_block;
	unsigned long pfw_pte_block;
	unsigned long pfw_data_block;
};

struct opensimfs_inode_info {
	struct opensimfs_inode_info_header header;
	struct inode vfs_inode;
};

struct opensimfs_inode_table {
	__le64 log_head;
};

static inline struct opensimfs_inode_info *OPENSIMFS_I(struct inode *inode)
{
	return container_of(inode, struct opensimfs_inode_info, vfs_inode);
}

struct opensimfs_free_list {
	spinlock_t s_lock;
	struct rb_root block_free_tree;
	struct opensimfs_range_node *first_node;
	unsigned long block_start;
	unsigned long block_end;
	unsigned long num_free_blocks;
	unsigned long num_blocknode;

	/* Statistics */
	unsigned long alloc_log_count;
	unsigned long alloc_data_count;
	unsigned long free_log_count;
	unsigned long free_data_count;
	unsigned long alloc_log_pages;
	unsigned long alloc_data_pages;
	unsigned long free_data_pages;
	unsigned long freed_log_pages;
	unsigned long freed_data_pages;

	u64 padding[8];
};

struct opensimfs_super_block {
	__le16  s_checksum;	 /* checksum of this sb */
	__le16  s_padding;
	__le32  s_magic;		/* magic signature */
	__le32  s_blocksize;	/* super block size in bytes */
	__le64  s_size;		 /* file system size in bytes */

	__le32  s_mtime;		/* mount time */
	__le32  s_wtime;		/* write time */
} __attribute((__packed__));

struct opensimfs_inode_map {
	struct mutex inode_table_mutex;
	struct rb_root inode_inuse_tree;
	unsigned long num_range_node_inode;
	struct opensimfs_range_node *first_inode_range;
	int allocated;
	int freed;
};

struct opensimfs_super_block_info {
	struct super_block *sb;
	struct block_device *s_bdev;

	/* 
	 * base physical and virtual address of OPENSIMFS, which
	 * is also the pointer to the super block.
	 */
	phys_addr_t	 phys_addr;
	void             *virt_addr;
	int              cpus;
	
	/* mount options */
	unsigned long   num_blocks;
	unsigned long   blocksize;
	unsigned long   initsize;
	unsigned long   s_mount_opt;
	kuid_t		  	uid;	/* mount uid for root directory */
	kgid_t		  	gid;	/* mount gid for root directory */
	umode_t		 	mode;   /* mount mode for root directory */
	atomic_t		next_generation;

	unsigned long	s_inodes_used_count;
	unsigned long   reserved_blocks;

	struct mutex	s_lock;
	spinlock_t	*journal_locks;

	struct opensimfs_free_list shared_free_list;
	struct opensimfs_inode_map inode_map;
};

#define OPENSIMFS_DIR_PAD	8
#define OPENSIMFS_DIR_ROUND	(OPENSIMFS_DIR_PAD - 1)
#define OPENSIMFS_DIR_LOG_REC_LEN(name_len) (((name_len) + 28 + OPENSIMFS_DIR_ROUND) & ~OPENSIMFS_DIR_ROUND)

struct opensimfs_dentry {
	u8		entry_type;
	u8		name_len;
	u8		file_type;
	u8		invalid;
	__le16	de_len;
	__le16	links_count;
	__le32	mtime;
	__le64	ino;
	__le64	size;
	char	name[OPENSIMFS_NAME_LEN + 1];
} __attribute((__packed__));

struct opensimfs_range_node {
	struct rb_node node;
	unsigned long range_low;
	unsigned long range_high;
};

enum opensimfs_log_entry_type {
	FILE_WRITE = 1,
	DIR_LOG,
	SET_ATTR,
	LINK_CHANGE,
	LOG_NEXT_PAGE,
};

static inline u8 opensimfs_get_log_entry_type(
	void *p)
{
	return *(u8 *)p;
}

static inline void opensimfs_set_entry_type(
	void *p,
	enum opensimfs_log_entry_type type)
{
	*(u8 *)p = type;
}

struct opensimfs_file_write_entry {
	__le64 block;
	__le64 pgoff;
	__le32 num_pages;
	__le32 invalid_pages;
	__le32 mtime;
	__le32 padding;
	__le64 size;
} __attribute((__packed__));

#define INVALID_MASK 4095
#define LOG_BLOCK_OFFSET(p) ((p) & ~INVALID_MASK)
#define LOG_ENTRY_LOC(p) ((p) & INVALID_MASK)

struct opensimfs_inode_log_page_tail {
	__le64 padding1;
	__le64 padding2;
	__le64 padding3;
	__le64 next_page;
} __attribute((__packed__));

#define LOG_LAST_ENTRY 4064
#define LOG_PAGE_TAIL(p) (((p) & ~INVALID_MASK) + LOG_LAST_ENTRY)

/* Fit in PAGE_SIZE */
struct opensimfs_inode_log_page {
	char padding[LOG_LAST_ENTRY];
	struct opensimfs_inode_log_page_tail page_tail;
} __attribute((__packed__));

// BKDR String Hash Function
static inline unsigned long BKDRHash(const char *str, int length)
{
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned long hash = 0;
	int i;

	for (i = 0; i < length; i++) {
		hash = hash * seed + (*str++);
	}
	return hash;
}

static inline struct opensimfs_super_block_info *OPENSIMFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct opensimfs_super_block *opensimfs_get_super(struct super_block *sb)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	
	return (struct opensimfs_super_block *)sbi->virt_addr;
}

static inline void *opensimfs_get_block(
	struct super_block *sb,
	u64 block)
{
	struct opensimfs_super_block *ps = opensimfs_get_super(sb);

	return block ? ((void *)ps + block) : NULL;
}

static inline struct opensimfs_free_list *opensimfs_get_shared_free_list(
	struct super_block *sb)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	return &sbi->shared_free_list;
}

static inline u64 opensimfs_get_address_offset(
	struct opensimfs_super_block_info *sbi,
	void *addr)
{
	return (u64)(addr - sbi->virt_addr);
}

static inline u64 opensimfs_get_block_offset(
	struct super_block *sb,
	unsigned long blocknr,
	unsigned short btype)
{
	return (u64)blocknr << PAGE_SHIFT;
}

static inline struct opensimfs_inode *opensimfs_get_inode(
	struct super_block *sb,
	struct inode *inode)
{
	struct opensimfs_inode_info *si = OPENSIMFS_I(inode);
	struct opensimfs_inode_info_header *sih = &si->header;

	return (struct opensimfs_inode *)opensimfs_get_block(sb, sih->pi_addr);
}

static inline struct opensimfs_inode_table *opensimfs_get_inode_table(
	struct super_block *sb)
{
	return (struct opensimfs_inode_table *)((char *)opensimfs_get_block(sb,
		OPENSIMFS_DEF_BLOCK_SIZE_4K * 2));
}

#define clear_mount_opt(o, opt) (o &= ~opt)
#define set_mount_opt(o, opt)   (o |= opt)
#define test_mount_opt(sb, opt) (OPENSIMFS_SB(sb)->s_mount_opt & opt)

/* bbuild.c */
void opensimfs_init_header(
	struct super_block *sb,
	struct opensimfs_inode_info_header *sih,
	u16 i_mode);
int opensimfs_new_log_blocks(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	unsigned long *new_blocknr,
	unsigned num_blocks,
	int zero);
int opensimfs_new_data_blocks(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	unsigned long *new_blocknr,
	unsigned num_blocks,
	int zero);

/* super.c */
struct opensimfs_inode *opensimfs_get_basic_inode(
	struct super_block *sb,
	u64 ino);
struct opensimfs_inode *opensimfs_get_special_inode(
	struct super_block *sb,
	u64 ino);
struct opensimfs_range_node *opensimfs_alloc_block_node(
	struct super_block *sb);
void opensimfs_free_block_node(
	struct super_block *sb,
	struct opensimfs_range_node *blknode);
struct opensimfs_range_node *opensimfs_alloc_inode_node(
	struct super_block *sb);
void opensimfs_free_inode_node(
	struct super_block *sb,
	struct opensimfs_range_node *blknode);

/* dir.c */
int opensimfs_append_dir_init_entries(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	u64 self_ino,
	u64 parent_ino);
int opensimfs_add_dentry(
	struct dentry *dentry,
	u64 ino,
	int inc_link,
	u64 tail,
	u64 *new_tail);

/* inode.c */
int opensimfs_init_inode_inuse_list(
	struct super_block *sb);
int opensimfs_init_inode_table(
	struct super_block *sb);
int opensimfs_get_inode_address(
	struct super_block *sb,
	u64 ino,
	u64 *pi_addr,
	int extendable);
struct inode *opensimfs_iget(
	struct super_block *sb,
	unsigned long ino);
int opensimfs_write_inode(
	struct inode *inode,
	struct writeback_control *wbc);
void opensimfs_dirty_inode(
	struct inode *inode,
	int flags);
void opensimfs_evict_inode(
	struct inode *inode);
int opensimfs_notify_change(
	struct dentry *dentry,
	struct iattr *attr);
int opensimfs_getattr(
	struct vfsmount *mnt,
	struct dentry *dentry,
	struct kstat *stat);
enum alloc_type {
	LOG = 1,
	DATA,
};
int opensimfs_new_blocks(
	struct super_block *sb,
	unsigned long *blocknr,
	unsigned int num_blocks,
	unsigned short btype,
	int zero,
	enum alloc_type atype);
u64 opensimfs_new_opensimfs_inode(
	struct super_block *sb,
	u64 *pi_addr);
int opensimfs_allocate_inode_log_pages(
	struct super_block *sb,
	struct opensimfs_inode *inode,
	unsigned long num_pages,
	u64 *new_block);
enum opensimfs_new_inode_type {
	TYPE_CREATE = 0,
	TYPE_MKNOD,
	TYPE_SYMLINK,
	TYPE_MKDIR
};
struct inode *opensimfs_new_vfs_inode(
	enum opensimfs_new_inode_type type,
	struct inode *dir,
	u64 pi_addr,
	u64 ino,
	umode_t mode,
	size_t size,
	dev_t rdev,
	const struct qstr *qstr);
u64 opensimfs_get_log_append_head(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	struct opensimfs_inode_info_header *sih,
	u64 tail,
	size_t size,
	int *extended);
u64 opensimfs_append_file_write_entry(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	struct inode *inode,
	struct opensimfs_file_write_entry *data,
	u64 tail);

/* balloc.c */
unsigned long opensimfs_count_free_blocks(
	struct super_block *sb);
int opensimfs_search_inode_tree(
	struct opensimfs_super_block_info *sbi,
	unsigned long ino,
	struct opensimfs_range_node **ret_node);
int opensimfs_insert_inode_tree(
	struct opensimfs_super_block_info *sbi,
	struct opensimfs_range_node *new_node);
void opensimfs_init_blockmap(
	struct super_block *sb);
unsigned long opensimfs_alloc_blocks_in_free_list(
	struct super_block *sb,
	struct opensimfs_free_list *free_list,
	unsigned long num_blocks,
	unsigned long *new_blocknr);

/* namei.c */
struct dentry *opensimfs_get_parent(
	struct dentry *child);

/* dax.c */
ssize_t opensimfs_dax_file_read(
	struct file *filp,
	char __user *buf,
	size_t len,
	loff_t *ppos);
ssize_t opensimfs_dax_file_write(
	struct file *filp,
	const char __user *buf,
	size_t len,
	loff_t *ppos);
int opensimfs_dax_file_mmap(
	struct file *file,
	struct vm_area_struct *vma);

/* journal.c */
struct opensimfs_journal_entry {
	u64 addrs[4];
	u64 values[4];
};

int opensimfs_journal_soft_init(
	struct super_block *sb);
int opensimfs_journal_hard_init(
	struct super_block *sb);
u64 opensimfs_create_journal_transaction(
	struct super_block *sb,
	struct opensimfs_journal_entry *dram_entry1,
	struct opensimfs_journal_entry *dram_entry2,
	int entries,
	int cpu);
void opensimfs_commit_journal_transaction(
	struct super_block *sb,
	u64 tail,
	int cpu);

struct journal_ptr_pair {
	__le64 journal_head;
	__le64 journal_tail;
};

/* Flags that should be inherited by new inodes from their parent. */
#define OPENSIMFS_FL_INHERITED \
	(FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | \
	 FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL |	\
	 FS_COMPRBLK_FL | FS_NOCOMP_FL | FS_JOURNAL_DATA_FL | \
	 FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define OPENSIMFS_REG_FLMASK (~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define OPENSIMFS_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)
#define OPENSIMFS_FL_USER_VISIBLE (FS_FL_USER_VISIBLE | NOVA_EOFBLOCKS_FL)

static inline __le32 opensimfs_mask_flags(umode_t mode, __le32 flags)
{
	flags &= cpu_to_le32(OPENSIMFS_FL_INHERITED);
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & cpu_to_le32(OPENSIMFS_REG_FLMASK);
	else
		return flags & cpu_to_le32(OPENSIMFS_OTHER_FLMASK);
}

/* assumes the length to be 4-byte aligned */
static inline void memset_nt(void *dest, uint32_t dword, size_t length)
{
	uint64_t dummy1, dummy2;
	uint64_t qword = ((uint64_t)dword << 32) | dword;

	asm volatile(
		"	movl %%edx,%%ecx\n"
		"	andl $63,%%edx\n"
		"	shrl $6,%%ecx\n"
		"	jz 9f\n"
		"1:  movnti %%rax,(%%rdi)\n"
		"2:  movnti %%rax,1*8(%%rdi)\n"
		"3:  movnti %%rax,2*8(%%rdi)\n"
		"4:  movnti %%rax,3*8(%%rdi)\n"
		"5:  movnti %%rax,4*8(%%rdi)\n"
		"6:  movnti %%rax,5*8(%%rdi)\n"
		"7:  movnti %%rax,6*8(%%rdi)\n"
		"8:  movnti %%rax,7*8(%%rdi)\n"
		"	leaq 64(%%rdi),%%rdi\n"
		"	decl %%ecx\n"
		"	jnz 1b\n"
		"9:  movl %%edx,%%ecx\n"
		"	andl $7,%%edx\n"
		"	shrl $3,%%ecx\n"
		"	jz 11f\n"
		"10: movnti %%rax,(%%rdi)\n"
		"	leaq 8(%%rdi),%%rdi\n"
		"	decl %%ecx\n"
		"	jnz 10b\n"
		"11: movl %%edx,%%ecx\n"
		"	shrl $2,%%ecx\n"
		"	jz 12f\n"
		"	movnti %%eax,(%%rdi)\n"
		"12:\n"
		: "=D"(dummy1), "=d" (dummy2) : "D" (dest), "a" (qword), "d" (length) : "memory", "rcx");
}

/* ======================= Write ordering (begin) ================= */

#define CACHELINE_SIZE  (64)
#define CACHELINE_MASK  (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr)+CACHELINE_SIZE-1) & CACHELINE_MASK)

#define X86_FEATURE_PCOMMIT	( 9*32+22) /* PCOMMIT instruction */
#define X86_FEATURE_CLFLUSHOPT	( 9*32+23) /* CLFLUSHOPT instruction */
#define X86_FEATURE_CLWB	( 9*32+24) /* CLWB instruction */

#pragma GCC push_options
#pragma GCC optimize("O2")

static inline bool arch_has_pcommit(void)
{
	return static_cpu_has(X86_FEATURE_PCOMMIT);
}

static inline bool arch_has_clwb(void)
{
	return static_cpu_has(X86_FEATURE_CLWB);
}

#pragma GCC pop_options

extern int opensimfs_support_clwb;
extern int opensimfs_support_pcommit;

#define _mm_clflush(addr) \
	asm volatile("clflush %0" : "+m" (*(volatile char *)(addr)))
#define _mm_clflushopt(addr) \
	asm volatile(".byte 0x66; clflush %0" : "+m" (*(volatile char *)(addr)))
#define _mm_clwb(addr) \
	asm volatile(".byte 0x66; xsaveopt %0" : "+m" (*(volatile char *)(addr)))
#define _mm_pcommit() \
	asm volatile(".byte 0x66, 0x0f, 0xae, 0xf8")

/* Provides ordering from all previous clflush too */
static inline void PERSISTENT_MARK(void)
{
	/* TODO: Fix me. */
}

static inline void PERSISTENT_BARRIER(void)
{
	asm volatile ("sfence\n" : : );
	if (opensimfs_support_pcommit) {
		/* Do nothing */
	}
}

static inline void opensimfs_flush_buffer(
	void *buf,
	uint32_t len,
	bool fence)
{
	uint32_t i;
	len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
	if (opensimfs_support_clwb) {
		for (i = 0; i < len; i += CACHELINE_SIZE)
			_mm_clwb(buf + i);
	} else {
		for (i = 0; i < len; i += CACHELINE_SIZE)
			_mm_clflush(buf + i);
	}
	/* Do a fence only if asked. We often don't need to do a fence
	 * immediately after clflush because even if we get context switched
	 * between clflush and subsequent fence, the context switch operation
	 * provides implicit fence. */
	if (fence)
		PERSISTENT_BARRIER();
}

static inline int memcpy_to_pmem_nocache(
	void *dst,
	const void *src,
	unsigned int size)
{
	return __copy_from_user_inatomic_nocache(dst, src, size);
}

/* ======================= Write ordering (end) =================== */

static inline void opensimfs_set_next_log_page_address(
	struct super_block *sb,
	struct opensimfs_inode_log_page *curr_page,
	u64 next_page,
	int fence)
{
	curr_page->page_tail.next_page = next_page;
	opensimfs_flush_buffer(&curr_page->page_tail,
		sizeof(struct opensimfs_inode_log_page_tail), 0);
	if (fence)
		PERSISTENT_BARRIER();
}

static inline bool opensimfs_goto_next_log_page(
	struct super_block *sb,
	u64 curr_p)
{
	void *addr;
	u8 type;

	if (LOG_ENTRY_LOC(curr_p) + 32 > LOG_LAST_ENTRY)
		return true;

	addr = opensimfs_get_block(sb, curr_p);
	type = opensimfs_get_log_entry_type(addr);
	if (type == LOG_NEXT_PAGE)
		return true;

	return false;
}

static inline u64 opensimfs_next_log_page(
	struct super_block *sb,
	u64 curr_p)
{
	void *curr_addr = opensimfs_get_block(sb, curr_p);
	unsigned long log_page_tail = ((unsigned long)curr_addr & ~INVALID_MASK)
		+ LOG_LAST_ENTRY;
	return ((struct opensimfs_inode_log_page_tail *)log_page_tail)->next_page;
}

static inline unsigned long opensimfs_get_num_blocks(
	unsigned short btype)
{
	unsigned long num_blocks;
	if (btype == OPENSIMFS_BLOCK_TYPE_4K) {
		num_blocks = 1;
	} else if (btype == OPENSIMFS_BLOCK_TYPE_2M) {
		num_blocks = 512;
	} else {
		num_blocks = 0x40000;
	}
	return num_blocks;
}

static inline void opensimfs_update_log_tail(
	struct opensimfs_inode *pi,
	u64 new_log_tail)
{
	PERSISTENT_BARRIER();
	pi->log_tail = new_log_tail;
	opensimfs_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 1);
}

static inline bool opensimfs_is_last_entry(u64 curr_p, size_t size)
{
	unsigned int entry_end;
	entry_end = LOG_ENTRY_LOC(curr_p) + size;
	return entry_end > LOG_LAST_ENTRY;
}

#define LOG_EXTENDED_THRESHOLD 256

static inline struct journal_ptr_pair *opensimfs_get_journal_pointers(
	struct super_block *sb,
	int cpu)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);

	if (cpu >= sbi->cpus)
		return NULL;

	return (struct journal_ptr_pair *)((char *)opensimfs_get_block(sb,
		OPENSIMFS_DEF_BLOCK_SIZE_4K) + cpu * CACHELINE_SIZE);
}

extern unsigned int opensimfs_blk_type_to_shift[OPENSIMFS_BLOCK_TYPE_MAX];
extern uint32_t opensimfs_blk_type_to_size[OPENSIMFS_BLOCK_TYPE_MAX];

static inline unsigned int opensimfs_inode_blk_shift(
	struct opensimfs_inode *pi)
{
	return opensimfs_blk_type_to_shift[pi->i_blk_type];
}

static inline uint32_t  opensimfs_inode_blk_size(
	struct opensimfs_inode *pi)
{
	return opensimfs_blk_type_to_size[pi->i_blk_type];
}

#endif
