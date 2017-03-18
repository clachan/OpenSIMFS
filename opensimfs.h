#ifndef ___OPENSIMFS_H___
#define ___OPENSIMFS_H___

#include <linux/radix-tree.h>

#define OPENSIMFS_SUPER_MAGIC 0x4F53494D /* 'O' 'S' 'I' 'M' */

/*
 * mount options
 */
#define OPENSIMFS_MOUNT_PROTECT		 0x000001	/* wprotect CR0.WP */
#define OPENSIMFS_MOUNT_XATTR_USER	  0x000002	/* Extended user attributes */
#define OPENSIMFS_MOUNT_POSIX_ACL	   0x000004	/* POSIX Access Control Lists */
#define OPENSIMFS_MOUNT_DAX			 0x000008	/* Direct Access */
#define OPENSIMFS_MOUNT_ERRORS_CONT	 0x000010	/* Continue on errors */
#define OPENSIMFS_MOUNT_ERRORS_RO	   0x000020	/* Remount fs ro on errors */
#define OPENSIMFS_MOUNT_ERRORS_PANIC	0x000040	/* Panic on errors */
#define OPENSIMFS_MOUNT_HUGEMMAP		0x000080	/* Huge mappings with mmap */
#define OPENSIMFS_MOUNT_HUGEIOREMAP	 0x000100	/* Huge mappings with ioremap */
#define OPENSIMFS_MOUNT_FORMAT		  0x000200	/* was FS formatted on mount? */
#define OPENSIMFS_MOUNT_MOUNTING		0x000400	/* FS currently being mounted */

#define OPENSIMFS_DEF_BLOCK_SIZE_4K	 4096
#define OPENSIMFS_SB_SIZE			   512
#define OPENSIMFS_RESERVED_BLOCKS	   3

/* The root inode follows immediately after the redundant super block */
#define OPENSIMFS_ROOT_INO		  (1)
#define OPENSIMFS_INODETABLE_INO	(2) /* Temporaty inode table */
#define OPENSIMFS_BLOCKNODE_INO	 (3)
#define OPENSIMFS_INODELIST_INO	 (4)
#define OPENSIMFS_LITEJOURNAL_INO   (5)
#define OPENSIMFS_INODELIST1_INO	(6)

#define OPENSIMFS_ROOT_INODE_START  (OPENSIMFS_SB_SIZE * 2)

/* Normal inode starts at 16 */
#define OPENSIMFS_NORMAL_INODE_START (16)

#define OPENSIMFS_INODE_SIZE		128
#define OPENSIMGS_INODE_BITS		7

#define OPENSIMFS_NAME_LEN			255

struct opensimfs_inode {
	__le16  i_reserved;
	u8	  valid;
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

	struct {
		__le32 rdev;
	} dev;
} __attribute((__packed__));

struct opensimfs_inode_info_header {
	struct radix_tree_root tree;
	struct radix_tree_root cache_tree;
	unsigned short i_mode;
	unsigned long i_size;
	unsigned long ino;
	unsigned long pi_addr;
	unsigned long mmap_pages;
	u64 last_setattr;
	u64	last_link_change;
};

struct opensimfs_inode_info {
	struct opensimfs_inode_info_header header;
	struct inode vfs_inode;
};

static inline struct opensimfs_inode_info *OPENSIMFS_I(struct inode *inode)
{
	return container_of(inode, struct opensimfs_inode_info, vfs_inode);
}

struct opensimfs_super_block {
	__le16  s_checksum;	 /* checksum of this sb */
	__le16  s_padding;
	__le32  s_magic;		/* magic signature */
	__le32  s_blocksize;	/* super block size in bytes */
	__le64  s_size;		 /* file system size in bytes */
	
	__le32  s_mtime;		/* mount time */
	__le32  s_wtime;		/* write time */
} __attribute((__packed__));

struct opensimfs_super_block_info {
	struct super_block *sb;
	struct block_device *s_bdev;

	/* 
	 * base physical and virtual address of OPENSIMFS, which
	 * is also the pointer to the super block.
	 */
	phys_addr_t	 phys_addr;
	void			*virt_addr;
	
	/* mount options */
	unsigned long   num_blocks;
	unsigned long   blocksize;
	unsigned long   initsize;
	unsigned long   s_mount_opt;
	kuid_t		  uid;	/* mount uid for root directory */
	kgid_t		  gid;	/* mount gid for root directory */
	umode_t		 mode;   /* mount mode for root directory */

	unsigned long   reserved_blocks;

	struct mutex	s_lock;
};

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

#define clear_mount_opt(o, opt) (o &= ~opt)
#define set_mount_opt(o, opt)   (o |= opt)
#define test_mount_opt(sb, opt) (OPENSIMFS_SB(sb)->s_mount_opt & opt)

/* dir.c */
int opensimfs_append_dir_init_entries(
	struct super_block *sb,
	struct opensimfs_inode *pi,
	u64 self_ino,
	u64 parent_ino);

/* inode.c */
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

/* balloc.c */
unsigned long opensimfs_count_free_blocks(
	struct super_block *sb);

/* namei.c */
struct dentry *opensimfs_get_parent(
	struct dentry *child);

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

/* ======================= Write ordering ========================= */

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

#endif
