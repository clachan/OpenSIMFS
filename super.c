#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/statfs.h>
#include <linux/slab.h>
#include <linux/pfn_t.h>
#include <linux/blkdev.h>
#include <linux/random.h>
#include "opensimfs.h"

int opensimfs_support_clwb;
int opensimfs_support_pcommit;
static struct kmem_cache *opensimfs_inode_cachep;
static struct kmem_cache *opensimfs_range_node_cachep;

static void init_once(void *foo);

static int __init init_range_node_cache(void)
{
	opensimfs_range_node_cachep = kmem_cache_create(
		"opensimfs_range_node_cache",
		sizeof(struct opensimfs_range_node),
		0,
		(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
		NULL);

	if (opensimfs_range_node_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_range_node_cache(void)
{
	kmem_cache_destroy(opensimfs_range_node_cachep);
}

static int __init init_inode_cache(void)
{
	opensimfs_inode_cachep = kmem_cache_create(
		"opensimfs_inode_cache",
		sizeof(struct opensimfs_inode_info),
		0,
		(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
		init_once);

	if (opensimfs_inode_cachep == NULL)
		return -ENOMEM;

	return 0;
}

static void destroy_inode_cache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before
	 * we destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(opensimfs_inode_cachep);
}

static int opensimfs_get_sb_info(
	struct super_block *sb,
	struct opensimfs_super_block_info *sbi)
{
	pfn_t pfn;
	void *virt_addr = NULL;
	long size;
	
	if (!sb->s_bdev->bd_disk->fops->direct_access) {
		return -EINVAL;
	}

	sbi->s_bdev = sb->s_bdev;
	size = sb->s_bdev->bd_disk->fops->direct_access(
		sb->s_bdev, 0, &virt_addr, &pfn);
	if (size <= 0)
		return -EINVAL;

	sbi->phys_addr = pfn_t_to_pfn(pfn);
	sbi->virt_addr = virt_addr;
	sbi->initsize = size;

	return 0;
}

static void opensimfs_set_default_opts(
	struct opensimfs_super_block_info *sbi)
{
	set_mount_opt(sbi->s_mount_opt, OPENSIMFS_MOUNT_HUGEIOREMAP);
	set_mount_opt(sbi->s_mount_opt, OPENSIMFS_MOUNT_ERRORS_CONT);
	sbi->reserved_blocks = OPENSIMFS_RESERVED_BLOCKS;
}

static void opensimfs_set_blocksize(
	struct super_block *sb,
	unsigned long size)
{
	int bits;

	bits = fls(size) - 1;
	sb->s_blocksize_bits = bits;
	sb->s_blocksize = (1 << bits);
}

void opensimfs_sysfs_init(
	struct super_block *sb)
{
}

void opensimfs_sysfs_exit(
	struct super_block *sb)
{
}

inline struct opensimfs_inode *opensimfs_get_basic_inode(
	struct super_block *sb,
	u64 ino)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);

	return (struct opensimfs_inode *)
		(sbi->virt_addr +
		 OPENSIMFS_ROOT_INODE_START +
		 (ino - OPENSIMFS_ROOT_INO) * OPENSIMFS_INODE_SIZE);
}

inline struct opensimfs_inode *opensimfs_get_special_inode(
	struct super_block *sb,
	u64 ino)
{
	if (ino == 0 || ino >= OPENSIMFS_NORMAL_INODE_START)
		return NULL;

	return opensimfs_get_basic_inode(sb, ino);
}

/* returns root_inode */
static struct opensimfs_inode *opensimfs_init(
	struct super_block *sb,
	unsigned long size)
{
	unsigned long blocksize;
	unsigned long reserved_space, reserved_blocks;
	struct opensimfs_super_block *super;
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	struct opensimfs_inode *root_i;

	sbi->num_blocks = (size >> PAGE_SHIFT);
	blocksize = sbi->blocksize = OPENSIMFS_DEF_BLOCK_SIZE_4K;

	opensimfs_set_blocksize(sb, blocksize);
	blocksize = sb->s_blocksize;

	if (sbi->blocksize && sbi->blocksize != blocksize)
		sbi->blocksize = blocksize;

	reserved_space = OPENSIMFS_SB_SIZE * 4;
	reserved_blocks = (reserved_space + blocksize - 1) / blocksize;

	super = opensimfs_get_super(sb);
	
	/* clear-out super block and inode table */
	memset_nt(super, 0, sbi->reserved_blocks * sbi->blocksize);
	super->s_blocksize = cpu_to_le32(blocksize);
	super->s_size = cpu_to_le64(size);
	super->s_magic = cpu_to_le32(OPENSIMFS_SUPER_MAGIC);

	opensimfs_init_blockmap(sb);
	opensimfs_init_inode_inuse_list(sb);
	opensimfs_init_inode_table(sb);
	
	opensimfs_flush_buffer(super, OPENSIMFS_SB_SIZE, false);
	opensimfs_flush_buffer(
		(char *)super + OPENSIMFS_SB_SIZE, sizeof(*super), false);

	root_i = opensimfs_get_special_inode(sb, OPENSIMFS_ROOT_INO);

	/* allocate root inode */
	root_i->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
	root_i->i_uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
	root_i->i_gid = cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
	root_i->i_links_count = cpu_to_le16(2);
	root_i->i_flags = 0;
	root_i->i_blocks = cpu_to_le64(1);
	root_i->i_size = cpu_to_le64(sb->s_blocksize);
	root_i->i_atime = root_i->i_mtime = root_i->i_ctime =
		cpu_to_le32(get_seconds());
	root_i->opensimfs_ino = OPENSIMFS_ROOT_INO;
	root_i->valid = 1;
	opensimfs_flush_buffer(root_i, sizeof(*root_i), false);

	PERSISTENT_MARK();
	PERSISTENT_BARRIER();

	return root_i;
}

static loff_t opensimfs_max_file_size(int bits)
{
	loff_t res;

	res = (1ULL << 63) - 1;
	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;

	return res;
}

static inline
struct opensimfs_range_node *opensimfs_alloc_range_node(
	struct super_block *sb)
{
	struct opensimfs_range_node *p;
	p = (struct opensimfs_range_node *)
		kmem_cache_alloc(opensimfs_range_node_cachep, GFP_NOFS);
	return p;
}

static inline
void opensimfs_free_range_node(
	struct opensimfs_range_node *node)
{
	kmem_cache_free(opensimfs_range_node_cachep, node);
}

inline struct opensimfs_range_node *opensimfs_alloc_block_node(
	struct super_block *sb)
{
	return opensimfs_alloc_range_node(sb);
}

inline void opensimfs_free_block_node(
	struct super_block *sb,
	struct opensimfs_range_node *node)
{
	opensimfs_free_range_node(node);
}

inline struct opensimfs_range_node *opensimfs_alloc_inode_node(
	struct super_block *sb)
{
	return opensimfs_alloc_range_node(sb);
}

inline void opensimfs_free_inode_node(
	struct super_block *sb,
	struct opensimfs_range_node *node)
{
	opensimfs_free_range_node(node);
}

static struct inode *opensimfs_alloc_inode(
	struct super_block *sb)
{
	struct opensimfs_inode_info *vi;

	vi = kmem_cache_alloc(opensimfs_inode_cachep, GFP_NOFS);
	if (!vi)
		return NULL;

	vi->vfs_inode.i_version = 1;
	return &vi->vfs_inode;
}

static void opensimfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct opensimfs_inode_info *vi = OPENSIMFS_I(inode);

	kmem_cache_free(opensimfs_inode_cachep, vi);
}

static void opensimfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, opensimfs_i_callback);
}

static void opensimfs_put_super(struct super_block *sb)
{
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);

	if (sbi->virt_addr) {
		sbi->virt_addr = NULL;
	}

	opensimfs_sysfs_exit(sb);
	kfree(sbi);
	sb->s_fs_info = NULL;
}

int opensimfs_statfs(
	struct dentry *d,
	struct kstatfs *buf)
{
	struct super_block *sb = d->d_sb;
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);

	buf->f_type = OPENSIMFS_SUPER_MAGIC;

	buf->f_type = OPENSIMFS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = sbi->num_blocks;
	buf->f_bfree = buf->f_bavail = opensimfs_count_free_blocks(sb);
	buf->f_files = LONG_MAX;
	buf->f_ffree = LONG_MAX;
	buf->f_namelen = OPENSIMFS_NAME_LEN;

	return 0;
}

int opensimfs_remount(
	struct super_block *sb,
	int *mntflags,
	char *data)
{
	struct opensimfs_super_block *ps;
	struct opensimfs_super_block_info *sbi = OPENSIMFS_SB(sb);
	int ret = -EINVAL;

	mutex_lock(&sbi->s_lock);

	sb->s_flags =
		(sb->s_flags & ~MS_POSIXACL) |
		((sbi->s_mount_opt & OPENSIMFS_MOUNT_POSIX_ACL) ? MS_POSIXACL : 0);
	if ((*mntflags & MS_RDONLY) != (sb->s_flags & MS_RDONLY)) {
		/* update time stuffs */
		ps = opensimfs_get_super(sb);
	}

	mutex_unlock(&sbi->s_lock);
	ret = 0;
	return ret;
}

static int opensimfs_show_options(
	struct seq_file *seq,
	struct dentry *root)
{
	return 0;
}

static struct super_operations opensimfs_sops = {
	.alloc_inode	= opensimfs_alloc_inode,
	.destroy_inode	= opensimfs_destroy_inode,
	.write_inode	= opensimfs_write_inode,
	.dirty_inode	= opensimfs_dirty_inode,
	.evict_inode	= opensimfs_evict_inode,
	.put_super		= opensimfs_put_super,
	.statfs			= opensimfs_statfs,
	.remount_fs		= opensimfs_remount,
	.show_options	= opensimfs_show_options,
};

/*
static struct dentry *opensimfs_fh_to_dentry(
	struct super_block *sb,
	int fh_type)
{
	return NULL;
}

static struct dentry *opensimfs_fh_to_parent(
	struct fid *fid,
	int fh_len,
	int fh_type)
{
	return NULL;
}

static const struct export_operations opensimfs_export_ops = {
	.fh_to_dentry 	= opensimfs_fh_to_dentry,
	.fh_to_parent	= opensimfs_fh_to_parent,
	.get_parent		= opensimfs_get_parent,
};
*/

static int opensimfs_fill_super(
	struct super_block *sb,
	void *data,
	int silent)
{
	int retval = -EINVAL;

	struct opensimfs_super_block *super;
	struct opensimfs_inode *root_pi;
	struct opensimfs_inode_info *si;
	struct opensimfs_inode_info_header *sih;
	struct opensimfs_super_block_info *sbi = NULL;
	struct inode *root_i;
	u32 random = 0;

	sbi = kzalloc(sizeof(struct opensimfs_super_block_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;
	sbi->sb = sb;

	opensimfs_set_default_opts(sbi);

	if (opensimfs_get_sb_info(sb, sbi))
		goto out;

	get_random_bytes(&random, sizeof(u32));
	atomic_set(&sbi->next_generation, random);

	/* initialize with default values */
	sbi->mode = (S_IRUGO | S_IXUGO | S_IWUGO);
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();
	set_mount_opt(sbi->s_mount_opt, OPENSIMFS_MOUNT_DAX);
	clear_mount_opt(sbi->s_mount_opt, OPENSIMFS_MOUNT_PROTECT);
	set_mount_opt(sbi->s_mount_opt, OPENSIMFS_MOUNT_HUGEIOREMAP);

	opensimfs_sysfs_init(sb);

	mutex_init(&sbi->s_lock);

	set_mount_opt(sbi->s_mount_opt, OPENSIMFS_MOUNT_MOUNTING);

	/* clayc: always initialize now */
	set_mount_opt(sbi->s_mount_opt, OPENSIMFS_MOUNT_FORMAT);
	if (sbi->s_mount_opt & OPENSIMFS_MOUNT_FORMAT) {
		root_pi = opensimfs_init(sb, sbi->initsize);
		if (IS_ERR(root_pi))
			goto out;
		super = opensimfs_get_super(sb);
		goto setup_sb;
	}

setup_sb:
	sb->s_magic = le32_to_cpu(super->s_magic);
	sb->s_magic = le32_to_cpu(super->s_magic);
	sb->s_op = &opensimfs_sops;
	sb->s_maxbytes = opensimfs_max_file_size(sb->s_blocksize_bits);
	sb->s_time_gran = 1;
	/* sb->s_export_op = &nova_export_ops; */
	sb->s_xattr = NULL;
	sb->s_flags |= MS_NOSEC;

	root_i = opensimfs_iget(sb, OPENSIMFS_ROOT_INO);
	if (IS_ERR(root_i)) {
		retval = PTR_ERR(root_i);
		goto out;
	}

	si = OPENSIMFS_I(root_i);
	sih = &si->header;

	opensimfs_new_blocks(sb, &sih->pte_block, 1, 1);
	opensimfs_new_blocks(sb, &sih->data_block, 1, 1);
	opensimfs_new_blocks(sb, &sih->pfw_pte_block, 1, 1);
	opensimfs_new_blocks(sb, &sih->pfw_data_block, 1, 1);

	opensimfs_append_dir_init_entries(
		sb, root_i, OPENSIMFS_ROOT_INO, OPENSIMFS_ROOT_INO);

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		retval = -ENOMEM;
		goto out;
	}

	if (!(sb->s_flags & MS_RDONLY)) {
		/* update time stuffs */
	}

	clear_mount_opt(sbi->s_mount_opt, OPENSIMFS_MOUNT_MOUNTING);
	retval = 0;

	return retval;

out:
	kfree(sbi);

	return retval;
}

static struct dentry *opensimfs_mount(
	struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, opensimfs_fill_super);
}

static struct file_system_type opensimfs_type = {
	.owner	  = THIS_MODULE,
	.name	   = "OpenSIMFS",
	.mount	  = opensimfs_mount,
	.kill_sb	= kill_block_super,
};

static void init_once(void *foo)
{
	struct opensimfs_inode_info *vi = foo;

	inode_init_once(&vi->vfs_inode);
}

static int __init init_opensimfs(void)
{
	int rc = 0;

	if (arch_has_pcommit())
		opensimfs_support_pcommit = 1;

	if (arch_has_clwb())
		opensimfs_support_clwb = 1;

	rc = init_range_node_cache();
	if (rc)
		return rc;

	rc = init_inode_cache();
	if (rc)
		goto out1;

	rc = register_filesystem(&opensimfs_type);
	if (rc)
		goto out2;

	return 0;

out2:
	destroy_inode_cache();
out1:
	destroy_range_node_cache();
	return rc;
}

static void __exit exit_opensimfs(void)
{
	unregister_filesystem(&opensimfs_type);
	destroy_inode_cache();
	destroy_range_node_cache();
}

MODULE_AUTHOR("Clay Chang <clay.chang@gmail.com>");
MODULE_DESCRIPTION("OpenSIMFS: An Open Source version of SIMFS");
MODULE_LICENSE("GPL");

module_init(init_opensimfs)
module_exit(exit_opensimfs)
