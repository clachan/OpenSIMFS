#include <linux/fs.h>
#include "opensimfs.h"

struct inode_operations opensimfs_file_inode_operations = {
	.setattr 	= opensimfs_notify_change,
	.getattr 	= opensimfs_getattr,
	.get_acl 	= NULL,
};

struct file_operations opensimfs_dax_file_operations = {
};
