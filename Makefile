#
# Makefile for the linux OpenSIMFS filesystem routines.
#

ccflags-y := -O0 -g

obj-y += opensimfs.o

opensimfs-y := super.o dir.o inode.o balloc.o namei.o file.o symlink.o dax.o bbuild.o journal.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
