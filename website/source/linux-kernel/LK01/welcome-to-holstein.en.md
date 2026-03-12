---
title: Analyzing the Holstein Module and Triggering the Vulnerability
tags:
    - [Linux]
    - [Kernel]
    - [Stack Overflow]
lang: en
permalink: /en/linux-kernel/LK01/welcome-to-holstein.html
pagination: true
bk: ../introduction/compile-and-transfer.html
fd: stack_overflow.html
---
In LK01 (Holstein), we study the basic attack patterns used in kernel exploitation. If you have not downloaded LK01 yet, first grab [the LK01 exercise files](distfiles/LK01.tar.gz) from the introduction chapter.

`qemu/rootfs.cpio` is the filesystem image. A common first step is to create a `mount` directory and extract the cpio archive there. Do this as root.

## Checking the initialization process
There is a file called `/init`. After the kernel finishes booting, that is the first program executed in user space. In many CTF kernels this script loads the vulnerable driver, so always inspect it.

In this challenge `/init` is just the default script from buildroot, and the driver setup lives in `/etc/init.d/S99pawnyable` instead.
```sh
#!/bin/sh

##
## Setup
##
mdev -s
mount -t proc none /proc
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
stty -opost
echo 2 > /proc/sys/kernel/kptr_restrict
#echo 1 > /proc/sys/kernel/dmesg_restrict

##
## Install driver
##
insmod /root/vuln.ko
mknod -m 666 /dev/holstein c `grep holstein /proc/devices | awk '{print $1;}'` 0

##
## User shell
##
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
echo "[ Holstein v1 (LK01) - Pawnyable ]"
setsid cttyhack setuidgid 1337 sh

##
## Cleanup
##
umount /proc
poweroff -d 0 -f
```

Several lines are important.

The first one is:
```sh
echo 2 > /proc/sys/kernel/kptr_restrict
```
As already mentioned in the mitigation chapter, this controls kernel address disclosure, so KASLR-related address output is restricted. That is annoying during debugging, so you may want to disable it locally while practicing.

The following line is commented out:
```sh
#echo 1 > /proc/sys/kernel/dmesg_restrict
```
Many real CTF kernel problems enable this restriction. It controls whether unprivileged users may read `dmesg`. In this practice setup, `dmesg` is intentionally left available.

Next, the module is loaded with:
```sh
insmod /root/vuln.ko
mknod -m 666 /dev/holstein c `grep holstein /proc/devices | awk '{print $1;}'` 0
```
The `insmod` call loads `/root/vuln.ko`, and `mknod` creates a character device called `/dev/holstein` that is bound to that driver.

Finally:
```sh
setsid cttyhack setuidgid 1337 sh
```
This launches `sh` as UID 1337. That is why you get an immediate shell without a login prompt.

While debugging, it is convenient to change that UID to `0` and give yourself a root shell directly.

There are also other initialization scripts under `/etc/init.d`, such as `S01syslogd` and `S41dhcpcd`. For local debugging those are often unnecessary. Moving them out of the way can reduce boot time by a few seconds.

## Analyzing the Holstein module
The vulnerable kernel module source code is in `src/vuln.c`. Let's read it from top to bottom.

### Initialization and cleanup
Every kernel module defines initialization and cleanup code.
```c
module_init(module_initialize);
module_exit(module_cleanup);
```
These lines register the startup and shutdown routines. First, look at `module_initialize`.
```c
static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
    printk(KERN_WARNING "Failed to register device\n");
    return -EBUSY;
  }

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    printk(KERN_WARNING "Failed to add cdev\n");
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}
```
To make the module accessible from user space, the kernel must expose an interface. In this case the interface is a character device because the code uses `cdev_add`.

At this stage nothing appears under `/dev` yet. As we saw above, the actual device file `/dev/holstein` is created later by `mknod`.

The interesting part is this line:
```c
cdev_init(&c_dev, &module_fops);
```
The second argument is a pointer to a function table:
```c
static struct file_operations module_fops =
  {
   .owner   = THIS_MODULE,
   .read    = module_read,
   .write   = module_write,
   .open    = module_open,
   .release = module_close,
  };
```
That table connects user actions on `/dev/holstein`, such as `read`, `write`, and `open`, to the corresponding module functions.

The cleanup code is simple:
```c
static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}
```

### `open`
Now look at `module_open`.
```c
static int module_open(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_open called\n");

  g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }

  return 0;
}
```
`printk` writes to the kernel log buffer. You can read those messages with `dmesg`.

The important part is `kmalloc`, which is the kernel equivalent of `malloc`. It allocates `BUFFER_SIZE` bytes from the kernel heap and stores the pointer in the global variable `g_buf`.

So opening the device allocates a `0x400`-byte kernel heap buffer.

### `close`
Next is `module_close`.
```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}
```
`kfree` is the matching free operation for `kmalloc`.

This is the normal behavior you would expect: the buffer allocated in `open` is released in `close`.

In fact, there is already a bug here that can lead to privilege escalation later, but we will postpone that to a later chapter.

### `read`
`module_read` is called when user space performs a `read` system call.
```c
static ssize_t module_read(struct file *file,
                        char __user *buf, size_t count,
                        loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_read called\n");

  memcpy(kbuf, g_buf, BUFFER_SIZE);
  if (_copy_to_user(buf, kbuf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}
```
The function first copies `BUFFER_SIZE` bytes from `g_buf` into a stack buffer called `kbuf`, then copies `count` bytes of that stack buffer into user space.

The helper used here is `_copy_to_user`, which is a lower-level form of `copy_to_user` that skips some of the safer stack overflow checking.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="Wolf" ></div>
  <p class="says">
    `copy_to_user` and `copy_from_user` are often implemented as inline helpers that perform additional size checks when possible.
  </p>
</div>

So the `read` path copies the heap buffer into the stack and then returns some of that stack data to user space.

### `write`
Finally, look at `module_write`.
```c
static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_write called\n");

  if (_copy_from_user(kbuf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }
  memcpy(g_buf, kbuf, BUFFER_SIZE);

  return count;
}
```
First, user input is copied into the stack buffer `kbuf` by `_copy_from_user`. Then the entire `BUFFER_SIZE` bytes are copied into `g_buf`.

## The stack overflow vulnerability
At this point you should already have found at least one vulnerability. In this chapter we focus on the stack overflow in `module_write`.
```c
static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_write called\n");

  if (_copy_from_user(kbuf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }
  memcpy(g_buf, kbuf, BUFFER_SIZE);

  return count;
}
```
The bug is obvious: `count` comes directly from user space, but `kbuf` is only `0x400` bytes long. If `count` is larger, `_copy_from_user` overflows the kernel stack buffer.

Kernel function calls use the same basic calling convention ideas as user-space code, so if you can smash the return address, you can also build a ROP chain.

## Triggering the vulnerability
Before abusing the bug, it is useful to write a normal test program that just talks to the device and confirms the interface works. From there, increase the write size until the bug is triggered and study the resulting crash in gdb.

That crash is the starting point for the real exploit in the next chapter.
