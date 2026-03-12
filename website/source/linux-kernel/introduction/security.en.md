---
title: Security Mechanisms
date: 2021-09-22 17:01:30
tags:
    - [Linux]
    - [Kernel]
    - [SMAP]
    - [SMEP]
    - [KASLR]
    - [FGKASLR]
    - [KPTI]
    - [KAISER]
lang: en
permalink: /en/linux-kernel/introduction/security.html
pagination: true
bk: debugging.html
fd: compile-and-transfer.html
---
Linux provides several security mechanisms to mitigate kernel exploitation. Some of them are hardware-level protections similar to NX in userland, so the same knowledge also applies directly to Windows kernel exploitation.

This section focuses on protections specific to the kernel. Device drivers also have security features such as Stack Canary, but there is nothing especially unique about them here, so we will not discuss them.

For kernel boot parameters, the [official documentation](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/kernel-parameters.txt) is a helpful reference.

## SMEP (Supervisor Mode Execution Prevention)
Among kernel security features, the most representative ones are SMEP and SMAP.
**SMEP** prevents the kernel from suddenly executing code in user space while already running in kernel mode. Conceptually it is similar to NX.

SMEP is a mitigation, but not a complete defense by itself. For example, suppose a kernel vulnerability lets an attacker control RIP. If SMEP is disabled, the attacker can execute shellcode prepared in user space like this:
```c
char *shellcode = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXECUTE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
memcpy(shellcode, SHELLCODE, sizeof(SHELLCODE));

control_rip(shellcode); // RIP = shellcode
```
However, if SMEP is enabled, trying to execute shellcode placed in user space as above triggers a kernel panic. As a result, even if the attacker gains control of RIP, turning that into privilege escalation becomes much harder.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_thinking.png" alt="Wolf" ></div>
  <p class="says">
    Then what should a kernel shellcode actually do?<br>
    We will study privilege-escalation techniques in another chapter.
  </p>
</div>

SMEP can be enabled with a QEMU command-line option. If the `-cpu` option contains `+smep` as below, SMEP is enabled.
```
-cpu kvm64,+smep
```
You can also confirm it from inside the guest by looking at `/proc/cpuinfo`.
```
$ cat /proc/cpuinfo | grep smep
```

SMEP is a hardware security feature. It becomes active when bit 21 of the `CR4` register is set.

## SMAP (Supervisor Mode Access Prevention)
It is obvious that user space should not be able to read or write kernel memory, but Linux also has a mechanism called **SMAP** (Supervisor Mode Access Prevention), which prevents the kernel from reading or writing user-space memory directly. To access user-space data from kernel space, code is supposed to use helper functions such as [`copy_from_user`](https://www.kernel.org/doc/htmldocs/kernel-api/API---copy-from-user.html) and [`copy_to_user`](https://www.kernel.org/doc/htmldocs/kernel-api/API---copy-to-user.html).
At first glance, it may seem strange to forbid the more privileged kernel from directly accessing the less privileged user space. Why is that useful?

I do not know the full historical background, but the benefits of SMAP can be thought of as mainly two things.

The first is preventing stack pivots.
In the SMEP example, control over RIP was not enough to run shellcode. However, the Linux kernel contains an enormous amount of machine code, so gadgets like the following are guaranteed to exist.
```
mov esp, 0x12345678; ret;
```
Whatever value goes into `ESP`, once this gadget is executed, `RSP` will be changed to that value[^1]. On the other hand, such low addresses can often be allocated from userland with `mmap`, so even if SMEP is enabled, an attacker who controls RIP can still execute a ROP chain like this:
```c
void *p = mmap(0x12340000, 0x10000, ...);
unsigned long *chain = (unsigned long*)(p + 0x5678);
*chain++ = rop_pop_rdi;
*chain++ = 0;
*chain++ = ...;
...

control_rip(rop_mov_esp_12345678h);
```
If SMAP is enabled, data mapped in user space such as the ROP chain cannot be read from kernel space, so the `ret` in the stack pivot will cause a kernel panic.
In this way, SMAP strengthens SMEP by mitigating ROP-based attacks as well.

The second benefit of SMAP is preventing bugs that are easy to make in kernel programming.
This relates to mistakes that kernel programmers, for example device driver authors, can accidentally write. Suppose a driver contains code like this. (You do not need to understand the exact function signature yet.)
```c
char buffer[0x10];

static long mydevice_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  if (cmd == 0xdead) {
    memcpy(buffer, arg, 0x10);
  } else if (cmd == 0xcafe) {
    memcpy(arg, buffer, 0x10);
  }
  return 
}
```
You can imagine that `memcpy` is reading from and writing to the global variable `buffer`.

From user space, the module can be used like this to store 0x10 bytes of data:
```c
int fd = open("/dev/mydevice", O_RDWR);

char src[0x10] = "Hello, World!";
char dst[0x10];

ioctl(fd, 0xdead, src);
ioctl(fd, 0xcafe, dst);

printf("%s\n", dst); // --> Hello, World!
```
If you are used to user-space programming, this does not look unusual. The `memcpy` size is fixed, and at first glance it seems fine.

However, if SMAP is disabled, the following call is also accepted:
```c
ioctl(fd, 0xdead, 0xffffffffdeadbeef);
```
`0xffffffffdeadbeef` is not a valid user-space address, but suppose for the sake of example that it points into sensitive kernel data. The driver would then execute:
```
memcpy(buffer, 0xffffffffdeadbeef, 0x10);
```
and end up reading that secret data. If a driver uses `memcpy` directly on an address received from user space without any checks, user space effectively gains arbitrary read and write access to kernel memory.
For people not used to kernel programming, this kind of vulnerability is very easy to overlook, but the impact is severe because it gives AAR/AAW. SMAP is useful partly because it helps prevent exactly this kind of mistake.

SMAP can be enabled through the QEMU command line. If the `-cpu` option contains `+smap` as below, SMAP is enabled.
```
-cpu kvm64,+smap
```
You can also confirm it from inside the guest by checking `/proc/cpuinfo`.
```
$ cat /proc/cpuinfo | grep smap
```

Like SMEP, SMAP is a hardware security feature. It is enabled by setting bit 22 of the `CR4` register.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="Wolf" ></div>
  <p class="says">
    On Intel CPUs there are instructions called <a href="https://www.felixcloutier.com/x86/stac" target="_blank">STAC</a> and <a href="https://www.felixcloutier.com/x86/clac" target="_blank">CLAC</a> that set EFLAGS.AC (Alignment Check) to 1 or 0. While AC is set, SMAP is temporarily bypassed.
  </p>
</div>


## KASLR / FGKASLR
In user space there was ASLR (Address Space Layout Randomization), which randomizes addresses. Similarly, Linux also has a mitigation called **KASLR** (Kernel ASLR), which randomizes the addresses of the Linux kernel and kernel-module code and data regions.
Once the kernel is loaded, it does not move, so KASLR only takes effect once at boot time. If you can leak even one function or data address from the Linux kernel, you can recover the base address.

Since around [2020](https://lwn.net/Articles/824307/), an even stronger variant called **FGKASLR** (Function Granular KASLR) has appeared. As of 2022 it seems to be disabled by default, but it randomizes the location of each kernel function individually. Even if you can leak the address of one kernel function, you can no longer derive the base address.
However, FGKASLR does not randomize sections such as the data segment, so if you can leak a data address, you can still obtain the base address. That said, even the base address is no longer enough to compute the address of a specific function, although it can still be useful for some special attack vectors that appear later.

Remember that addresses are shared across kernel space. Even if one device driver is not exploitable because of KASLR, another driver leaking a kernel address can make the first one exploitable too, because the underlying kernel addresses are shared.

KASLR can be disabled with a kernel boot argument. If QEMU's `-append` option includes `nokaslr`, KASLR is disabled.
```
-append "... nokaslr ..."
```

## KPTI (Kernel Page-Table Isolation)
In 2018, a side-channel attack called [Meltdown](https://ja.wikipedia.org/wiki/Meltdown) was discovered on Intel and other CPUs. We will not explain the vulnerability itself here, but it was a serious issue that allowed user mode to read kernel memory, which could for example defeat KASLR. To mitigate Meltdown, recent Linux kernels enable **KPTI** (Kernel Page-Table Isolation), also known by the older name **KAISER**.

As you know, page tables are used to translate virtual addresses into physical addresses. This security feature separates those page tables between user mode and kernel mode[^2]. KPTI exists specifically to stop Meltdown, so it is not usually a direct obstacle in ordinary kernel exploitation. However, if you build a ROP chain in kernel space while KPTI is enabled, problems occur when returning back to user space at the end. We will explain the concrete solution in the Kernel ROP chapter.

KPTI can be controlled by kernel boot arguments. If the QEMU `-append` option includes `pti=on`, KPTI is enabled. If it includes `pti=off` or `nopti`, KPTI is disabled.
```
-append "... pti=on ..."
```
You can also check it via `/sys/devices/system/cpu/vulnerabilities/meltdown`. If it says `Mitigation: PTI` as below, KPTI is enabled.
```
# cat /sys/devices/system/cpu/vulnerabilities/meltdown
Mitigation: PTI
```
If disabled, it will say `Vulnerable`.

Because KPTI works by switching page tables, user space and kernel space can be switched by manipulating the `CR3` register. In Linux, OR'ing `0x1000` into `CR3` (that is, changing the PDBR) switches from kernel space back to user space. This behavior is implemented in [`swapgs_restore_regs_and_return_to_usermode`](https://github.com/torvalds/linux/blob/master/arch/x86/entry/entry_64.S), but we will cover the details in the chapter where we actually write the exploit.

## KADR (Kernel Address Display Restriction)
Linux lets you read function names and addresses from `/proc/kallsyms`. In addition, some device drivers print debug information using functions such as `printk`, and users can read that output via commands such as `dmesg`.
Linux therefore also has a mechanism to prevent address leaks of kernel functions, data, and heap objects. I do not think it has an official name, but the [reference article](https://inaz2.hatenablog.com/entry/2015/03/27/021422) calls it **KADR** (Kernel Address Display Restriction), so this site uses that term too.

This behavior can be controlled with `/proc/sys/kernel/kptr_restrict`. If `kptr_restrict` is 0, address display is unrestricted. If it is 1, users with the `CAP_SYSLOG` capability can still see addresses. If it is 2, kernel addresses are hidden even from privileged users.
If KADR is disabled, you may not need any address leak at all, which can make exploitation much easier, so it is worth checking first.

[^1]: On x64, the result of operating on a 32-bit register is extended to 64 bits.
[^2]: Only the system-call entry path is shared between user and kernel space.

----

<div class="column" title="Exercise">
  Perform the following steps on the kernel from <a href="../LK01/distfiles/LK01.tar.gz">practice problem LK01</a>. (Start from the state where you already have a root shell from the previous exercise.)<br>
  (1) Read <code>run.sh</code> and check whether KASLR, KPTI, SMAP, and SMEP are enabled.<br>
  (2) Boot the kernel with options that enable both SMAP and SMEP, and verify through <code>/proc/cpuinfo</code> that they are enabled. (After checking, disable them again.)<br>
  (3) In the output of <code>head /proc/kallsyms</code>, the first address shown is the kernel base address. Check what that base address becomes when KASLR is disabled. (Hint: pay attention to KADR.)
</div>
