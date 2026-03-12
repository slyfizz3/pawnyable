---
title: Introduction to Kernel Exploitation
date: 2021-09-22 14:04:55
tags:
    - [Linux]
    - [Kernel]
lang: en
permalink: /en/linux-kernel/introduction/introduction.html
pagination: true
fd: debugging.html
---
Many people think, "I've studied userland pwn to some extent, but the kernel looks difficult so I can't get started." In reality, kernel exploitation can be very easy in some cases.
In this section, we explain the differences between userland exploitation and kernel exploitation, how to set up the environment, and other basics.

## Characteristics of kernel exploitation
First, let's understand what makes vulnerabilities in kernel space different from those in userland.

### Targets
The biggest difference between userland exploitation and kernel exploitation lies in the goal.
In userland exploits discussed so far, the goal was usually to achieve arbitrary command execution. In contrast, kernel exploits are generally written for **privilege escalation**. Assuming the attacker has already gained some form of access to the target machine, they use a kernel exploit to obtain root privileges[^1]. This kind of local privilege escalation is called **LPE** (Local Privilege Escalation).
Of course, userland vulnerabilities can also lead to privilege escalation, but that only happens because the vulnerable program itself runs with elevated privileges. In kernel exploitation, the main targets are the following two:

1. The Linux kernel
2. Kernel modules

Code inside the Linux kernel such as system calls and filesystems runs with root privileges, so bugs in the kernel itself can lead to LPE.
The other target is vulnerabilities inside kernel modules such as device drivers. A device driver provides an interface from user space to external devices such as printers. Device drivers also always run with root privileges[^2], so bugs there can also lead to LPE.

### Exploitation style
In userland exploitation, you normally exploit a service by sending it input. That is why Python and similar languages are commonly used for writing exploits.
In kernel exploitation, however, the target is the OS or a driver. Since those are much lower-level targets, exploits are usually written in C. You could still use Python in theory, but target machines in CTFs or lab environments are often very small Linux systems where Python is not installed, so the exploit may not run at all.

This site also writes exploits in C. We will discuss the details later, but we use a compiler called [musl-gcc](https://www.musl-libc.org/).

### Shared resources
Another feature of kernel exploitation is that resources are shared.
In userland, there is usually one target process, and exploiting that process gives you a shell or some other form of control. In contrast, programs such as the Linux kernel and device drivers are shared by all processes using the OS. Anyone can invoke a system call at any time, and you do not know who will access a device driver or when. In other words, when you write code that runs in kernel space, you must always think in terms of multithreading, otherwise it is very easy to introduce vulnerabilities.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="Wolf" ></div>
  <p class="says">
    So if you use data that can race, such as global variables, you need to take locks.<br>Programming in kernel space really is hard.
  </p>
</div>

### Shared heap region
There is also a major characteristic that the kernel heap is shared by the kernel and all drivers.
In userland exploitation so far, each program had its own heap, so whether a Heap Overflow was exploitable depended on that specific program. In the kernel, however, if a heap overflow occurs once in a device driver, it can corrupt adjacent heap data allocated by a completely different driver or by the Linux kernel itself.

From the attacker's point of view, this has both advantages and disadvantages. The advantage is that even small heap-related bugs can very often lead to LPE. For example, the Linux kernel contains many objects with function pointers, so corrupting one of them can easily give control of RIP. The disadvantage is that because the heap is affected by the whole system, its state is hard to predict. In simple userland programs, the heap state was often deterministic for a given input, which made complex heap exploits such as the so-called House of XXX possible. In the kernel, by contrast, you do not know what data sits behind the chunk where a Heap Overflow occurs, or who will reuse an address after a Use-after-Free.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="Wolf" ></div>
  <p class="says">
    That means heap spraying is important in kernel exploitation.
  </p>
</div>

The vulnerabilities themselves are not very different from those in userland. Stack Overflows and Use-after-Free bugs can also exist in kernel land. Security mechanisms such as Stack Canary can also be placed on a device driver's stack. That said, there are vulnerabilities specific to kernel space, and those will appear in later sections.

## Using QEMU
When writing Linux kernel exploits, the kernel is often run inside an emulator for debugging. Any VM is fine, but QEMU is common, so this site also uses QEMU.

Install `qemu-system` in whatever way matches your environment.
```
# apt install qemu-system
```

## Disk images
When booting a machine with QEMU, you need a disk image that will be mounted as the root directory in addition to the Linux kernel.
Disk images are generally distributed either as raw filesystem images such as ext filesystems or as an archive format called `cpio`.
If you have a filesystem image, you can mount it with the `mount` command and edit its contents.
```
# mkdir root
# mount rootfs.img root
```

In the exercises on this site, we use the `cpio` format because it is common in CTFs and lightweight.
Use the `cpio` command to extract files like this.
```
# mkdir root
# cd root; cpio -idv < ../rootfs.cpio
```
After adding or editing files, pack them back into a `cpio` archive like this.
```
# find . -print0 | cpio -o --format=newc --null > ../rootfs_updated.cpio
```
Sometimes the `cpio` archive is further compressed with `gz`, in which case you should decompress and recompress it as needed.

Also note that `cpio` stores ownership and permission information. When editing the filesystem, you therefore need to ensure that files are owned by `root`. In the commands above everything is run as root, so there is no issue, but if that is inconvenient you may also repack with the `--owner=root` option.
```
$ mkdir root
$ cd root; cpio -idv < ../rootfs.cpio
...
$ find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs_updated.cpio
```

[^1]: Extremely advanced attacks also exist where the kernel is exploited remotely from outside the machine, for example by abusing flaws in protocol stack implementations such as SMBGhost.
[^2]: Filesystems and character devices are usually implemented as kernel modules, but features such as [FUSE](https://lwn.net/Articles/796674/) and [CUSE](https://lwn.net/Articles/308445/) made it possible to implement them from user space as well.

----

<div class="column" title="Exercise">
  Download the files for <a href="../LK01/distfiles/LK01.tar.gz">practice problem LK01</a> and perform the following steps.<br>
  (1) Run <code>run.sh</code> and confirm that Linux boots successfully.<br>
  (2) Edit <code>rootfs.cpio</code> so that the shell starts with root privileges at boot. (Hint: look for the script that prints the boot-time messages.)
</div>
