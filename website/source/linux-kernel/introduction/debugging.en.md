---
title: Debugging the Kernel with gdb
date: 2021-09-22 13:59:43
tags:
    - [Linux]
    - [Kernel]
lang: en
permalink: /en/linux-kernel/introduction/debugging.html
pagination: true
bk: introduction.html
fd: security.html
---
One major reason kernel exploitation feels hard to get into is that people do not know how to debug it.
In this section, we learn how to use `gdb` to debug a Linux kernel running under QEMU.

First, download the files for [practice problem LK01](../LK01/distfiles/LK01.tar.gz).

## Getting a root shell
When debugging kernel exploits locally, running as an ordinary user is often inconvenient. In particular, if you want to place breakpoints inside the kernel or a kernel driver, or check what function an address leak points to, you need root privileges to access kernel address information.
So when debugging a kernel exploit, first obtain root privileges. The contents of this section are the same as exercise (2) from the previous chapter, so if you already solved it, you can skim this as a review.

When the kernel boots, it starts by executing one program. Depending on the setup, the path varies, but in many cases it is `/init` or `/sbin/init`. If you extract `rootfs.cpio` from LK01, you will find `/init`.
```sh
#!/bin/sh
# devtmpfs does not get automounted for initramfs
/bin/mount -t devtmpfs devtmpfs /dev

# use the /dev/console device node from devtmpfs if possible to not
# confuse glibc's ttyname_r().
# This may fail (E.G. booted with console=), and errors from exec will
# terminate the shell, so use a subshell for the test
if (exec 0</dev/console) 2>/dev/null; then
    exec 0</dev/console
    exec 1>/dev/console
    exec 2>/dev/console
fi

exec /sbin/init "$@"
```
There is nothing especially important in this file, but it does execute `/sbin/init`.
In the small environments often distributed in CTFs, `/init` itself sometimes directly installs the driver or launches a shell. In fact, if you insert `/bin/sh` before the last `exec` line, the kernel will boot straight into a root shell. However, other required initialization such as loading the driver would then be skipped, so we will not modify this file here.

Eventually, `/sbin/init` runs a shell script called `/etc/init.d/rcS`. That script runs files inside `/etc/init.d` whose names begin with `S`. In this case there is a script named `S99pawnyable`. It contains various initialization steps, but pay attention to the following line near the end.
```bash
setsid cttyhack setuidgid 1337 sh
```
This line is what launches the shell as an unprivileged user when the kernel boots. `cttyhack` makes terminal input such as Ctrl+C work properly. Then `setuidgid` sets the user ID and group ID to 1337 before launching `/bin/sh`. Change that number to 0, which is the root user.
```bash
setsid cttyhack setuidgid 0 sh
```
Also, as explained in detail in the [next chapter](security.html), comment out the following line as well in order to disable a security mechanism.
```diff
-echo 2 > /proc/sys/kernel/kptr_restrict    # before
+#echo 2 > /proc/sys/kernel/kptr_restrict   # after
```
After making the change, repack the `cpio` archive and run `run.sh`. You should then be able to use a root shell like in the screenshot below. (For the packing method, see the [previous chapter](introduction.html#disk-images).)

<center>
  <img src="img/rooted.png" alt="Launching a root shell" style="width:340px;">
</center>

## Attaching to QEMU
QEMU includes support for debugging with `gdb`. If you pass the `-gdb` option to QEMU, you can have it listen on a chosen protocol, host, and port. For example, if you edit `run.sh` and add the following option, `gdb` will be able to connect over TCP port 12345 on localhost.
```
-gdb tcp::12345
```
In the exercises below we use port 12345 without further notice, but you can use any port you like.

To attach from `gdb`, use the `target` command.
```
pwndbg> target remote localhost:12345
```
If the connection succeeds, you are done. From there you can use normal `gdb` commands to read and write registers and memory, set breakpoints, and so on. Memory addresses are interpreted as the virtual addresses in the context where that breakpoint is set. That means you can set breakpoints directly at the familiar addresses used by a kernel driver or by a user-space program.

The target here is x86-64. If your `gdb` does not automatically recognize the architecture, you can set it explicitly as follows. (Usually it is detected automatically.)
```
pwndbg> set arch i386:x86-64:intel
```

## Debugging the kernel
Through the procfs file `/proc/kallsyms`, you can view the list of addresses and symbols defined inside the Linux kernel. As explained in the [KADR section of the next chapter](security.html#kadr-kernel-address-display-restriction), security features may hide kernel addresses even from root.
We already did this in the [root shell section](#getting-a-root-shell), but do not forget to comment out the following line in the init script. Otherwise kernel pointers will not be visible.
```bash
echo 2 > /proc/sys/kernel/kptr_restrict     # before
#echo 2 > /proc/sys/kernel/kptr_restrict    # after
```
Now let's actually look at `kallsyms`. Since it is huge, use `head` or a similar command to inspect only the first few lines.

<center>
  <img src="img/kallsyms_head.png" alt="Beginning of /proc/kallsyms" style="width:480px;">
</center>

The output is arranged as symbol address, section, and symbol name. For example, `T` means the text section and `D` means the data section; uppercase letters indicate globally exported symbols. See `man nm` for the detailed meaning of those letters.
In the screenshot above, you can see that `0xffffffff81000000` is the address of the symbol `_stext`. This corresponds to the kernel base address.

Next, search for the address of the function named `commit_creds` using `grep`. You should find `0xffffffff8106e390`. Set a breakpoint there in `gdb` and continue execution.
```
pwndbg> break *0xffffffff8106e390
pwndbg> conti
```
This function is called when, for example, a new process is created. If you run something like `ls` in the shell, `gdb` should stop at the breakpoint.

<center>
  <img src="img/commit_creds_bp.png" alt="Stopping at commit_creds with a breakpoint" style="width:720px;">
</center>

The first argument in `RDI` is a pointer into kernel space. Let's inspect the memory it points to.

<center>
  <img src="img/commit_creds_rdi.png" alt="Inspecting memory at commit_creds" style="width:620px;">
</center>

As you can see, the same kinds of `gdb` commands available in user space can also be used in kernel space. Extensions such as `pwndbg` may also work, but of course features not written for kernel debugging may not behave properly.
There are also debuggers with [kernel-aware features](https://github.com/bata24/gef), so feel free to use whichever debugger you prefer.

## Debugging drivers
Next, let's debug a kernel module.
LK01 loads a kernel module named `vuln`. You can check the list of loaded modules and their base addresses in `/proc/modules`.

<center>
  <img src="img/modules.png" alt="Contents of /proc/modules" style="width:420px;">
</center>

From this you can see that the module `vuln` is loaded at `0xffffffffc0000000`. The source code and binary for this module are in the `src` directory of the distributed files. We will analyze the source in detail in a later chapter, but for now let's place a breakpoint inside one of its functions.
If you open `src/vuln.ko` in IDA or a similar tool, several functions are visible. For example, `module_close` has a relative address of `0x20f`.

<center>
  <img src="img/module_close.png" alt="module_close seen in IDA" style="width:360px;">
</center>

Therefore the start of that function should currently exist at `0xffffffffc0000000 + 0x20f` in kernel memory. Let's set a breakpoint there.

<center>
  <img src="img/module_close_bp.png" alt="Setting a breakpoint on module_close in gdb" style="width:520px;">
</center>

We will analyze the details in the next chapter, but this module is mapped to the file `/dev/holstein`. If you use the `cat` command, `module_close` will be called. Confirm that the breakpoint is hit.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="Wolf" ></div>
  <p class="says">
    If you want symbol information for the driver, use the <code>add-symbol-file</code> command. Pass your local driver file as the first argument and the base address as the second argument. Then you can set breakpoints using function names.
  </p>
</div>

```
# cat /dev/holstein
```

Commands such as `stepi` and `nexti` also work. In other words, debugging in kernel space differs only in how you attach; the available commands and general debugging workflow are basically the same as in user space.

----

<div class="column" title="Exercise">
  In this chapter, we stopped at <code>commit_creds</code> and inspected the memory pointed to by the RDI register. Now try doing the same thing from a shell running with ordinary user privileges (for example when cttyhack sets the uid to 1337).<br>Also compare the root case (uid=0) and the ordinary user case (uid=1337 etc.), and check what differences appear in the data passed as the first argument to <code>commit_creds</code>.
</div>
