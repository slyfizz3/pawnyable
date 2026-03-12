---
title: Compiling and Transferring the Exploit
date: 2021-10-27 21:31:39
tags:
    - [Linux]
    - [Kernel]
lang: en
permalink: /en/linux-kernel/introduction/compile-and-transfer.html
pagination: true
bk: security.html
fd: ../LK01/welcome-to-holstein.html
---
By now you have learned everything needed to start kernel exploitation: how to boot the kernel, how to debug it, and what security mechanisms matter. From here on, we move to actually writing exploits and to how to run the exploit you wrote inside QEMU.

## Running on QEMU
If you write, build, and run your exploit directly inside QEMU, every kernel crash forces you to start over, which is painful. It is much more practical to build the exploit locally and then send it into the guest.
Since typing the full workflow every time is tedious, prepare a template shell script. For example, make a `transfer.sh` like the following:
```bash
#!/bin/sh
gcc exploit.c -o exploit
mv exploit root
cd root; find . -print0 | cpio -o --null --format=newc > ../debugfs.cpio
cd ../

qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 nopti nokaslr" \
    -no-reboot \
    -cpu qemu64 \
    -gdb tcp::12345 \
    -smp 1 \
    -monitor /dev/null \
    -initrd debugfs.cpio \
    -net nic,model=virtio \
    -net user
```
There is not much to explain here. It simply compiles `exploit.c`, adds it to the `cpio`, and boots QEMU. To avoid damaging the original `rootfs.cpio`, this script uses a disk image named `debugfs.cpio`, but you can change that if you prefer.
Also note that when creating the `cpio`, file permissions will differ unless you run as root, so be careful to execute `transfer.sh` with root privileges.

Now put the following code into `exploit.c` and run `transfer.sh`.
```c
#include <stdio.h>

int main() {
  puts("Hello, World!");
  return 0;
}
```
If you do so, you will see an error like the following. Why does this happen?

<center>
  <img src="img/gcc_error.png" alt="A GCC-compiled exploit does not run" style="width:320px;">
</center>

The reason is that the distributed image uses a compact C library called `uClibc` instead of the usual `libc`. Your local GCC environment links against a different `libc`, so dynamic linking fails and the exploit does not run.
Therefore, when running an exploit on QEMU, make sure to link it statically.
```bash
gcc exploit.c -o exploit -static
```
If you rebuild and run with that change, the program should work.

<center>
  <img src="img/static_works.png" alt="The exploit works when statically linked" style="width:320px;">
</center>

## Running on remote targets: using musl-gcc
At this point, we can successfully run our exploit on QEMU. The distributed environment used here has networking enabled, so if you want to execute the exploit remotely, you can transfer it from inside QEMU using commands such as `wget`.
However, some small environments used in CTFs do not have networking. In that case, you need to transfer a binary from the outside using commands available in busybox. A common method is to use `base64`, but binaries built with GCC are often hundreds of KB or even tens of MB, so the transfer takes a very long time. The size is large because functions from external libraries such as `libc` are being statically linked.
If you want to keep the GCC binary small, you have to avoid libc entirely and define things like `read` and `write` yourself using syscalls and inline assembly. Of course, that is very inconvenient.
For that reason, many CTF players use a C compiler called `musl-gcc` when writing kernel exploits. Download, build, and install it from the following site.

https://www.musl-libc.org/

After installation, change the compilation line in `transfer.sh` as follows. Replace the path with wherever you installed `musl-gcc`.
```bash
/usr/local/musl/bin/musl-gcc exploit.c -o exploit -static
```
On the author's machine, the Hello, World program above was 851 KB when built with `gcc`, but only 18 KB when built with `musl-gcc`. If you want it even smaller, you can also strip debug symbols.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="Wolf" ></div>
  <p class="says">
    Some header files, especially Linux-kernel-related ones, may not be available in musl-gcc. In such cases you need to add include paths or fall back to gcc. If you want to keep the output small while still using gcc features, one trick is to compile via assembly once.<br>
    <code>
    $ gcc -S sample.c -o sample.S<br>
    $ musl-gcc sample.S -o sample.elf
    </code>
  </p>
</div>

Once that is done, write a script that transfers the binary to the remote machine over `nc` using `base64`. In CTFs, you will use this uploader all the time, so it is worth having your own template ready.
```python
from ptrlib import *
import time
import base64
import os

def run(cmd):
    sock.sendlineafter("$ ", cmd)
    sock.recvline()

with open("./root/exploit", "rb") as f:
    payload = bytes2str(base64.b64encode(f.read()))

#sock = Socket("HOST", PORT) # remote
sock = Process("./run.sh")

run('cd /tmp')

logger.info("Uploading...")
for i in range(0, len(payload), 512):
    print(f"Uploading... {i:x} / {len(payload):x}")
    run('echo "{}" >> b64exp'.format(payload[i:i+512]))
run('base64 -d b64exp > exploit')
run('rm b64exp')
run('chmod +x exploit')

sock.interactive()
```
After running it for a while, the upload should finish as shown below.

<center>
  <img src="img/upload_script.png" alt="Result of running upload.py" style="width:520px;">
</center>

On this site you are mainly testing locally, so uploading is not required, but when you use the same workflow in CTFs, this is a good pattern to remember.
