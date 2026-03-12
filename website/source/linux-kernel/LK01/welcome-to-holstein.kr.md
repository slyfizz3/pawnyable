---
title: Holstein 모듈 분석과 취약점 발화
tags:
    - [Linux]
    - [Kernel]
    - [Stack Overflow]
lang: kr
permalink: /kr/linux-kernel/LK01/welcome-to-holstein.html
pagination: true
bk: ../introduction/compile-and-transfer.html
fd: stack_overflow.html
---
LK01(Holstein) 장에서는 커널 exploit의 가장 기본적인 공격 기법을 다룹니다. 아직 LK01을 다운로드하지 않았다면 먼저 [LK01 연습 파일](distfiles/LK01.tar.gz)을 받으세요.

`qemu/rootfs.cpio`가 파일시스템 이미지입니다. 보통 `mount` 디렉터리를 하나 만든 뒤 그 안에 cpio를 풀어서 확인합니다. 이 작업은 root 권한으로 하는 편이 편합니다.

## 초기화 처리 확인
`/init`이라는 파일이 있는데, 커널이 부팅된 뒤 사용자 공간에서 가장 먼저 실행되는 프로그램입니다. CTF 커널에서는 여기에 취약한 드라이버를 로드하는 코드가 들어 있는 경우가 많으므로 항상 확인해야 합니다.

이번 환경에서는 `/init`은 buildroot 기본 스크립트이고, 실제 드라이버 설정은 `/etc/init.d/S99pawnyable`에 있습니다.
```sh
#!/bin/sh

##
## Setup
##
mdev -s
mount -t proc none /proc
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
stty -opost
echo 2 > /proc/sys/kernel/kptr_restrict
#echo 1 > /proc/sys/kernel/dmesg_restrict

##
## Install driver
##
insmod /root/vuln.ko
mknod -m 666 /dev/holstein c `grep holstein /proc/devices | awk '{print $1;}'` 0

##
## User shell
##
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
echo "[ Holstein v1 (LK01) - Pawnyable ]"
setsid cttyhack setuidgid 1337 sh

##
## Cleanup
##
umount /proc
poweroff -d 0 -f
```

여기서 몇 줄은 특히 중요합니다.

먼저:
```sh
echo 2 > /proc/sys/kernel/kptr_restrict
```
이것은 커널 주소 출력 제한을 제어합니다. 앞에서 본 것처럼 KASLR 관련 주소 정보 노출에 영향을 주므로, 디버깅할 때는 불편할 수 있습니다.

다음은 주석 처리된 이 줄입니다.
```sh
#echo 1 > /proc/sys/kernel/dmesg_restrict
```
실전 CTF 문제에서는 이것이 켜져 있는 경우가 많습니다. 일반 사용자에게 `dmesg` 출력을 허용할지 결정하는 옵션입니다. 이번 실습 환경에서는 연습을 위해 막지 않았습니다.

그 다음 드라이버 로드는 다음 두 줄에서 이루어집니다.
```sh
insmod /root/vuln.ko
mknod -m 666 /dev/holstein c `grep holstein /proc/devices | awk '{print $1;}'` 0
```
`insmod`가 `/root/vuln.ko`를 로드하고, `mknod`가 `holstein` 드라이버에 연결된 `/dev/holstein` 문자 장치를 만듭니다.

마지막으로:
```sh
setsid cttyhack setuidgid 1337 sh
```
이 명령은 UID 1337으로 `sh`를 실행합니다. 로그인 프롬프트 없이 바로 셸이 뜨는 이유가 이것입니다.

디버깅할 때는 이 UID를 `0`으로 바꿔 root 셸을 받는 편이 더 편합니다.

또한 `/etc/init.d`에는 `S01syslogd`, `S41dhcpcd` 같은 다른 초기화 스크립트들도 있습니다. 로컬 디버깅에서는 필요 없는 경우가 많으니 잠시 치워 두면 부팅 속도를 더 줄일 수 있습니다.

## Holstein 모듈 분석
취약한 커널 모듈 소스는 `src/vuln.c`에 있습니다. 위에서부터 차례대로 읽어 봅시다.

### 초기화와 종료
모든 커널 모듈은 초기화 코드와 종료 코드를 가집니다.
```c
module_init(module_initialize);
module_exit(module_cleanup);
```
이 줄들이 시작 함수와 종료 함수를 등록합니다. 먼저 `module_initialize`를 보겠습니다.
```c
static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
    printk(KERN_WARNING "Failed to register device\n");
    return -EBUSY;
  }

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    printk(KERN_WARNING "Failed to add cdev\n");
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}
```
사용자 공간에서 모듈을 다루게 하려면 커널이 인터페이스를 노출해야 합니다. 여기서는 `cdev_add`를 사용하므로 문자 장치 인터페이스를 만드는 구조입니다.

이 시점에는 아직 `/dev` 아래에 파일이 자동으로 생기지 않습니다. 앞에서 본 것처럼 실제 `/dev/holstein` 파일은 나중에 `mknod`로 만들어집니다.

핵심은 다음 줄입니다.
```c
cdev_init(&c_dev, &module_fops);
```
두 번째 인자인 `module_fops`는 함수 테이블입니다.
```c
static struct file_operations module_fops =
  {
   .owner   = THIS_MODULE,
   .read    = module_read,
   .write   = module_write,
   .open    = module_open,
   .release = module_close,
  };
```
즉 `/dev/holstein`에 대해 `read`, `write`, `open` 같은 동작이 일어났을 때 어떤 함수가 호출될지를 결정합니다.

정리 코드는 단순합니다.
```c
static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}
```

### `open`
이제 `module_open`을 봅시다.
```c
static int module_open(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_open called\n");

  g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }

  return 0;
}
```
`printk`는 커널 로그 버퍼에 문자열을 출력하는 함수입니다. 출력은 `dmesg`로 확인할 수 있습니다.

중요한 부분은 `kmalloc`입니다. 이는 커널 공간의 `malloc` 같은 함수로, `BUFFER_SIZE` 바이트를 커널 힙에서 할당하고 그 주소를 전역 변수 `g_buf`에 저장합니다.

즉 장치를 `open`하면 `0x400`바이트 커널 힙 버퍼가 하나 생깁니다.

### `close`
다음은 `module_close`입니다.
```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}
```
`kfree`는 `kmalloc`과 짝이 되는 해제 함수입니다.

즉 `open`에서 확보했던 버퍼를 `close`에서 해제하는, 언뜻 보면 매우 자연스러운 구조입니다.

사실 여기에도 나중에 권한 상승으로 이어지는 문제가 하나 숨어 있지만, 그 부분은 뒤 장에서 다루겠습니다.

### `read`
`module_read`는 사용자 공간에서 `read`를 호출할 때 실행됩니다.
```c
static ssize_t module_read(struct file *file,
                        char __user *buf, size_t count,
                        loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_read called\n");

  memcpy(kbuf, g_buf, BUFFER_SIZE);
  if (_copy_to_user(buf, kbuf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}
```
먼저 `g_buf`에서 `kbuf`라는 스택 버퍼로 `BUFFER_SIZE` 바이트를 복사하고, 다시 그중 `count`바이트를 사용자 공간으로 돌려줍니다.

여기서는 `copy_to_user`가 아니라 `_copy_to_user`를 사용합니다. 이 버전은 더 낮은 수준의 helper라 일부 스택 관련 안전 검사 없이 동작합니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="늑대" ></div>
  <p class="says">
    `copy_to_user`나 `copy_from_user`는 보통 inline helper로 정의되어 있고, 가능하면 크기 검사를 추가로 수행해 줘.
  </p>
</div>

즉 `read` 경로는 힙 버퍼를 한 번 스택으로 가져온 뒤 그 일부를 사용자 공간으로 반환하는 구조입니다.

### `write`
마지막으로 `module_write`입니다.
```c
static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_write called\n");

  if (_copy_from_user(kbuf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }
  memcpy(g_buf, kbuf, BUFFER_SIZE);

  return count;
}
```
먼저 사용자 입력이 `_copy_from_user`를 통해 스택 버퍼 `kbuf`로 복사되고, 그다음 `BUFFER_SIZE` 전체가 `g_buf`로 복사됩니다.

## 스택 오버플로 취약점
이 시점에서 최소한 한 개 이상의 취약점은 이미 보였을 것입니다. 이 장에서는 `module_write`에 있는 스택 오버플로를 다룹니다.
```c
static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_write called\n");

  if (_copy_from_user(kbuf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }
  memcpy(g_buf, kbuf, BUFFER_SIZE);

  return count;
}
```
문제는 분명합니다. `count`는 사용자 공간이 결정하지만 `kbuf`는 `0x400`바이트 고정 크기입니다. 따라서 `count`가 더 크면 `_copy_from_user`가 커널 스택 버퍼를 넘쳐서 덮어쓰게 됩니다.

커널 함수 호출도 기본적으로 사용자 공간과 같은 호출 규약 개념을 따르므로, 리턴 주소를 덮을 수 있다면 ROP chain도 만들 수 있습니다.

## 취약점 발화
본격적으로 exploit하기 전에 먼저 장치를 정상적으로 사용하는 테스트 프로그램을 하나 작성해 인터페이스가 제대로 동작하는지 확인하는 편이 좋습니다. 그다음 write 크기를 점점 늘려 버그를 실제로 터뜨리고, 그 크래시를 gdb에서 관찰하면 됩니다.

그 크래시가 다음 장에서 실제 exploit를 만들기 위한 출발점이 됩니다.
