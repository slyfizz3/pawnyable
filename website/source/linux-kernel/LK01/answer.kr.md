---
title: "Holstein v1: 예제 해설"
tags:
    - [Linux]
    - [Kernel]
lang: kr
permalink: /kr/linux-kernel/LK01/answer.html
pagination: true
bk: stack_overflow.html
---
### SMEP 비활성화?
여기까지 해서 kROP로 권한 상승이 가능하다는 것은 확인했지만, 사실 다른 방법도 생각해 볼 수 있습니다.
[보안 기법](../introduction/security#smep-supervisor-mode-execution-prevention) 절에서 설명했듯이, SMEP은 `CR4` 레지스터로 제어됩니다. 따라서 ROP로 `CR4`의 21번째 비트를 뒤집을 수 있다면 SMEP이 꺼지고 `ret2usr`를 사용할 수 있을 것입니다.

문제는 그런 ROP gadget이 실제로 존재하느냐입니다.
`CR4`에 즉시값 연산을 직접 할 수는 없기 때문에, 다른 범용 레지스터를 거쳐 조작해야 합니다. `CR4`를 다루는 코드는 커널 내부에 존재하므로 그런 gadget 자체는 반드시 있지만, 부작용 없이 `ret`으로 끝나는 usable한 형태가 있는지는 `objdump` 등으로 직접 찾아봐야 합니다. (많은 도구는 CR 레지스터 조작을 제대로 찾아주지 못하고, 이런 코드 뒤에는 `jmp`가 이어지는 경우도 많습니다.)
예를 들어 `CR4`를 설정하는 gadget으로는 다음 같은 것들이 있습니다.
```
ffffffff810284d5:       0f 22 e7                mov    cr4,rdi
ffffffff810284d8:       8b 05 4a 2f d4 00       mov    eax,DWORD PTR [rip+0xd42f4a]        # 0xffffffff81d6b428
ffffffff810284de:       85 c0                   test   eax,eax
ffffffff810284e0:       7e ea                   jle    0xffffffff810284cc
...
ffffffff810284cc:       c3                      ret
```

```
ffffffff81028535:       8b 05 ed 2e d4 00       mov    eax,DWORD PTR [rip+0xd42eed]        # 0xffffffff81d6b428
ffffffff8102853b:       85 c0                   test   eax,eax
ffffffff8102853d:       7f a5                   jg     0xffffffff810284e4
ffffffff8102853f:       c3                      ret
```
곧바로 `ret`으로 끝나는 깔끔한 gadget은 보이지 않으므로, 이 코드들이 어떤 함수에서 왔는지 확인해 봅시다. `kallsyms`에서 가까운 주소의 함수를 찾으면 됩니다.
```
/ # cat /proc/kallsyms | grep ffffffff810285
ffffffff81028540 T native_write_cr4
ffffffff810285b0 T cr4_init
/ # cat /proc/kallsyms | grep ffffffff810284
ffffffff81028440 t default_init
ffffffff810284b0 T cr4_update_irqsoff
```
각각 [`cr4_init`](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/kernel/cpu/common.c#L420), [`cr4_update_irqsoff`](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/kernel/cpu/common.c#L399)라는 함수에서 온 코드입니다.
특히 `cr4_update_irqsoff`는 사용 가능해 보입니다.
```c
void cr4_update_irqsoff(unsigned long set, unsigned long clear)
{
	unsigned long newval, cr4 = this_cpu_read(cpu_tlbstate.cr4);

	lockdep_assert_irqs_disabled();

	newval = (cr4 & ~clear) | set;
	if (newval != cr4) {
		this_cpu_write(cpu_tlbstate.cr4, newval);
		__write_cr4(newval);
	}
}
EXPORT_SYMBOL(cr4_update_irqsoff);
```
이 함수는 인자로 `CR4`에서 1로 만들 비트와 0으로 만들 비트를 지정할 수 있습니다.
그래서 다음과 같은 ROP chain을 시도해 볼 수 있습니다.
```c
  *chain++ = rop_pop_rdi;
  *chain++ = 0; // set할 비트
  *chain++ = rop_pop_rsi;
  *chain++ = 1 << 20; // clear할 비트
  *chain++ = cr4_update_irqsoff;
  *chain++ = (unsigned long)&escalate_privilege;
```
하지만 이것을 실행해도 `escalate_privilege`에 도달했을 때 여전히 SMEP로 크래시가 발생합니다. 직전에 `CR4` 값을 확인해 보면 SMEP 비트가 그대로 켜져 있습니다. 왜 `CR4`가 갱신되지 않는지 step 실행으로 확인해 봅시다.

<center>
  <img src="img/update_cr4.png" alt="cr4_update_irqoff의 CR4 갱신 부분" style="width:640px;">
</center>

이 기계어는 `cr4_update_irqsoff`의 다음 부분에 해당합니다.
```
if (newval != cr4) {
```
보면 알 수 있듯이 이 시점에서는 실제 `CR4` 레지스터 값을 아직 읽거나 쓰지 않았습니다. 계속 step 실행을 진행하면, 다음과 같은 경로로 들어갑니다.

<center>
  <img src="img/pinned_cr4.png" alt="고정된 CR4 비트 변경 감지 처리" style="width:640px;">
</center>

이때 `RDI` 레지스터에는 다음 문자열의 포인터가 들어 있습니다.

<center>
  <img src="img/pinned_cr4_message.png" alt="pinned CR4 bits changed" style="width:480px;">
</center>

이 메시지로 커널 코드를 검색하면, [`native_write_cr4`](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/kernel/cpu/common.c#L377)에 다음과 같은 처리가 있습니다.
```c
	if (static_branch_likely(&cr_pinning)) {
		if (unlikely((val & cr4_pinned_mask) != cr4_pinned_bits)) {
			bits_changed = (val & cr4_pinned_mask) ^ cr4_pinned_bits;
			val = (val & ~cr4_pinned_mask) | cr4_pinned_bits;
			goto set_register;
		}
		/* Warn after we've corrected the changed bits. */
		WARN_ONCE(bits_changed, "pinned CR4 bits changed: 0x%lx!?\n",
			  bits_changed);
	}
```
`cr_pinning`이라는 전역 변수가 있습니다. 즉 커널에는 `CR4`의 특정 비트를 바꾸지 못하도록 하는 작은 보안 기법이 들어 있습니다.
`cr4_pinned_bits`는 상수라 바꿀 수 없고, `cr_pinning`에 사용되는 데이터 역시 읽기 전용 영역에 있으므로 변경할 수 없습니다. 기계어로는 다음 부분에 해당합니다.

<center>
  <img src="img/cr_pinning.png" alt="cr_pinning 확인" style="width:480px;">
</center>

즉 `native_write_cr4`를 이용하는 경우에는 이런 체크가 들어가기 때문에, SMEP이나 SMAP을 동적으로 비활성화할 수 없다는 것을 알 수 있습니다. ROP가 가능한 상황이라면 `CR4`를 바꾸기보다 `commit_creds`를 사용하는 편이 더 쉽습니다.
물론 SMEP을 비활성화하는 기법 자체는 Windows 7 Kernel Exploit 같은 곳에서 등장합니다.

결국 예제의 답은 "`native_write_cr4`를 거치지 않고 `CR4`에 0x1000을 OR할 수 있는 ROP gadget이 존재한다면 가능하다"입니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/cow.jpg" alt="소" ></div>
  <p class="says">
    CR4에 0x1000을 OR해 주는 gadget은 보통 없지만, 사실 Linux Kernel의 BPF 기능을 악용하면 임의 gadget을 만들 수 있어.
  </p>
</div>
