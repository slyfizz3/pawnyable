---
title: 보안 기법
date: 2021-09-22 17:01:30
tags:
    - [Linux]
    - [Kernel]
    - [SMAP]
    - [SMEP]
    - [KASLR]
    - [FGKASLR]
    - [KPTI]
    - [KAISER]
lang: kr
permalink: /kr/linux-kernel/introduction/security.html
pagination: true
bk: debugging.html
fd: compile-and-transfer.html
---
커널 익스플로잇에 대한 완화책으로 Linux 커널에는 여러 가지 보안 기법이 존재합니다. 유저랜드에서 등장한 NX처럼 하드웨어 수준의 보안 기능도 있기 때문에, 여기서 나오는 지식 중 일부는 Windows 커널 익스플로잇에도 그대로 적용할 수 있습니다.

이 절에서는 커널 특유의 보호 기법을 다룹니다. Stack Canary 같은 보안 기법은 디바이스 드라이버에도 존재하지만, 여기서 특별히 짚을 만한 차이는 없으므로 설명하지 않습니다.

커널 부팅 파라미터는 [공식 문서](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/kernel-parameters.txt)가 참고하기 좋습니다.

## SMEP (Supervisor Mode Execution Prevention)
커널 보안 기법 중 대표적인 것이 SMEP와 SMAP입니다.
**SMEP**은 커널 공간의 코드를 실행하는 도중 갑자기 사용자 공간의 코드를 실행하는 것을 막는 보안 기법입니다. 개념적으로는 NX와 비슷합니다.

SMEP은 완화 기법이지, 그것만으로 충분한 강력한 방어책은 아닙니다. 예를 들어 커널 취약점을 이용해 공격자가 RIP를 장악했다고 가정합시다. SMEP이 비활성화되어 있다면, 다음처럼 사용자 공간에 준비해 둔 셸코드를 실행할 수 있습니다.
```c
char *shellcode = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXECUTE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
memcpy(shellcode, SHELLCODE, sizeof(SHELLCODE));

control_rip(shellcode); // RIP = shellcode
```
하지만 SMEP이 활성화되어 있다면 위처럼 사용자 공간에 놓인 셸코드를 실행하려는 순간 커널 패닉이 발생합니다. 따라서 공격자가 RIP를 탈취하더라도, 그것을 바로 권한 상승으로 연결하기가 훨씬 어려워집니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_thinking.png" alt="늑대" ></div>
  <p class="says">
    그렇다면 커널 셸코드에서는 무엇을 실행해야 할까?<br>
    권한 상승 방법은 다른 장에서 다시 공부하자.
  </p>
</div>

SMEP은 qemu 실행 인자로 활성화할 수 있습니다. 다음처럼 `-cpu` 옵션에 `+smep`이 붙어 있으면 SMEP이 켜집니다.
```
-cpu kvm64,+smep
```
머신 내부에서는 `/proc/cpuinfo`를 확인해서도 알 수 있습니다.
```
$ cat /proc/cpuinfo | grep smep
```

SMEP은 하드웨어 보안 기능입니다. `CR4` 레지스터의 21번째 비트를 세우면 SMEP이 활성화됩니다.

## SMAP (Supervisor Mode Access Prevention)
사용자 공간에서 커널 메모리를 읽고 쓸 수 없다는 것은 보안상 당연하지만, 사실 커널 공간에서도 사용자 공간 메모리를 직접 읽고 쓰지 못하게 하는 **SMAP**(Supervisor Mode Access Prevention)이라는 보안 기능이 존재합니다. 커널 공간에서 사용자 공간 데이터를 읽거나 쓰려면 [`copy_from_user`](https://www.kernel.org/doc/htmldocs/kernel-api/API---copy-from-user.html), [`copy_to_user`](https://www.kernel.org/doc/htmldocs/kernel-api/API---copy-to-user.html) 같은 함수를 사용해야 합니다.
그런데 왜 더 높은 권한을 가진 커널이 더 낮은 권한의 사용자 공간 데이터를 직접 읽고 쓰지 못하게 막는 걸까요?

정확한 역사적 배경은 모르지만, SMAP의 이점은 주로 두 가지로 생각할 수 있습니다.

첫 번째는 stack pivot 방지입니다.
SMEP 예시에서는 RIP를 제어할 수 있어도 셸코드를 실행할 수 없었습니다. 하지만 Linux 커널에는 엄청난 양의 기계어 코드가 있기 때문에, 다음과 같은 ROP gadget은 반드시 존재합니다.
```
mov esp, 0x12345678; ret;
```
`ESP`에 어떤 값이 들어가든, 이 gadget이 실행되면 `RSP`는 그 값으로 바뀝니다[^1]. 한편 이런 낮은 주소는 사용자 공간에서 `mmap`으로 확보할 수 있기 때문에, SMEP이 활성화되어 있어도 공격자는 RIP만 장악하면 다음처럼 ROP chain을 실행할 수 있습니다.
```c
void *p = mmap(0x12340000, 0x10000, ...);
unsigned long *chain = (unsigned long*)(p + 0x5678);
*chain++ = rop_pop_rdi;
*chain++ = 0;
*chain++ = ...;
...

control_rip(rop_mov_esp_12345678h);
```
SMAP이 활성화되어 있다면 사용자 공간에 `mmap`한 데이터, 즉 ROP chain을 커널 공간에서 읽을 수 없으므로, stack pivot 뒤의 `ret` 명령에서 커널 패닉이 발생합니다.
이처럼 SMAP은 SMEP에 더해 ROP 기반 공격도 완화해 줍니다.

SMAP의 두 번째 이점은 커널 프로그래밍에서 발생하기 쉬운 버그를 막아 준다는 점입니다.
이것은 디바이스 드라이버 개발자 등이 실수로 작성하기 쉬운 커널 특유의 버그와 관련이 있습니다. 예를 들어 드라이버가 다음과 같은 코드를 가지고 있다고 합시다. (지금은 함수 정의의 의미를 정확히 몰라도 괜찮습니다.)
```c
char buffer[0x10];

static long mydevice_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  if (cmd == 0xdead) {
    memcpy(buffer, arg, 0x10);
  } else if (cmd == 0xcafe) {
    memcpy(arg, buffer, 0x10);
  }
  return 
}
```
`memcpy`를 이용해 `buffer`라는 전역 변수에 데이터를 읽고 쓰고 있다는 정도로 이해하면 됩니다.

이 모듈은 사용자 공간에서 다음처럼 사용하면 0x10바이트의 데이터를 저장해 줍니다.
```c
int fd = open("/dev/mydevice", O_RDWR);

char src[0x10] = "Hello, World!";
char dst[0x10];

ioctl(fd, 0xdead, src);
ioctl(fd, 0xcafe, dst);

printf("%s\n", dst); // --> Hello, World!
```
유저 공간 프로그래밍에 익숙하다면 별문제 없어 보입니다. `memcpy` 크기도 고정이고, 겉보기에는 안전해 보입니다.

하지만 SMAP이 비활성화되어 있다면, 다음 호출도 허용되어 버립니다.
```c
ioctl(fd, 0xdead, 0xffffffffdeadbeef);
```
`0xffffffffdeadbeef`는 사용자 공간에서는 유효하지 않은 주소지만, 예를 들어 이 주소에 Linux 커널의 비밀 데이터가 들어 있다고 가정해 봅시다. 그러면 드라이버는 다음을 실행하게 됩니다.
```
memcpy(buffer, 0xffffffffdeadbeef, 0x10);
```
즉 비밀 데이터를 읽어 버립니다. 이번 예시처럼 사용자 공간에서 받은 주소를 아무 검증 없이 `memcpy`에 넘겨 버리면, 사용자 공간에서 커널 공간의 임의 주소를 읽고 쓸 수 있게 됩니다.
커널 프로그래밍에 익숙하지 않은 사람에게는 이런 취약점이 매우 눈에 잘 띄지 않지만, AAR/AAW가 가능해지므로 영향은 치명적입니다. SMAP은 이런 종류의 실수를 막는 데에도 도움이 됩니다.

SMAP 역시 qemu 실행 인자로 활성화할 수 있습니다. 다음처럼 `-cpu` 옵션에 `+smap`이 붙어 있으면 SMAP이 켜집니다.
```
-cpu kvm64,+smap
```
머신 내부에서는 `/proc/cpuinfo`를 확인해서도 알 수 있습니다.
```
$ cat /proc/cpuinfo | grep smap
```

SMAP도 SMEP과 마찬가지로 하드웨어 보안 기능입니다. `CR4` 레지스터의 22번째 비트를 세우면 활성화됩니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="늑대" ></div>
  <p class="says">
    Intel CPU에는 EFLAGS.AC(Alignment Check) 플래그를 각각 1, 0으로 바꾸는 <a href="https://www.felixcloutier.com/x86/stac" target="_blank">STAC</a>와 <a href="https://www.felixcloutier.com/x86/clac" target="_blank">CLAC</a> 명령이 있고, AC가 세트되어 있는 동안에는 SMAP 효과가 일시적으로 비활성화돼.
  </p>
</div>


## KASLR / FGKASLR
유저 공간에는 주소를 랜덤화하는 ASLR(Address Space Layout Randomization)이 있었습니다. 이와 비슷하게 Linux 커널과 디바이스 드라이버의 코드 및 데이터 영역 주소를 랜덤화하는 **KASLR**(Kernel ASLR)라는 완화 기법도 존재합니다.
커널은 한 번 로드되면 이동하지 않으므로, KASLR은 부팅 시 한 번만 작동합니다. Linux 커널 내부의 함수나 데이터 주소를 하나라도 누출할 수 있으면 베이스 주소를 구할 수 있습니다.

[2020년 이후](https://lwn.net/Articles/824307/)에는 더 강력한 **FGKASLR**(Function Granular KASLR)도 등장했습니다. 2022년 기준으로는 기본 비활성화인 것 같지만, 이 기능은 Linux 커널의 함수마다 주소를 랜덤화합니다. 따라서 어떤 함수의 주소를 누출하더라도 베이스 주소를 계산할 수 없습니다.
하지만 FGKASLR은 데이터 섹션 같은 영역은 랜덤화하지 않으므로, 데이터 주소를 누출할 수 있다면 베이스 주소를 구할 수 있습니다. 물론 베이스 주소만으로 특정 함수 주소를 바로 계산할 수는 없지만, 뒤에서 등장하는 특수한 공격 벡터에는 여전히 유용할 수 있습니다.

주소는 커널 공간 전체에서 공유된다는 점을 기억하세요. 어떤 디바이스 드라이버가 KASLR 때문에 exploit 불가능해 보여도, 다른 드라이버가 커널 주소를 누출해 버리면 주소는 공통이므로 결국 exploit 가능해질 수 있습니다.

KASLR은 커널 부팅 인자로 비활성화할 수 있습니다. qemu의 `-append` 옵션에 `nokaslr`가 포함되어 있으면 KASLR은 꺼져 있습니다.
```
-append "... nokaslr ..."
```

## KPTI (Kernel Page-Table Isolation)
2018년에 Intel 등의 CPU에서 [Meltdown](https://ja.wikipedia.org/wiki/Meltdown)이라는 사이드 채널 공격이 발견되었습니다. 이 취약점 자체는 여기서 설명하지 않지만, 사용자 권한으로 커널 메모리를 읽을 수 있게 되는 매우 심각한 문제였고, KASLR 우회 등도 가능했습니다. 최근 Linux 커널은 Meltdown 대응책으로 **KPTI**(Kernel Page-Table Isolation), 또는 예전 이름인 **KAISER**를 활성화합니다.

가상 주소를 물리 주소로 변환할 때 페이지 테이블이 사용된다는 것은 잘 알려져 있습니다. 이 보안 기능은 사용자 모드와 커널 모드에서 사용하는 페이지 테이블을 분리합니다[^2]. KPTI는 어디까지나 Meltdown을 막기 위한 기법이므로, 일반적인 커널 익스플로잇 자체에서는 큰 문제가 되지 않습니다. 하지만 커널 공간에서 ROP를 구성하는 경우 KPTI가 켜져 있으면 마지막에 사용자 공간으로 복귀할 때 문제가 생깁니다. 구체적인 해결 방법은 Kernel ROP 장에서 다시 설명합니다.

KPTI는 커널 부팅 인자로 제어할 수 있습니다. qemu의 `-append` 옵션에 `pti=on`이 있으면 KPTI가 활성화되고, `pti=off` 또는 `nopti`가 있으면 비활성화됩니다.
```
-append "... pti=on ..."
```
`/sys/devices/system/cpu/vulnerabilities/meltdown`를 통해서도 확인할 수 있습니다. 다음처럼 `Mitigation: PTI`라고 적혀 있으면 KPTI가 활성화된 것입니다.
```
# cat /sys/devices/system/cpu/vulnerabilities/meltdown
Mitigation: PTI
```
비활성화된 경우에는 `Vulnerable`로 표시됩니다.

KPTI는 페이지 테이블 전환이므로, `CR3` 레지스터 조작으로 사용자 공간과 커널 공간을 전환할 수 있습니다. Linux에서는 `CR3`에 `0x1000`을 OR하는 방식, 즉 PDBR을 바꾸는 방식으로 커널 공간에서 사용자 공간으로 돌아갑니다. 이 동작은 [`swapgs_restore_regs_and_return_to_usermode`](https://github.com/torvalds/linux/blob/master/arch/x86/entry/entry_64.S)에 정의되어 있으며, 자세한 내용은 실제 익스플로잇을 작성하는 장에서 설명합니다.

## KADR (Kernel Address Display Restriction)
Linux 커널에서는 `/proc/kallsyms`를 통해 함수 이름과 주소 정보를 읽을 수 있습니다. 또한 일부 디바이스 드라이버는 `printk` 같은 함수를 사용해 여러 디버그 정보를 로그에 출력하며, 사용자는 `dmesg` 명령 등을 통해 이를 볼 수 있습니다.
이처럼 커널 공간의 함수, 데이터, 힙 등의 주소 정보 누출을 막기 위한 기능이 Linux에는 존재합니다. 공식 명칭은 없는 것 같지만, [참고 문헌](https://inaz2.hatenablog.com/entry/2015/03/27/021422)에서는 이를 **KADR**(Kernel Address Display Restriction)이라고 부르고 있어, 이 사이트에서도 그 명칭을 사용합니다.

이 기능은 `/proc/sys/kernel/kptr_restrict` 값으로 제어할 수 있습니다. `kptr_restrict`가 0이면 주소 표시 제한이 없습니다. 1이면 `CAP_SYSLOG` 권한을 가진 사용자에게만 주소가 보입니다. 2이면 특권 사용자라도 커널 주소는 숨겨집니다.
KADR이 비활성화되어 있으면 주소 누출이 전혀 필요 없어질 수 있어서, 익스플로잇이 훨씬 쉬워질 수 있으니 먼저 확인해 볼 가치가 있습니다.

[^1]: x64에서는 32비트 레지스터에 대해 연산한 결과가 64비트로 확장됩니다.
[^2]: 시스템 콜 진입 경로만은 커널/사용자 공간 사이에서 공유됩니다.

----

<div class="column" title="예제">
  <a href="../LK01/distfiles/LK01.tar.gz">연습문제 LK01</a>의 커널에 대해 다음 작업을 수행해 봅시다. (앞선 예제에서 이미 root 권한 셸을 얻은 상태에서 시작하세요.)<br>
  (1) <code>run.sh</code>를 읽고 KASLR, KPTI, SMAP, SMEP가 활성화되어 있는지 확인하세요.<br>
  (2) SMAP과 SMEP를 모두 활성화하는 옵션을 붙여 부팅한 뒤, <code>/proc/cpuinfo</code>를 확인해 두 기능이 활성화된 것을 확인하세요. (확인 후에는 다시 비활성화하세요.)<br>
  (3) <code>head /proc/kallsyms</code> 결과에서 가장 처음 나오는 주소가 커널 베이스 주소입니다. KASLR이 비활성화된 경우 그 값이 얼마인지 확인하세요. (힌트: KADR에 주의하세요.)
</div>
