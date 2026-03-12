---
title: BPF 입문
tags:
    - [Linux]
    - [Kernel]
    - [BPF]
    - [JIT]
lang: kr
permalink: /kr/linux-kernel/LK06/ebpf.html
pagination: true
fd: verifier.html
---
LK06(Brahman)에서는 Linux 커널 기능 중 하나인 eBPF의 JIT(그리고 verifier) 버그를 공격합니다. 이 장에서는 먼저 BPF가 무엇인지, 그리고 어떻게 사용하는지를 배웁니다.

## BPF
eBPF를 설명하기 전에, 그 전신인 BPF부터 설명하겠습니다.
BPF는 시대가 지나며 용도가 크게 넓어졌고, 그 과정에서 많은 확장이 들어갔습니다. 큰 변경 이후의 BPF를 eBPF(extended BPF), 그 이전 것을 cBPF(classic BPF)라고 구분하기도 합니다. 하지만 현대 Linux는 내부적으로 eBPF만 사용하므로, 이 사이트에서는 구분이 꼭 필요할 때를 제외하면 둘을 통틀어 BPF라고 부르겠습니다.

### BPF란?
**BPF**(Berkeley Packet Filter)는 Linux 커널 안에 있는 RISC형 가상 머신입니다. 사용자 공간에서 전달된 코드를 커널 공간에서 실행하기 위해 존재합니다.

물론 임의 코드를 커널에서 실행하게 두는 것은 위험하므로, BPF 명령어 집합은 대부분 연산, 조건 분기처럼 비교적 안전한 명령으로 구성됩니다. 하지만 메모리 접근이나 점프처럼 안전성을 자동으로 보장할 수 없는 명령도 포함되므로, 바이트코드를 수용하기 전에 반드시 **verifier(검증기)**를 통과시킵니다. 이를 통해 예를 들어 무한 루프에 빠지지 않는 등 안전하다고 판단된 프로그램만 실행됩니다.

그렇다면 왜 이렇게까지 해서 사용자 공간 코드를 커널에서 실행하려는 걸까요?
BPF는 원래 패킷 필터링을 위해 설계되었습니다. 사용자가 BPF 코드를 로드해 두면 패킷이 발생할 때 그 코드가 실행되어 필터링에 쓰입니다. 지금은 패킷 필터뿐 아니라 실행 추적, seccomp 시스템콜 필터링 등 다양한 기능에도 사용됩니다.

이처럼 BPF가 여러 기능에 쓰이게 되면서 성능이 중요해졌습니다. 매번 바이트코드를 인터프리트하는 것은 너무 느리므로, verifier를 통과한 BPF 바이트코드는 **JIT**(Just-In-Time) 컴파일러를 통해 CPU가 직접 실행할 수 있는 기계어로 변환됩니다.

JIT 컴파일러란 프로그램 실행 중에 어떤 형태의 코드를 네이티브 기계어로 바꾸는 장치를 말합니다. Chrome이나 Firefox 같은 브라우저도 자주 호출되는 JavaScript 함수를 기계어로 바꿔 더 빠르게 실행합니다. Linux 커널의 BPF에서 JIT 사용 여부는 설정에 따라 다르지만, 요즘 커널에서는 기본적으로 활성화되어 있습니다.

정리하면 BPF 코드가 실행되기까지의 흐름은 다음과 같습니다.

1. 사용자 공간에서 `bpf` 시스템콜로 BPF 바이트코드를 커널에 전달한다.
2. verifier가 그 바이트코드가 안전한지 검사한다.
3. 검증에 성공하면 JIT 컴파일러가 현재 CPU용 기계어로 변환한다.
4. 해당 이벤트가 발생하면 JIT 변환된 기계어가 실행된다.

<center>
  <img src="img/bpf_load.png" alt="BPF 로드" style="width:640px;">
</center>

이벤트가 발생하면, 등록한 BPF 종류에 따라 인자가 전달됩니다. 이 인자를 **context**라고 부릅니다. BPF는 그 context를 처리하고 최종적으로 하나의 값을 반환합니다.

예를 들어 seccomp의 경우, 시스템콜 번호, 아키텍처 정보 등이 들어 있는 구조체가 BPF 프로그램에 전달됩니다. BPF 프로그램은 그 정보를 보고 시스템콜을 허용할지 판단한 뒤 결과를 커널에 반환합니다. 커널은 그 반환값을 이용해 시스템콜을 허용할지, 거부할지, 실패시킬지를 결정합니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="늑대" ></div>
  <p class="says">
    seccomp는 외부 인터페이스 수준에서는 아직 cBPF를 쓰지만, 커널 내부에서는 먼저 eBPF로 변환돼. 또 seccomp에는 BPF verifier와는 별도의 자체 검증 로직도 있어.
  </p>
</div>

또한 BPF 프로그램과 사용자 공간이 데이터를 주고받으려면 **BPF map**을 사용합니다. map은 커널 안에 존재하는 key-value 형태의 저장소입니다[^1]. 이것은 실제로 BPF 프로그램을 쓰면서 다시 보겠습니다.

[^1]: map에는 여러 종류가 있습니다. 예를 들어 `BPF_MAP_TYPE_ARRAY`는 key가 정수이고 상한도 고정되어 있으므로 사실상 그냥 배열입니다.

### BPF의 아키텍처
이제 eBPF의 구조를 좀 더 자세히 봅시다.
cBPF는 32비트 아키텍처였지만, eBPF는 현대 CPU에 맞춰 64비트가 되었고 레지스터 수도 늘었습니다.

#### 레지스터와 스택
BPF 프로그램은 512바이트 스택을 사용할 수 있습니다. eBPF에는 다음 레지스터들이 있습니다.

| BPF 레지스터 | 대응하는 x64 레지스터 |
|:-:|:-:|
| R0 | rax |
| R1 | rdi |
| R2 | rsi |
| R3 | rdx |
| R4 | rcx |
| R5 | r8 |
| R6 | rbx |
| R7 | r13 |
| R8 | r14 |
| R9 | r15 |
| R10 | rbp |

`R10`을 제외한 레지스터는 일반적인 범용 레지스터처럼 쓸 수 있지만, 몇 개는 관례상 특별한 의미를 가집니다.

커널이 넘겨주는 context 포인터는 `R1`에 들어갑니다. 많은 BPF 프로그램은 여기서부터 필요한 필드를 읽어 시작합니다.

`R0`는 반환값 레지스터입니다. 따라서 `BPF_EXIT_INSN`으로 종료하기 전에 `R0`에 적절한 값을 반드시 넣어야 합니다. 이 값의 의미는 프로그램 타입에 따라 달라집니다. 예를 들어 seccomp에서는 시스템콜 허용/거부 정책이 됩니다.

또한 `R1`부터 `R5`까지는 helper 함수를 호출할 때 인자 레지스터로도 사용됩니다.

마지막으로 `R10`은 프레임 포인터이며 읽기 전용입니다.

#### 명령어 집합
일반 사용자가 로드하는 BPF 프로그램은 최대 4096개의 명령어를 사용할 수 있습니다[^2].

[^2]: root는 최대 100만 개까지 로드할 수 있습니다.

BPF는 RISC 구조이므로 모든 명령어 크기가 같습니다. 각 명령은 64비트이고, 다음과 같이 나뉩니다.

| 비트 | 이름 | 의미 |
|:-:|:-:|:-:|
| 0-7 | `op` | opcode |
| 8-11 | `dst_reg` | 목적지 레지스터 |
| 12-15 | `src_reg` | 소스 레지스터 |
| 16-31 | `off` | 오프셋 |
| 32-63 | `imm` | 즉값 |

`op` 안에서는 하위 4비트가 연산 종류, 그 다음 1비트가 소스 종류, 나머지 3비트가 클래스입니다.

클래스는 메모리 접근, 산술 연산 같은 명령군을 의미합니다. 소스 비트는 피연산자가 레지스터인지 즉값인지 나타냅니다. 그리고 연산 필드가 실제 세부 명령을 지정합니다.

전체 BPF 명령어 집합은 [Linux 커널 문서](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html)에 정리되어 있습니다.

#### 프로그램 타입
앞선 예제에서는 `BPF_PROG_TYPE_SOCKET_FILTER`를 사용했습니다. 이처럼 BPF 프로그램은 로드 시점에 어떤 용도로 사용할지 타입을 지정해야 합니다.

cBPF 시절에는 소켓 필터와 시스템콜 필터 정도만 대표적이었지만, eBPF는 20개가 넘는 프로그램 타입을 가집니다.

전체 목록은 [`uapi/linux/bpf.h`](https://elixir.bootlin.com/linux/v5.18.10/source/include/uapi/linux/bpf.h#L922)에서 확인할 수 있습니다.

예를 들어 `BPF_PROG_TYPE_SOCKET_FILTER`는 전통적인 패킷 필터링 모드입니다. BPF 프로그램의 반환값에 따라 패킷을 드롭하거나 잘라낼 수 있습니다. 이 타입은 `setsockopt(..., SO_ATTACH_BPF, ...)`를 통해 소켓에 붙입니다.

이때 context로는 [`__sk_buff` 구조체](https://elixir.bootlin.com/linux/v5.18.10/source/include/uapi/linux/bpf.h#L5543)가 전달됩니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="늑대" ></div>
  <p class="says">
    커널 내부 `sk_buff`를 그대로 노출하면 커널 버전에 따라 BPF 프로그램이 너무 많이 깨질 수 있으니, BPF용으로 정돈된 표현을 따로 쓰는 거야.
  </p>
</div>

#### Helper 함수
앞서 말한 것처럼 BPF 프로그램은 특정 커널 helper를 호출할 수 있습니다. 예를 들어 socket filter는 다음과 같은 helper 선택 로직을 가집니다.
```c
static const struct bpf_func_proto *
sk_filter_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_skb_load_bytes:
		return &bpf_skb_load_bytes_proto;
	case BPF_FUNC_skb_load_bytes_relative:
		return &bpf_skb_load_bytes_relative_proto;
	case BPF_FUNC_get_socket_cookie:
		return &bpf_get_socket_cookie_proto;
	case BPF_FUNC_get_socket_uid:
		return &bpf_get_socket_uid_proto;
	case BPF_FUNC_perf_event_output:
		return &bpf_skb_event_output_proto;
	default:
		return bpf_sk_base_func_proto(func_id);
	}
}
```
대표적인 helper로는 `map_lookup_elem`, `map_update_elem` 같은 map 조작 함수가 있습니다. 각 helper의 실제 사용법은 BPF 코드를 직접 쓰면서 익히는 편이 가장 좋습니다.

## BPF 사용
이제 실제로 BPF(eBPF)를 사용해 봅시다.

LK06 실습 머신에서는 그대로 테스트하면 되지만, 평소 쓰는 Linux 머신에서 테스트한다면 먼저 일반 사용자에게 BPF가 허용되는지 확인해야 합니다. 이 글을 쓰던 시점에는 Spectre 같은 사이드채널 문제 때문에 unprivileged BPF가 기본적으로 막힌 환경이 많았습니다.
```
$ cat /proc/sys/kernel/unprivileged_bpf_disabled
2
```
값이 `0`이면 비특권 사용자도 BPF를 쓸 수 있습니다. `1`이나 `2`라면 임시로 `0`으로 바꾸세요.

### BPF 프로그램 작성
패킷 필터나 트레이싱처럼 복잡한 용도에서는 보통 [BCC](https://github.com/iovisor/bcc) 같은 도구를 사용해 C 같은 상위 언어로 작성한 뒤 컴파일합니다. 하지만 여기서는 exploit 실습용으로 가볍게 쓰기만 하면 되므로, 바이트코드를 직접 적겠습니다.

직접 적는다고 해도 생 바이트를 16진수로 쓰는 건 아닙니다. BPF 명령어를 사람이 읽기 쉬운 형태로 표현할 수 있는 C 매크로가 준비되어 있습니다. 먼저 [bpf_insn.h](distfiles/bpf_insn.h)를 다운로드해 테스트 코드와 같은 폴더에 두세요.

우선 아무 일도 하지 않는 간단한 BPF 프로그램을 실행해 봅시다.
```c
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "bpf_insn.h"

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int bpf(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int main() {
  char verifier_log[0x10000];

  /* BPF 프로그램 준비 */
  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 4),
    BPF_EXIT_INSN(),
  };

  /* 사용 타입 설정 (socket filter) */
  union bpf_attr prog_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
    .insns = (uint64_t)insns,
    .license = (uint64_t)"GPL v2",
    .log_level = 2,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };

  /* BPF 프로그램 로드 */
  int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
  if (progfd == -1) {
    fatal("bpf(BPF_PROG_LOAD)");
  }

  /* 소켓 생성 */
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    fatal("socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    fatal("setsockopt");

  /* 소켓 사용 (BPF 프로그램 발동) */
  write(socks[1], "Hello", 5);

  char buf[0x10] = {};
  read(socks[0], buf, 0x10);
  printf("Received: %s\n", buf);

  return 0;
}
```
이 코드는 `BPF_PROG_TYPE_SOCKET_FILTER` 타입의 BPF 프로그램을 소켓에 붙입니다. 따라서 마지막 `write`가 BPF 프로그램의 트리거가 됩니다.

BPF 프로그램 본체는 다음 부분입니다.
```c
  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 4),
    BPF_EXIT_INSN(),
  };
```
이 예제는 `R0`에 즉값 `4`를 넣고 종료합니다. 정상적으로 동작하면 `"Hello"`가 아니라 `"Hell"`만 출력됩니다.

레지스터는 뒤에서 다시 정리하지만, 지금은 `R0`가 반환값 레지스터라는 점만 기억하면 됩니다. `write`로 5바이트를 보냈는데 4바이트만 읽히는 이유는 BPF 프로그램이 패킷 길이를 잘랐기 때문입니다. 실제로 `socket` 매뉴얼에는 다음과 같이 설명되어 있습니다.

> SO_ATTACH_FILTER (since Linux 2.2), SO_ATTACH_BPF (since Linux 3.19)
>
> Attach a classic BPF (SO_ATTACH_FILTER) or an extended BPF (SO_ATTACH_BPF) program to the socket for use as a filter of incoming packets. A packet will be dropped if the filter program returns zero. If the filter program returns a nonzero value which is less than the packet's data length, the packet will be truncated to the length returned. If the value returned by the filter is greater than or equal to the packet's data length, the packet is allowed to proceed unmodified.

### BPF map 사용
여기까지로 BPF가 패킷을 필터링할 수 있다는 것은 확인했습니다. 이제 eBPF exploit에서 거의 항상 등장하는 BPF map을 사용해 봅시다.

BPF map은 사용자 공간과 커널 안에서 돌아가는 BPF 프로그램이 데이터를 주고받는 통로입니다.
map을 만들려면 `bpf` 시스템콜에 `BPF_MAP_CREATE`를 전달합니다. 이때 `bpf_attr` 구조체에서 타입을 `BPF_MAP_TYPE_ARRAY`로 하고, 배열 크기 및 key/value 크기를 지정합니다. exploit 문맥에서는 보통 key를 작은 정수로 두면 충분합니다.
```c
int map_create(int val_size, int max_entries) {
  union bpf_attr attr = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = val_size,
    .max_entries = max_entries
  };
  int mapfd = bpf(BPF_MAP_CREATE, &attr);
  if (mapfd == -1) fatal("bpf(BPF_MAP_CREATE)");
  return mapfd;
}
```
값 업데이트는 `BPF_MAP_UPDATE_ELEM`, 값 읽기는 `BPF_MAP_LOOKUP_ELEM`으로 합니다.
```c
int map_update(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = (uint64_t)pval,
    .flags = BPF_ANY
  };
  int res = bpf(BPF_MAP_UPDATE_ELEM, &attr);
  if (res == -1) fatal("bpf(BPF_MAP_UPDATE_ELEM)");
  return res;
}

int map_lookup(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = (uint64_t)pval,
    .flags = BPF_ANY
  };
  return bpf(BPF_MAP_LOOKUP_ELEM, &attr); // not found면 -1
}
```
다음 같은 프로그램으로 사용자 공간에서 map 읽기/쓰기가 되는지 먼저 확인해 보세요.
```c
  unsigned long val;
  int mapfd = map_create(sizeof(val), 4);

  val = 0xdeadbeefcafebabe;
  map_update(mapfd, 1, &val);

  val = 0;
  map_lookup(mapfd, 1, &val);
  printf("0x%lx\n", val);
```

이제는 같은 BPF map을 BPF 프로그램 내부에서 조작해 보겠습니다.
```c
  /* BPF map 준비 */
  unsigned long val;
  int mapfd = map_create(sizeof(val), 4);

  val = 0xdeadbeefcafebabe;
  map_update(mapfd, 1, &val);

  /* BPF 프로그램 준비 */
  struct bpf_insn insns[] = {
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 1),      // key=1
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0x1337), // val=0x1337
    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // arg3: value pointer
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_2),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),
    // arg4: flags
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),

    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem(mapfd, &k, &v)

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

...

  /* 소켓 사용 (BPF 프로그램 발동) */
  map_lookup(mapfd, 1, &val);
  printf("val (before): 0x%lx\n", val);

  write(socks[1], "Hello", 5);

  map_lookup(mapfd, 1, &val);
  printf("val (after) : 0x%lx\n", val);
```
이 BPF 프로그램은 `map_update_elem` helper를 사용해 key `1`의 값을 `0x1337`로 바꿉니다.

먼저 `map_update_elem`은 key와 value 모두 포인터로 받기 때문에, 스택에 key와 value를 준비합니다.
```c
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 1),      // key=1
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0x1337), // val=0x1337
```
`BPF_REG_FP`는 `R10`, 즉 프레임 포인터입니다. 이 명령은 x86-64 느낌으로 쓰면 대략 다음과 같습니다.
```
mov dword [rsp-0x08], 1
mov dword [rsp-0x10], 0x1337
```

그다음 helper 인자들을 채웁니다. `BPF_REG_ARG1`부터가 helper 인자 레지스터입니다.
첫 번째 인자는 map의 file descriptor입니다.
```c
    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
```
두 번째와 세 번째 인자는 각각 key, value에 대한 포인터입니다.
```c
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // arg3: value pointer
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_2),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),
```
네 번째 인자는 플래그이며 `0`을 넣습니다.
```c
    // arg4: flags
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),
```
마지막으로 helper는 이렇게 호출합니다.
```c
    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem(mapfd, &k, &v)
```

실행하면 BPF 프로그램을 트리거하는 `write` 전후로 key `1`의 값이 바뀌는 것을 볼 수 있습니다.
```
$ ./a.out
val (before): 0xdeadbeefcafebabe
val (after) : 0x1337
```

여기까지가 BPF의 기초입니다. 이처럼 BPF 프로그래밍에서는 map과 helper를 조합해 패킷 필터 같은 기능을 구현합니다.
다음 장에서는 BPF 취약점 분석에서 가장 중요한 verifier를 다룹니다.

---

<div class="column" title="예제">
  이 장에서는 BPF 프로그램으로 패킷을 부분적으로 드롭했습니다. 다음 동작이 가능한지 조사하고, 가능하다면 그런 BPF 프로그램을 작성해 보세요. (힌트: <code>skb_load_bytes</code> 같은 helper를 찾아보세요.)<br>
  (1) 송신 데이터에 "evil" 문자열이 포함돼 있으면 드롭한다.<br>
  (2) 송신 데이터 길이가 4바이트 이상이면, 앞 4바이트를 "evil"로 바꾼다.
</div>
