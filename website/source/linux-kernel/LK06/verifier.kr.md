---
title: 검증기와 JIT 컴파일러
tags:
    - [Linux]
    - [Kernel]
    - [BPF]
    - [JIT]
lang: kr
permalink: /kr/linux-kernel/LK06/verifier.html
pagination: true
fd: exploit.html
bk: ebpf.html
---
[이전 장](ebpf.html)에서는 eBPF의 기본을 배웠습니다. 이번 장에서는 사용자 공간이 넘긴 BPF 프로그램을 안전하고 빠르게 실행하기 위해 존재하는 verifier와 JIT를 설명합니다.

## Verifier
먼저 eBPF verifier를 봅시다. 소스는 [`kernel/bpf/verifier.c`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c)에 있습니다.
verifier는 명령어를 하나씩 검사하고, 모든 분기 경로를 `exit` 명령까지 추적합니다. 검증은 크게 두 단계, 즉 First Pass와 Second Pass로 나뉩니다.

첫 번째 단계에서는 깊이 우선 탐색을 통해 프로그램이 DAG(Directed Acyclic Graph), 즉 지원되지 않는 루프가 없는 유향 비순환 그래프인지 확인합니다.
이 단계는 다음 프로그램들을 거부합니다.

- `BPF_MAXINSNS`를 넘는 명령 수[^1]
- 루프가 존재하는 경우
- 도달 불가능한 명령이 존재하는 경우
- 범위를 벗어나거나 잘못된 점프가 존재하는 경우

[^1]: 명령 수 검사는 `check_cfg` 이전에 먼저 수행됩니다.

두 번째 단계에서는 모든 경로를 다시 탐색하면서 레지스터 타입, 값 범위, 알려진 비트, 오프셋을 추적합니다.
이 단계가 거부하는 예는 다음과 같습니다.

- 초기화되지 않은 레지스터 사용
- 커널 포인터 반환
- 커널 포인터를 BPF map에 저장
- 잘못된 포인터 읽기/쓰기

### 1단계 검사
DAG 검사는 [`check_cfg`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L10186)에 구현되어 있습니다. 알고리즘 자체는 재귀를 쓰지 않는 깊이 우선 탐색입니다.
`check_cfg`는 프로그램 시작부터 DFS 방식으로 명령어를 보며, 현재 명령어에 대해 [`visit_insn`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L10121)이 호출됩니다. 이 함수가 다음에 탐색할 경로를 스택에 넣습니다.

실제 push는 [`push_insn`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L10044)에서 일어나며, 바로 여기서 범위 밖 점프와 루프가 감지됩니다.
```c
	if (w < 0 || w >= env->prog->len) {
		verbose_linfo(env, t, "%d: ", t);
		verbose(env, "jump out of range from insn %d to %d\n", t, w);
		return -EINVAL;
	}
...

	} else if ((insn_state[w] & 0xF0) == DISCOVERED) {
		if (loop_ok && env->bpf_capable)
			return DONE_EXPLORING;
		verbose_linfo(env, t, "%d: ", t);
		verbose_linfo(env, w, "%d: ", w);
		verbose(env, "back-edge from insn %d to %d\n", t, w);
		return -EINVAL;
```

흥미로운 점은 `visit_insn`이 조건 분기의 양쪽을 한 번에 push하지 않는다는 것입니다. 한 번에 하나의 경로만 push하거나, 모든 경로가 이미 탐색되었으면 `DONE_EXPLORING`을 반환합니다.
예를 들어 `BPF_JEQ` 같은 조건 분기에서는 첫 호출 때 한쪽 분기만 push합니다. DFS이므로 그 분기를 전부 탐색한 뒤 다시 돌아오고, 두 번째 호출에서 반대 분기를 push합니다. 마지막으로 세 번째 호출에서 `DONE_EXPLORING`을 반환하며 스택에서 빠집니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="늑대" ></div>
  <p class="says">
    얼핏 비효율적으로 보이지만, 검증 실패 시 더 깔끔한 스택 트레이스를 출력하기 위한 설계라고 볼 수 있어.
  </p>
</div>

다음과 같은 프로그램은 모두 1단계 검사에서 거부됩니다.
```c
// 도달 불가능한 명령이 있음
struct bpf_insn insns[] = {
  BPF_EXIT_INSN(),
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};
```

```c
// 범위를 벗어나는 점프가 있음
struct bpf_insn insns[] = {
  BPF_JMP_IMM(BPF_JA, 0, 0, 2),
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};
```

```c
// 루프가 있음
struct bpf_insn insns[] = {
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 123, -1),
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};
```

음수 방향 점프가 있어도 루프만 아니면 괜찮습니다.
```c
struct bpf_insn insns[] = {
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_JMP_IMM(BPF_JA, 0, 0, 1),
  BPF_JMP_IMM(BPF_JA, 0, 0, 1),
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, -2),
  BPF_EXIT_INSN(),
};
```

### 2단계 검사
eBPF verifier 버그에서 가장 중요한 부분은 두 번째 단계입니다.
이 단계는 주로 [`do_check`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L11450)에 구현되어 있으며, 레지스터 타입, 값 범위, 알려진 비트, 오프셋을 추적합니다.

#### 타입 추적
verifier는 각 레지스터가 어떤 종류의 값인지 [`struct bpf_reg_state`](https://elixir.bootlin.com/linux/v5.18.11/source/include/linux/bpf_verifier.h#L46)로 관리합니다.
예를 들어:
```
BPF_MOV64_REG(BPF_REG_0, BPF_REG_10)
BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, -8)
```
첫 번째 명령은 스택 포인터를 `R0`로 복사하므로 `R0`의 타입은 `PTR_TO_STACK`가 됩니다.
두 번째 명령은 8을 빼지만 여전히 스택 내부를 가리키므로 타입은 그대로 `PTR_TO_STACK`입니다.

타입 추적은 필수입니다. 스칼라 값을 포인터처럼 사용할 수 있다면 바로 임의 메모리 접근이 가능해집니다. 마찬가지로 map 포인터나 context 포인터를 helper에 속여 넘길 수 있으면 helper 자체를 악용할 수 있습니다.

대표적인 [`enum bpf_reg_type`](https://elixir.bootlin.com/linux/v5.18.11/source/include/linux/bpf.h#L493) 값은 다음과 같습니다.

| 타입 | 의미 |
|:-:|:-:|
| `NOT_INIT` | 미초기화 |
| `SCALAR_VALUE` | 일반 스칼라 값 |
| `PTR_TO_CTX` | 프로그램 context 포인터 |
| `CONST_PTR_TO_MAP` | BPF map 포인터 |
| `PTR_TO_MAP_VALUE` | BPF map value 포인터 |
| `PTR_TO_MAP_KEY` | BPF map key 포인터 |
| `PTR_TO_STACK` | BPF 스택 포인터 |
| `PTR_TO_MEM` | 유효 메모리 포인터 |
| `PTR_TO_FUNC` | BPF 함수 포인터 |

초기 레지스터 상태는 [`init_reg_state`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L1570)에 정의되어 있습니다.

#### 상수 추적
verifier는 값의 범위도 추적합니다.
정확한 단일 값을 저장하는 대신, 구간과 비트 수준 정보를 사용합니다. 즉 각 레지스터에 대해 현재 가능한 최솟값과 최댓값을 관리합니다.

예를 들어 `R0 += R1` 연산 시점에 `R0`가 `[10, 20]`, `R1`이 `[-2, 2]` 범위를 가진다면, 연산 후 `R0`의 범위는 `[8, 22]`가 됩니다.

이 동작은 [`adjust_reg_min_max_vals`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L8438), [`adjust_scalar_min_max_vals`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L8277) 같은 함수들에 구현되어 있습니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="늑대" ></div>
  <p class="says">
    정확한 값을 모를 때는 안전한 추상 범위를 써서 추적하는 경우가 많아. 이 추상화가 sound하지 않으면 분석 전체가 틀어질 수 있어.
  </p>
</div>

범위 추적을 위해 verifier는 다음 필드를 저장합니다.

| 변수 | 의미 |
|:-:|:-|
| `umin_value`, `umax_value` | 64비트 unsigned로 본 최소/최대 |
| `smin_value`, `smax_value` | 64비트 signed로 본 최소/최대 |
| `u32_min_value`, `u32_max_value` | 32비트 unsigned로 본 최소/최대 |
| `s32_min_value`, `s32_max_value` | 32비트 signed로 본 최소/최대 |
| `var_off` | 레지스터의 알려진/알려지지 않은 비트 정보 |

`var_off`는 `tnum`으로 표현되며 `mask`와 `value`를 가집니다.
`mask`는 아직 모르는 비트, `value`는 이미 확정된 비트를 뜻합니다.

예를 들어 BPF map에서 읽어온 64비트 값은 처음엔 모든 비트를 모릅니다.
```
(mask=0xffffffffffffffff; value=0x0)
```
여기에 `0xffff0000`를 AND하면 아래쪽 비트는 0으로 확정됩니다.
```
(mask=0xffff0000; value=0x0)
```
그다음 `0x12345`를 더하면 carry 가능성 때문에 불확실성이 약간 커지면서:
```
(mask=0x1ffff0000; value=0x2345)
```
처럼 됩니다.

일반적인 `BPF_ADD`에 대해서 verifier는 다음처럼 상태를 갱신합니다.
```c
	case BPF_ADD:
		scalar32_min_max_add(dst_reg, &src_reg);
		scalar_min_max_add(dst_reg, &src_reg);
		dst_reg->var_off = tnum_add(dst_reg->var_off, src_reg.var_off);
		break;
```

그리고 범위 갱신 도우미는 signed/unsigned overflow도 고려합니다.
```c
static void scalar_min_max_add(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	s64 smin_val = src_reg->smin_value;
	s64 smax_val = src_reg->smax_value;
	u64 umin_val = src_reg->umin_value;
	u64 umax_val = src_reg->umax_value;

	if (signed_add_overflows(dst_reg->smin_value, smin_val) ||
	    signed_add_overflows(dst_reg->smax_value, smax_val)) {
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
	} else {
		dst_reg->smin_value += smin_val;
		dst_reg->smax_value += smax_val;
	}
	if (dst_reg->umin_value + umin_val < umin_val ||
	    dst_reg->umax_value + umax_val < umax_val) {
		dst_reg->umin_value = 0;
		dst_reg->umax_value = U64_MAX;
	} else {
		dst_reg->umin_value += umin_val;
		dst_reg->umax_value += umax_val;
	}
}
```

이렇게 계산된 범위는 나중에 스택, map, context 접근의 범위 검증에 사용됩니다.
예를 들어 스택 범위 검사는 [`check_stack_access_within_bounds`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L4315)에 있습니다.
오프셋이 상수면 평범한 concrete check를 합니다.
```c
	if (tnum_is_const(reg->var_off)) {
		min_off = reg->var_off.value + off;
		if (access_size > 0)
			max_off = min_off + access_size - 1;
		else
			max_off = min_off;
```
상수가 아니면 가능한 최소/최대 오프셋을 계산해 검사합니다.
```c
	} else {
		if (reg->smax_value >= BPF_MAX_VAR_OFF ||
		    reg->smin_value <= -BPF_MAX_VAR_OFF) {
			verbose(env, "invalid unbounded variable-offset%s stack R%d\n",
				err_extra, regno);
			return -EACCES;
		}
		min_off = reg->smin_value + off;
		if (access_size > 0)
			max_off = reg->smax_value + off + access_size - 1;
		else
			max_off = min_off;
	}
```
그 다음 양 끝값 모두를 검사합니다.
```c
	err = check_stack_slot_within_bounds(min_off, state, type);
	if (!err)
		err = check_stack_slot_within_bounds(max_off, state, type);
```

이런 종류의 범위 추적은 BPF에만 있는 것이 아닙니다. 최적화와 속도가 중요한 JIT나 컴파일러 전반에서 자주 등장합니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="늑대" ></div>
  <p class="says">
    실행 속도를 높이기 위해, 가능한 많은 안전성 검사를 미리 끝내려고 하는 거지.
  </p>
</div>

다음과 같은 프로그램은 모두 2단계 검사에서 거부됩니다.
```c
// 초기화되지 않은 레지스터 사용
struct bpf_insn insns[] = {
  BPF_MOV64_REG(BPF_REG_0, BPF_REG_5),
  BPF_EXIT_INSN(),
};
```

```c
// 커널 포인터 누출
struct bpf_insn insns[] = {
  BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
  BPF_EXIT_INSN(),
};
```

값이 상수는 아니지만 bounded한 경우의 예를 보겠습니다.
```c
int mapfd = map_create(0x10, 1);

struct bpf_insn insns[] = {
  BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 0),      // key=0
  // arg1: mapfd
  BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
  // arg2: key pointer
  BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
  // map_lookup_elem(mapfd, &key)
  BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
  // jmp if success (R0 != NULL)
  BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
  BPF_EXIT_INSN(), // exit on failure

  BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),   // R6 = arr[0]
  BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),            // R7 = &arr[0]

  BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 0b0111),    // R6 &= 0b0111
  BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6), // R7 += R6
  BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_7, 0), // R0 = [R7]
  BPF_EXIT_INSN(),
};
```
`R6`는 `0b0111`과 AND되므로 verifier는 `R6`가 `[0, 7]` 범위에 있음을 압니다. map value 크기가 `0x10`이므로 그 범위에서 8바이트를 읽는 것은 안전하여 프로그램이 허용됩니다.
반대로 마스크를 `0b1111`로 바꾸면 verifier가 거부합니다.
```
...
11: (0f) r7 += r6
 R0=map_value(id=0,off=0,ks=4,vs=16,imm=0) R6_w=invP(id=0,umax_value=15,var_off=(0x0; 0xf)) R7_w=map_value(id=0,off=0,ks=4,vs=16,umax_value=15,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmmmmmm
12: R0=map_value(id=0,off=0,ks=4,vs=16,imm=0) R6_w=invP(id=0,umax_value=15,var_off=(0x0; 0xf)) R7_w=map_value(id=0,off=0,ks=4,vs=16,umax_value=15,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmmmmmm
12: (79) r0 = *(u64 *)(r7 +0)
 R0_w=map_value(id=0,off=0,ks=4,vs=16,imm=0) R6_w=invP(id=0,umax_value=15,var_off=(0x0; 0xf)) R7_w=map_value(id=0,off=0,ks=4,vs=16,umax_value=15,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmmmmmm
invalid access to map value, value_size=16 off=15 size=8
R7 max value is outside of the allowed memory range
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1

bpf(BPF_PROG_LOAD): Permission denied
```

일부 명령은 verifier가 정밀하게 추적하지 못합니다. 예를 들어 `BPF_NEG`를 거치면 범위 정보가 크게 무너지는 경우가 많아서 실제로는 안전한 코드도 거부될 수 있습니다.

그래서 2단계 검사가 중요합니다. 이 체크가 틀리면 범위 밖 접근이 통과하게 되고, 다음 장에서 그것이 어떻게 exploit로 이어지는지를 보게 됩니다.

#### ALU sanitation
앞서 본 타입/범위 추적이 verifier의 핵심 역할이지만, eBPF exploit가 많아지면서 **ALU sanitation**이라는 완화책이 추가되었습니다.

verifier 버그가 위험한 주된 이유는 범위 밖 접근을 허용하기 때문입니다.
예를 들어 verifier는 어떤 스칼라 레지스터를 `0`이라고 믿지만, 실제 런타임 값은 `32`라고 해 봅시다. 공격자는 그 "깨진" 값을 작은 map 안의 포인터에 더합니다. verifier는 여전히 그 포인터가 map 내부에 있다고 믿지만, 실제로는 범위 밖을 가리키게 됩니다. 그 포인터로 load를 하면 탐지되지 않은 OOB 접근이 생깁니다.

<center>
  <img src="img/simple_oob.png" alt="잘못된 범위 추적으로 인한 OOB 접근" style="width:640px;">
</center>

이를 완화하기 위해 ALU sanitation이 [2019년에 도입](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=979d63d50c0c0f7bc537bf821e056cc9fe5abd38)되었습니다.[^2]

[^2]: 초기 구현에도 버그가 있어서 [2021년에 수정](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=10d2bb2e6b1d8c4576c56a748f697dbeb8388899)되었습니다.

eBPF에서는 포인터에 대해 직접 허용되는 산술은 스칼라와의 덧셈/뺄셈뿐입니다.
스칼라가 상수라고 증명되면 ALU sanitation은 그 연산을 즉값 형태 `BPF_ALUxx_IMM`으로 바꿉니다.
상수가 아니면 `alu_limit`이라는 값, 즉 그 포인터가 안전하게 움직일 수 있는 최대 범위를 계산하고, 범위를 벗어나는 런타임 오프셋이 들어와도 실제 사용 전 무력화되도록 보조 명령을 삽입합니다.

세부 패치 시퀀스보다 중요한 것은 아이디어입니다.
- 런타임 오프셋이 안전 범위 안에 있으면 그대로 유지
- 범위를 벗어나면 실제로는 0처럼 무력화

#### 2단계 검사가 금지하는 것들
대략 정리하면 2단계 검사는 다음을 막습니다.

- 레지스터 오용
  - `R10`(frame pointer)에 대한 쓰기
  - 초기화되지 않은 레지스터 읽기
- context 오용
  - context 범위 밖 읽기/쓰기
  - 지원되지 않는 context 필드 사용
- 포인터 오용
  - 스칼라를 임의 포인터처럼 다루기
  - 커널 주소를 사용자 공간으로 반환하기
  - 원시 커널 포인터를 공격자 제어 저장소에 기록하기

바로 그래서 verifier 버그가 강력합니다. verifier를 한 번이라도 일관성 없게 만들 수 있으면, 그 모든 보장이 무너지기 시작합니다.
