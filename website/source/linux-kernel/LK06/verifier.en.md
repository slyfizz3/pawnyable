---
title: Verifier and JIT Compiler
tags:
    - [Linux]
    - [Kernel]
    - [BPF]
    - [JIT]
lang: en
permalink: /en/linux-kernel/LK06/verifier.html
pagination: true
fd: exploit.html
bk: ebpf.html
---
In the [previous chapter](ebpf.html), we learned the basics of eBPF. In this chapter, we explain the verifier and JIT, which exist to make user-supplied BPF programs both safe and fast.

## Verifier
Let's start with the eBPF verifier. Its source code lives in [`kernel/bpf/verifier.c`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c).
The verifier checks instructions one by one and explores every control-flow path until it reaches an exit instruction. Verification is broadly divided into two phases: the First Pass and the Second Pass.

In the first pass, a depth-first search ensures that the program forms a directed acyclic graph (DAG), meaning it contains no unsupported loops.
This phase rejects programs that:

- contain more than `BPF_MAXINSNS` instructions[^1]
- contain loops
- contain unreachable instructions
- jump out of range or jump to invalid destinations

[^1]: The instruction-count check happens even before `check_cfg`, which performs the other CFG checks.

In the second pass, the verifier walks all paths again while tracking register types, value ranges, concrete bits, and offsets.
This is what rejects programs that:

- use uninitialized registers
- return kernel pointers
- store kernel pointers into BPF maps
- perform invalid pointer reads or writes

### First-pass checks
The DAG check is implemented in [`check_cfg`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L10186). The algorithm is a depth-first search implemented without recursive calls.
`check_cfg` visits instructions in DFS order starting from the beginning of the program. For each current instruction, [`visit_insn`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L10121) is called, and that function decides which next path to push onto the exploration stack.

The actual stack push happens in [`push_insn`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L10044), which is also where out-of-range jumps and loops are detected.
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

One subtle point is that `visit_insn` never pushes both branches of a conditional at once. It pushes exactly one path, or returns `DONE_EXPLORING` once every branch for that instruction has already been explored.
For example, if the current instruction is a conditional jump like `BPF_JEQ`, the verifier first pushes only one branch target. Since the traversal is depth-first, the verifier eventually returns to that `BPF_JEQ`, calls `visit_insn` again, and then pushes the other branch. When both have been explored, a third call returns `DONE_EXPLORING`, and the instruction is popped.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="Wolf" ></div>
  <p class="says">
    At first glance this looks inefficient. But it makes it easier to emit a clean stack trace when verification fails.
  </p>
</div>

The following kinds of programs are rejected entirely by the first-pass checks:
```c
// Contains an unreachable instruction
struct bpf_insn insns[] = {
  BPF_EXIT_INSN(),
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};
```

```c
// Contains an out-of-range jump
struct bpf_insn insns[] = {
  BPF_JMP_IMM(BPF_JA, 0, 0, 2),
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};
```

```c
// Contains a loop
struct bpf_insn insns[] = {
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 123, -1),
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};
```

Negative jumps are fine as long as they do not create a cycle:
```c
struct bpf_insn insns[] = {
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_JMP_IMM(BPF_JA, 0, 0, 1),
  BPF_JMP_IMM(BPF_JA, 0, 0, 1),
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, -2),
  BPF_EXIT_INSN(),
};
```

### Second-pass checks
The most important verifier bugs in eBPF live in the second pass.
This phase is primarily implemented in [`do_check`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L11450), which tracks register types, value ranges, exact known bits, and offsets.

#### Tracking types
The verifier keeps track of the kind of value stored in each register through [`struct bpf_reg_state`](https://elixir.bootlin.com/linux/v5.18.11/source/include/linux/bpf_verifier.h#L46).
Consider:
```
BPF_MOV64_REG(BPF_REG_0, BPF_REG_10)
BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, -8)
```
The first instruction copies the stack pointer into `R0`, so `R0` gets the type `PTR_TO_STACK`.
The second subtracts 8, but since the result still points inside the BPF stack, `R0` remains `PTR_TO_STACK`.

Type tracking is essential. If a scalar could be treated as a pointer, you would immediately get arbitrary memory access. Likewise, if a program could pass a fake map pointer or fake context pointer into helpers, it could abuse helpers in unintended ways.

Some of the main [`enum bpf_reg_type`](https://elixir.bootlin.com/linux/v5.18.11/source/include/linux/bpf.h#L493) values are:

| Type | Meaning |
|:-:|:-:|
| `NOT_INIT` | uninitialized |
| `SCALAR_VALUE` | plain scalar value |
| `PTR_TO_CTX` | pointer to the program context |
| `CONST_PTR_TO_MAP` | pointer to a BPF map |
| `PTR_TO_MAP_VALUE` | pointer to a BPF map value |
| `PTR_TO_MAP_KEY` | pointer to a BPF map key |
| `PTR_TO_STACK` | pointer to the BPF stack |
| `PTR_TO_MEM` | pointer to valid memory |
| `PTR_TO_FUNC` | pointer to a BPF function |

The initial state of registers is defined in [`init_reg_state`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L1570).

#### Tracking constants
The verifier also tracks value ranges.
Rather than keeping one exact value, it uses intervals and bit-level abstractions. For each register, it stores the minimum and maximum values the register may currently hold.

For example, if `R0 += R1` and the verifier currently knows that `R0` is in `[10, 20]` while `R1` is in `[-2, 2]`, then after abstract interpretation the new range for `R0` becomes `[8, 22]`.

This behavior is implemented in functions such as [`adjust_reg_min_max_vals`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L8438) and [`adjust_scalar_min_max_vals`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L8277).

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="Wolf" ></div>
  <p class="says">
    Whenever exact values are unknown, JITs and static analyzers often approximate them with safe abstract ranges. If the abstraction stops being sound, the whole analysis becomes wrong.
  </p>
</div>

To track ranges, the verifier stores fields such as:

| Field | Meaning |
|:-:|:-|
| `umin_value`, `umax_value` | min/max as 64-bit unsigned |
| `smin_value`, `smax_value` | min/max as 64-bit signed |
| `u32_min_value`, `u32_max_value` | min/max as 32-bit unsigned |
| `s32_min_value`, `s32_max_value` | min/max as 32-bit signed |
| `var_off` | known and unknown bits in the register |

`var_off` is represented by a `tnum`, which contains a `mask` and a `value`.
The `mask` marks bits that are still unknown. The `value` stores the known bits.

For example, if a 64-bit value is loaded from a BPF map, initially every bit is unknown:
```
(mask=0xffffffffffffffff; value=0x0)
```
If you then AND it with `0xffff0000`, the zeroed low bits become known:
```
(mask=0xffff0000; value=0x0)
```
If you then add `0x12345`, the low bits become partly known and the carry uncertainty widens the mask:
```
(mask=0x1ffff0000; value=0x2345)
```

At the same time, the unsigned ranges become consistent with those bit constraints.

For a normal `BPF_ADD`, the verifier updates the tracked state like this:
```c
	case BPF_ADD:
		scalar32_min_max_add(dst_reg, &src_reg);
		scalar_min_max_add(dst_reg, &src_reg);
		dst_reg->var_off = tnum_add(dst_reg->var_off, src_reg.var_off);
		break;
```

The helper that updates scalar ranges also accounts for signed and unsigned overflow:
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

Those computed ranges are later used for bounds checks on accesses to stack memory, maps, and context structures.
For example, stack bounds checking is implemented in [`check_stack_access_within_bounds`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L4315).
If the offset is known exactly, the verifier does a normal concrete check:
```c
	if (tnum_is_const(reg->var_off)) {
		min_off = reg->var_off.value + off;
		if (access_size > 0)
			max_off = min_off + access_size - 1;
		else
			max_off = min_off;
```
If the exact value is unknown, it checks the smallest and largest possible offsets:
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
Then it checks both ends:
```c
	err = check_stack_slot_within_bounds(min_off, state, type);
	if (!err)
		err = check_stack_slot_within_bounds(max_off, state, type);
```

This kind of range tracking appears far beyond BPF. Any JIT or optimizing compiler that tries to push checks earlier and run faster tends to rely on the same idea.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="Wolf" ></div>
  <p class="says">
    To improve runtime performance, the kernel tries to finish as many safety checks as possible ahead of time.
  </p>
</div>

The second pass rejects examples like:
```c
// Use of an uninitialized register
struct bpf_insn insns[] = {
  BPF_MOV64_REG(BPF_REG_0, BPF_REG_5),
  BPF_EXIT_INSN(),
};
```

```c
// Leaking a kernel-space pointer
struct bpf_insn insns[] = {
  BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
  BPF_EXIT_INSN(),
};
```

Now consider a case where the verifier proves a value is bounded, but not constant:
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
Because `R6` is ANDed with `0b0111`, the verifier knows `R6` is in `[0, 7]`. Since the map value size is `0x10`, reading 8 bytes from offsets in that range is safe, so the program is accepted.
But if you change the mask to `0b1111`, the verifier rejects it:
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

Some instructions are not modeled precisely enough by the verifier. For example, after `BPF_NEG`, the verifier often loses useful range precision, so even safe programs may get rejected.

This is exactly why the second pass matters so much: if the verifier gets these checks wrong, an out-of-bounds access can slip through. The next chapter explains how that becomes exploitable.

#### ALU sanitation
The verifier's type and range tracking is the first line of defense, but as eBPF exploitation became more common, a mitigation called **ALU sanitation** was added.

The main reason verifier bugs are dangerous is that they allow out-of-bounds access.
Imagine that the verifier believes a scalar register is `0`, while its real runtime value is `32`. The attacker adds that broken scalar to a pointer into a small map. The verifier still believes the pointer stays inside the map, but in reality it now points outside the allowed area. A load through that pointer becomes an undetected out-of-bounds access.

<center>
  <img src="img/simple_oob.png" alt="Out-of-bounds access caused by incorrect range tracking" style="width:640px;">
</center>

To mitigate this, ALU sanitation was [introduced in 2019](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=979d63d50c0c0f7bc537bf821e056cc9fe5abd38).[^2]

[^2]: The first implementation had bugs of its own and was [fixed in 2021](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=10d2bb2e6b1d8c4576c56a748f697dbeb8388899).

In eBPF, the only arithmetic directly allowed on pointers is addition and subtraction with scalars.
If the scalar is known to be constant, ALU sanitation rewrites the operation into an immediate form such as `BPF_ALUxx_IMM`.
If the scalar is not constant, the verifier computes an `alu_limit`, which represents how far the pointer may move safely, and patches in additional masking logic so that out-of-range offsets collapse to zero instead of escaping the object.

The exact patch sequence is less important than the idea:
- if the runtime offset stays within the safe range, it is preserved
- if the runtime offset escapes that range, it is neutralized before use

#### What the second pass forbids
Very roughly speaking, the second pass forbids things like:

- Register misuse
  - writing to `R10` (the frame pointer)
  - reading from uninitialized registers
- Context misuse
  - reading or writing outside the context bounds
  - using context fields in unsupported ways
- Pointer misuse
  - turning scalars into arbitrary pointers
  - returning kernel addresses to userland
  - writing raw kernel pointers into attacker-controlled storage

That is why verifier bugs are so valuable to attackers. If the verifier can be made inconsistent even once, these guarantees start to collapse.
