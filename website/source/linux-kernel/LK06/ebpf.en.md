---
title: Introduction to BPF
tags:
    - [Linux]
    - [Kernel]
    - [BPF]
    - [JIT]
lang: en
permalink: /en/linux-kernel/LK06/ebpf.html
pagination: true
fd: verifier.html
---
In LK06 (Brahman), we attack a bug in the eBPF JIT and verifier, which are features of the Linux kernel. In this chapter, we first learn what BPF is and how to use it.

## BPF
Before explaining eBPF, let's start with its predecessor, BPF.
Over time, BPF gained more use cases and was expanded significantly. After those major extensions, it is often called eBPF (extended BPF), while the older form is called cBPF (classic BPF). In modern Linux, only eBPF is used internally, so on this site we simply say "BPF" unless the distinction matters.

### What is BPF?
**BPF** (Berkeley Packet Filter) is a RISC-style virtual machine built into the Linux kernel. It exists so that code supplied from userland can run inside the kernel.

Obviously, letting arbitrary code run in the kernel would be dangerous, so the BPF instruction set is mostly made of relatively safe instructions such as arithmetic and conditional branches. Still, it does contain instructions like memory access and jumps whose safety cannot be guaranteed automatically. For that reason, every BPF bytecode program is checked by a **verifier** before it is accepted. Only programs that satisfy the safety rules, for example not falling into infinite loops, are allowed to run.

Why go to all this trouble just to run user-supplied code in the kernel?
BPF was originally designed for packet filtering. A user loads BPF code, and when a packet arrives, the kernel executes that code to decide how to handle the packet. Today, BPF is also used for execution tracing, seccomp filtering, and many other kernel features.

As BPF spread into packet filters, seccomp, tracing, and more, performance became important. Interpreting BPF bytecode every time is too slow, so after a program passes the verifier, it is translated into native machine code by a **JIT** (Just-In-Time) compiler.

A JIT compiler dynamically converts some form of code into native machine code while the program is running. Browsers such as Chrome and Firefox do this for frequently executed JavaScript functions. In Linux, whether the BPF JIT is enabled depends on the configuration, but in modern kernels it is enabled by default.

So the overall flow looks like this:

1. A BPF bytecode program is passed from userland into the kernel through the `bpf` syscall.
2. The verifier checks whether executing that bytecode is safe.
3. If verification succeeds, the JIT compiler translates it into machine code for the current CPU.
4. When the corresponding event happens, that JIT-compiled machine code runs.

<center>
  <img src="img/bpf_load.png" alt="Loading BPF" style="width:640px;">
</center>

When the event occurs, the kernel passes arguments to the registered BPF program according to the program type. Those arguments are called the **context**. The BPF program processes the context and finally returns one value.

For example, in seccomp, a structure containing the syscall number, architecture, and related metadata is passed into the BPF program. The BPF program inspects those fields and returns a policy decision to the kernel. The kernel then decides whether to allow, deny, or fail the syscall.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="Wolf" ></div>
  <p class="says">
    seccomp still uses cBPF at the interface level, but inside the kernel it is converted into eBPF first. seccomp also has its own validation logic in addition to the BPF verifier.
  </p>
</div>

To exchange data between a BPF program and userland, BPF uses **BPF maps**. A map is a kernel-side key-value container[^1]. We will see the details once we start writing real BPF programs.

[^1]: Maps come in several kinds. For example, `BPF_MAP_TYPE_ARRAY` is effectively just an array because the key is an integer with a fixed upper bound.

### BPF architecture
Let's look at the internal structure of eBPF in more detail.
cBPF used a 32-bit architecture. eBPF is 64-bit and has more registers, matching modern CPUs much more closely.

#### Registers and stack
BPF programs get a 512-byte stack. eBPF provides the following registers:

| BPF register | Corresponding x64 register |
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

All registers except `R10` are general-purpose from the point of view of the BPF program, but some of them have conventional meanings.

The context pointer provided by the kernel is placed in `R1`. In many program types, the BPF code begins by reading useful fields out of that context.

`R0` is used as the return value register. Before a program exits with `BPF_EXIT_INSN`, `R0` must contain an appropriate result. That value has a different meaning depending on program type. For seccomp, it determines whether the syscall is allowed or denied.

`R1` through `R5` are also used as argument registers when a BPF program calls a kernel helper function.

Finally, `R10` is the frame pointer for the BPF stack, and it is read-only.

#### Instruction set
An unprivileged BPF program can contain up to 4096 instructions[^2].

[^2]: A root user may load programs with up to one million instructions.

BPF is a RISC architecture, so every instruction has the same size. Each instruction is 64 bits and is divided like this:

| Bits | Name | Meaning |
|:-:|:-:|:-:|
| 0-7 | `op` | opcode |
| 8-11 | `dst_reg` | destination register |
| 12-15 | `src_reg` | source register |
| 16-31 | `off` | offset |
| 32-63 | `imm` | immediate |

Inside `op`, the low 4 bits encode the operation, the next 1 bit encodes the source kind, and the remaining 3 bits encode the class.

The class describes the instruction family, such as memory access or arithmetic. The source bit says whether the source operand is a register or an immediate. The operation field then selects the exact instruction within that class.

The full BPF instruction set is documented in the [Linux kernel documentation](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html).

#### Program types
When we briefly tested BPF earlier, we used `BPF_PROG_TYPE_SOCKET_FILTER`. As that name suggests, a BPF program must be loaded for a specific purpose.

cBPF had only two main uses, socket filtering and syscall filtering, but eBPF defines more than twenty program types.

You can find the complete list in [`uapi/linux/bpf.h`](https://elixir.bootlin.com/linux/v5.18.10/source/include/uapi/linux/bpf.h#L922).

For example, `BPF_PROG_TYPE_SOCKET_FILTER` is the classic packet filtering mode. Depending on the program's return value, the kernel may drop or truncate packets. This type of program can be attached to a socket with `setsockopt(..., SO_ATTACH_BPF, ...)`.

Its context is a [`__sk_buff` structure](https://elixir.bootlin.com/linux/v5.18.10/source/include/uapi/linux/bpf.h#L5543).

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="Wolf" ></div>
  <p class="says">
    The kernel does not expose the raw internal `sk_buff` structure directly because that would make BPF programs too dependent on the exact kernel version. So it uses a stabilized BPF-facing representation instead.
  </p>
</div>

#### Helper functions
As mentioned above, BPF programs may call certain kernel functions. For example, socket filters expose the following helper selection logic:
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
Common helpers include things like `map_lookup_elem` and `map_update_elem`, which operate on BPF maps. We will learn their concrete usage while writing actual BPF code.

## Using BPF
Now let's actually use BPF (eBPF).

If you test on the LK06 challenge machine, things should work out of the box. If you test on your normal Linux machine, first check whether unprivileged BPF is allowed. At the time this article was written, many kernels disabled it for side-channel reasons such as Spectre.
```
$ cat /proc/sys/kernel/unprivileged_bpf_disabled
2
```
If the value is `0`, unprivileged users may use BPF. If it is `1` or `2`, temporarily change it to `0`.

### Writing a BPF program
For complex production uses such as packet filters or tracing, people usually write BPF in a higher-level form and compile it with tools like [BCC](https://github.com/iovisor/bcc). Here we only need enough BPF for exploit work, so we will write BPF bytecode directly.

That does not mean typing raw hex. The kernel ecosystem provides C macros that let you express BPF instructions in a way that feels a bit like assembly. First, download [bpf_insn.h](distfiles/bpf_insn.h) and place it next to your test source.

Let's begin by running the simplest possible BPF program.
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

  /* Prepare a BPF program */
  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 4),
    BPF_EXIT_INSN(),
  };

  /* Set the usage type (socket filter) */
  union bpf_attr prog_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
    .insns = (uint64_t)insns,
    .license = (uint64_t)"GPL v2",
    .log_level = 2,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };

  /* Load the BPF program */
  int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
  if (progfd == -1) {
    fatal("bpf(BPF_PROG_LOAD)");
  }

  /* Create a socket */
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    fatal("socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    fatal("setsockopt");

  /* Use the socket (triggers the BPF program) */
  write(socks[1], "Hello", 5);

  char buf[0x10] = {};
  read(socks[0], buf, 0x10);
  printf("Received: %s\n", buf);

  return 0;
}
```
This program loads a BPF program of type `BPF_PROG_TYPE_SOCKET_FILTER` onto a socket. That means the final `write` triggers the BPF code.

The BPF program itself is this part:
```c
  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 4),
    BPF_EXIT_INSN(),
  };
```
It puts the immediate value `4` into `R0` and exits. If everything works, the program will print `"Hell"` instead of `"Hello"`.

We will discuss registers in more detail later, but for now remember that `R0` is the return value register. Even though the `write` sent 5 bytes, only 4 bytes are received because the BPF program truncated the packet. In fact, the `socket` man page says:

> SO_ATTACH_FILTER (since Linux 2.2), SO_ATTACH_BPF (since Linux 3.19)
>
> Attach a classic BPF (SO_ATTACH_FILTER) or an extended BPF (SO_ATTACH_BPF) program to the socket for use as a filter of incoming packets. A packet will be dropped if the filter program returns zero. If the filter program returns a nonzero value which is less than the packet's data length, the packet will be truncated to the length returned. If the value returned by the filter is greater than or equal to the packet's data length, the packet is allowed to proceed unmodified.

### Using BPF maps
So far we confirmed that BPF can filter packets. Next, let's use one of the most important building blocks in eBPF exploitation: the BPF map.

A BPF map is how userland and the in-kernel BPF program exchange data.
To create a map, call the `bpf` syscall with `BPF_MAP_CREATE`. In the `bpf_attr` structure, set the type to `BPF_MAP_TYPE_ARRAY`, then specify the array size and the key/value sizes. In exploit contexts, small integer keys are usually enough.
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
To update a value, use `BPF_MAP_UPDATE_ELEM`. To read one, use `BPF_MAP_LOOKUP_ELEM`.
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
  return bpf(BPF_MAP_LOOKUP_ELEM, &attr); // -1 if not found
}
```
Try a small program like this and verify that you can read and write the map from userland:
```c
  unsigned long val;
  int mapfd = map_create(sizeof(val), 4);

  val = 0xdeadbeefcafebabe;
  map_update(mapfd, 1, &val);

  val = 0;
  map_lookup(mapfd, 1, &val);
  printf("0x%lx\n", val);
```

Now let's operate on the same BPF map from inside a BPF program:
```c
  /* Prepare a BPF map */
  unsigned long val;
  int mapfd = map_create(sizeof(val), 4);

  val = 0xdeadbeefcafebabe;
  map_update(mapfd, 1, &val);

  /* Prepare a BPF program */
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

  /* Use the socket (triggers the BPF program) */
  map_lookup(mapfd, 1, &val);
  printf("val (before): 0x%lx\n", val);

  write(socks[1], "Hello", 5);

  map_lookup(mapfd, 1, &val);
  printf("val (after) : 0x%lx\n", val);
```
This BPF program uses the `map_update_elem` helper to change the value at key `1` to `0x1337`.

First, since `map_update_elem` expects pointers for both the key and the value, we place those on the stack:
```c
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 1),      // key=1
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0x1337), // val=0x1337
```
`BPF_REG_FP` is `R10`, the frame pointer. In x86-64 terms, those instructions are conceptually similar to:
```
mov dword [rsp-0x08], 1
mov dword [rsp-0x10], 0x1337
```

Next we set up the arguments. `BPF_REG_ARG1` and following correspond to the helper-call argument registers starting from `R1`.
The first argument to `map_update_elem` is the map file descriptor:
```c
    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
```
The second and third arguments are pointers to the key and value:
```c
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // arg3: value pointer
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_2),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),
```
The fourth argument is the flag value. We just pass `0`.
```c
    // arg4: flags
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),
```
Finally, we call the helper with:
```c
    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem(mapfd, &k, &v)
```

When you run the program, you can see that the value stored at key `1` changes before and after the `write` that triggers the BPF program:
```
$ ./a.out
val (before): 0xdeadbeefcafebabe
val (after) : 0x1337
```

That covers the basics of BPF. In practice, BPF programs implement things like packet filters by combining maps and helper functions.
In the next chapter, we move on to the verifier, which is the most important part of many BPF-related vulnerabilities.

---

<div class="column" title="Exercise">
  In this chapter, the BPF program partially dropped a packet. Investigate whether the following operations are possible from a BPF program, and if so, write such a program. (Hint: look at helpers such as <code>skb_load_bytes</code>.)<br>
  (1) Drop the packet if the outgoing data contains the string "evil".<br>
  (2) If the outgoing data length is at least 4 bytes, replace the first 4 bytes with "evil".
</div>
