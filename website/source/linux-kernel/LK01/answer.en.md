---
title: "Holstein v1: About the Exercise Answer"
tags:
    - [Linux]
    - [Kernel]
lang: en
permalink: /en/linux-kernel/LK01/answer.html
pagination: true
bk: stack_overflow.html
---
### Can SMEP be disabled?
At this point we have confirmed that privilege escalation is possible with kROP, but let's consider a different approach.
As explained in the [security mechanisms](../introduction/security#smep-supervisor-mode-execution-prevention) section, SMEP is controlled by the `CR4` register. Therefore, if a ROP chain can flip bit 21 of `CR4`, SMEP should be disabled and `ret2usr` should become usable again.

The question is whether such a ROP gadget actually exists.
Since you cannot directly perform an immediate operation on `CR4`, you have to manipulate it through another general-purpose register. Code that accesses `CR4` does exist inside the kernel, so such gadgets must exist somewhere, but whether there is one that ends cleanly in `ret` without problematic side effects has to be checked manually with tools such as `objdump`. (Many tools do not find control-register operations correctly, and such sequences are often followed by `jmp` rather than `ret`.)
For example, there are gadgets that write to `CR4` like the following:
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
Since we did not find a gadget that simply writes `CR4` and returns immediately, let's inspect where these gadgets come from. We can search `kallsyms` for nearby functions.
```
/ # cat /proc/kallsyms | grep ffffffff810285
ffffffff81028540 T native_write_cr4
ffffffff810285b0 T cr4_init
/ # cat /proc/kallsyms | grep ffffffff810284
ffffffff81028440 t default_init
ffffffff810284b0 T cr4_update_irqsoff
```
These turn out to come from the functions [`cr4_init`](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/kernel/cpu/common.c#L420) and [`cr4_update_irqsoff`](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/kernel/cpu/common.c#L399).
In particular, `cr4_update_irqsoff` looks promising:
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
It lets us specify which bits in `CR4` should be set and which should be cleared.
So we can try a ROP chain like the following:
```c
  *chain++ = rop_pop_rdi;
  *chain++ = 0; // bit to set
  *chain++ = rop_pop_rsi;
  *chain++ = 1 << 20; // bit to clear
  *chain++ = cr4_update_irqsoff;
  *chain++ = (unsigned long)&escalate_privilege;
```
When we execute this, the kernel still crashes under SMEP when `escalate_privilege` is reached. If we check the value of `CR4` just beforehand, the SMEP bit is still enabled. Let's single-step and see why `CR4` is not being updated.

<center>
  <img src="img/update_cr4.png" alt="The CR4 update part of cr4_update_irqoff" style="width:640px;">
</center>

This corresponds to the following part of `cr4_update_irqsoff`:
```
if (newval != cr4) {
```
As you can see, at this point the code is not yet reading or writing the real `CR4` register. If we keep single-stepping, execution eventually enters the following path:

<center>
  <img src="img/pinned_cr4.png" alt="Detection of changes to pinned CR4 bits" style="width:640px;">
</center>

At that point, the `RDI` register points to the following string:

<center>
  <img src="img/pinned_cr4_message.png" alt="pinned CR4 bits changed" style="width:480px;">
</center>

If we search the kernel source for that message, we find the following code in [`native_write_cr4`](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/kernel/cpu/common.c#L377):
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
There is a global variable called `cr_pinning`. In other words, the kernel has a small security feature that prevents certain bits in `CR4` from being changed.
`cr4_pinned_bits` is a constant, so we cannot modify it. The data used for `cr_pinning` also lives in a read-only area, so we cannot change that either. In machine code, the relevant part looks like this:

<center>
  <img src="img/cr_pinning.png" alt="Checking cr_pinning" style="width:480px;">
</center>

So when using `native_write_cr4`, an extra check is applied, and SMEP or SMAP cannot be disabled dynamically that way. Once ROP is available, using `commit_creds` is simpler than trying to rewrite `CR4`.
That said, techniques for disabling SMEP do appear in some places such as Windows 7 kernel exploits.

So the answer to the exercise is: it is possible only if there exists a ROP gadget that can OR `0x1000` into `CR4` without going through `native_write_cr4`.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/cow.jpg" alt="Cow" ></div>
  <p class="says">
    A gadget that simply ORs 0x1000 into CR4 usually does not exist, but by abusing Linux kernel BPF, it is actually possible to create arbitrary gadgets.
  </p>
</div>
