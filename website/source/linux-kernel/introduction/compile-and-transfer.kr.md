---
title: 컴파일과 익스플로잇 전송
date: 2021-10-27 21:31:39
tags:
    - [Linux]
    - [Kernel]
lang: kr
permalink: /kr/linux-kernel/introduction/compile-and-transfer.html
pagination: true
bk: security.html
fd: ../LK01/welcome-to-holstein.html
---
이제 커널 부팅 방법, 디버깅 방법, 그리고 보안 기법까지 Kernel Exploit을 시작하는 데 필요한 지식은 모두 익혔습니다. 이제부터는 실제로 익스플로잇을 어떻게 작성하는지, 그리고 작성한 익스플로잇을 qemu 위에서 어떻게 실행하는지를 배웁니다.

## qemu에서 실행하기
qemu 위에서 직접 익스플로잇을 작성하고 빌드하고 실행하면, 커널이 한 번 크래시할 때마다 처음부터 다시 해야 해서 매우 번거롭습니다. 그래서 보통은 C로 작성한 익스플로잇을 로컬에서 빌드한 뒤, 그 결과물을 qemu 쪽으로 전송합니다.
이 과정을 매번 직접 입력하는 것은 귀찮으므로, 셸 스크립트 같은 템플릿을 하나 만들어 두는 것이 좋습니다. 예를 들어 다음과 같은 `transfer.sh`를 준비해 봅시다.
```bash
#!/bin/sh
gcc exploit.c -o exploit
mv exploit root
cd root; find . -print0 | cpio -o --null --format=newc > ../debugfs.cpio
cd ../

qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 nopti nokaslr" \
    -no-reboot \
    -cpu qemu64 \
    -gdb tcp::12345 \
    -smp 1 \
    -monitor /dev/null \
    -initrd debugfs.cpio \
    -net nic,model=virtio \
    -net user
```
설명할 것도 없이, 단순히 `exploit.c`를 컴파일해 `cpio`에 추가하고 qemu를 실행하는 스크립트입니다. 원래의 `rootfs.cpio`를 망가뜨리지 않기 위해 `debugfs.cpio`라는 이름의 디스크를 사용하고 있지만, 원한다면 바꿔도 됩니다.
또한 `cpio`를 만들 때 root 권한이 아니면 파일 권한 정보가 달라질 수 있으므로, `transfer.sh`는 root 권한으로 실행하는 것이 안전합니다.

이제 `exploit.c`에 다음 코드를 넣고 `transfer.sh`를 실행해 봅시다.
```c
#include <stdio.h>

int main() {
  puts("Hello, World!");
  return 0;
}
```
그러면 다음과 같은 에러가 발생할 것입니다. 왜 그럴까요?

<center>
  <img src="img/gcc_error.png" alt="GCC로 컴파일한 exploit이 실행되지 않음" style="width:320px;">
</center>

실은 이번에 배포된 이미지는 일반적인 `libc`가 아니라 더 작은 라이브러리인 `uClibc`를 사용합니다. 반면 여러분 로컬 환경의 GCC는 다른 `libc`를 기준으로 링크하므로, 동적 링크에 실패해서 익스플로잇이 실행되지 않습니다.
따라서 qemu에서 익스플로잇을 실행할 때는 static 링크를 하도록 주의해야 합니다.
```bash
gcc exploit.c -o exploit -static
```
이렇게 바꾼 뒤 다시 실행하면 프로그램이 정상 동작할 것입니다.

<center>
  <img src="img/static_works.png" alt="static 링크하면 exploit이 동작함" style="width:320px;">
</center>

## 원격 머신에서 실행하기: musl-gcc 사용
여기까지 하면 qemu 위에서 익스플로잇을 무사히 실행할 수 있습니다. 이번에 배포된 환경은 네트워크 연결이 가능하도록 설정되어 있기 때문에, 원격 실행이 필요하다면 qemu 내부에서 `wget` 같은 명령으로 익스플로잇을 받아 올 수 있습니다.
하지만 CTF 등에서 제공되는 일부 작은 환경은 네트워크를 사용할 수 없습니다. 이럴 때는 busybox에 있는 명령을 이용해 외부에서 바이너리를 전송해야 합니다. 일반적으로 `base64`를 많이 쓰지만, GCC로 빌드한 파일은 수백 KB에서 수십 MB까지 커질 수 있어서 전송에 매우 오래 걸립니다. 파일 크기가 커지는 이유는 외부 라이브러리(`libc`) 함수를 static 링크하고 있기 때문입니다.
GCC를 계속 쓰면서 파일 크기를 줄이려면 `libc`를 사용하지 않고, `read`, `write` 같은 기능도 시스템 콜(인라인 어셈블리)로 직접 정의해야 합니다. 물론 매우 번거로운 작업입니다.
그래서 많은 CTF 플레이어가 Kernel Exploit 용도로 `musl-gcc`라는 C 컴파일러를 사용합니다. 아래 링크에서 다운로드하여 빌드하고 설치를 끝내세요.

https://www.musl-libc.org/

설치가 끝났다면 `transfer.sh`의 컴파일 부분을 다음처럼 바꿔 봅시다. `musl-gcc` 경로는 각자 설치한 위치로 수정하면 됩니다.
```bash
/usr/local/musl/bin/musl-gcc exploit.c -o exploit -static
```
저자 환경에서는 앞의 Hello, World 프로그램이 `gcc`로는 851KB였고, `musl-gcc`로는 18KB였습니다. 더 작게 만들고 싶다면 `strip`으로 디버그 심볼을 제거해도 됩니다.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="늑대" ></div>
  <p class="says">
    일부 헤더 파일 특히 Linux 커널 관련 헤더는 musl-gcc에 없을 수 있어서, include 경로를 따로 지정하거나 gcc로 컴파일해야 할 때가 있어. 그럴 때는 한 번 어셈블리를 거쳐서 빌드하면 gcc 기능을 쓰면서도 파일 크기를 줄일 수 있어.<br>
    <code>
    $ gcc -S sample.c -o sample.S<br>
    $ musl-gcc sample.S -o sample.elf
    </code>
  </p>
</div>

여기까지 끝났다면, 이제 원격으로 `nc`를 통해 `base64`를 사용해 바이너리를 전송하는 스크립트를 작성해 봅시다. CTF에서는 이런 업로더를 거의 매번 쓰게 되므로, 자신만의 템플릿을 만들어 두는 것을 권장합니다.
```python
from ptrlib import *
import time
import base64
import os

def run(cmd):
    sock.sendlineafter("$ ", cmd)
    sock.recvline()

with open("./root/exploit", "rb") as f:
    payload = bytes2str(base64.b64encode(f.read()))

#sock = Socket("HOST", PORT) # remote
sock = Process("./run.sh")

run('cd /tmp')

logger.info("Uploading...")
for i in range(0, len(payload), 512):
    print(f"Uploading... {i:x} / {len(payload):x}")
    run('echo "{}" >> b64exp'.format(payload[i:i+512]))
run('base64 -d b64exp > exploit')
run('rm b64exp')
run('chmod +x exploit')

sock.interactive()
```
잠시 기다리면 아래와 같이 업로드가 완료될 것입니다.

<center>
  <img src="img/upload_script.png" alt="upload.py 실행 결과" style="width:520px;">
</center>

이 사이트에서는 대부분 로컬에서 실습하므로 업로드 자체는 필요하지 않지만, CTF에서 실전으로 사용할 때는 이런 흐름을 기억해 두면 좋습니다.
