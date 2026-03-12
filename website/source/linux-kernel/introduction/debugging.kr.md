---
title: gdb로 커널 디버깅하기
date: 2021-09-22 13:59:43
tags:
    - [Linux]
    - [Kernel]
lang: kr
permalink: /kr/linux-kernel/introduction/debugging.html
pagination: true
bk: introduction.html
fd: security.html
---
커널 익스플로잇에 입문하기 어려운 큰 이유 중 하나는, 디버깅 방법이 잘 감이 오지 않는다는 점입니다.
이 절에서는 `gdb`를 사용해 qemu 위에서 동작하는 Linux 커널을 디버깅하는 방법을 배웁니다.

먼저 [연습문제 LK01](../LK01/distfiles/LK01.tar.gz) 파일을 다운로드하세요.

## root 권한 셸 얻기
로컬에서 커널 익스플로잇을 디버깅할 때는 일반 사용자 권한으로는 불편한 일이 많습니다. 특히 커널이나 커널 드라이버 내부에 브레이크포인트를 걸거나, 누출된 주소가 어떤 함수의 주소인지 확인하려면 커널 주소 정보에 접근할 수 있는 root 권한이 필요합니다.
따라서 커널 익스플로잇을 디버깅할 때는 먼저 root 권한을 얻어 두는 것이 좋습니다. 이 절의 내용은 앞 장 예제의 (2)번과 동일하므로, 이미 해 본 분은 복습 정도로만 읽어도 됩니다.

커널이 부팅되면 가장 먼저 하나의 프로그램이 실행됩니다. 설정에 따라 경로는 다양하지만, 많은 경우 `/init`이나 `/sbin/init` 등에 있습니다. LK01의 `rootfs.cpio`를 풀어 보면 `/init`이 존재합니다.
```sh
#!/bin/sh
# devtmpfs does not get automounted for initramfs
/bin/mount -t devtmpfs devtmpfs /dev

# use the /dev/console device node from devtmpfs if possible to not
# confuse glibc's ttyname_r().
# This may fail (E.G. booted with console=), and errors from exec will
# terminate the shell, so use a subshell for the test
if (exec 0</dev/console) 2>/dev/null; then
    exec 0</dev/console
    exec 1>/dev/console
    exec 2>/dev/console
fi

exec /sbin/init "$@"
```
여기에는 특별히 중요한 처리가 적혀 있지 않지만, `/sbin/init`을 실행하고 있습니다.
참고로 CTF에서 배포되는 작은 환경에서는 `/init`에 직접 드라이버를 설치하거나 셸을 띄우는 처리가 들어가 있는 경우도 있습니다. 실제로 마지막 `exec` 줄 앞에 `/bin/sh`를 적으면 커널 부팅 시 root 권한 셸을 바로 실행할 수 있습니다. 다만 그러면 드라이버 설치 등 다른 초기화 작업이 실행되지 않으므로, 이번에는 이 파일을 수정하지 않습니다.

이후 `/sbin/init`으로부터 최종적으로 `/etc/init.d/rcS`라는 셸 스크립트가 실행됩니다. 이 스크립트는 `/etc/init.d` 안에서 이름이 `S`로 시작하는 파일들을 순서대로 실행합니다. 이번 환경에는 `S99pawnyable`이라는 스크립트가 있습니다. 이 스크립트에는 다양한 초기화 처리가 들어 있지만, 후반부의 다음 줄에 주목하세요.
```bash
setsid cttyhack setuidgid 1337 sh
```
이 줄이 이번 커널에서 부팅 시 일반 사용자 권한으로 셸을 실행하는 코드입니다. `cttyhack`은 Ctrl+C 같은 입력이 동작하도록 해 주는 명령입니다. 그리고 `setuidgid` 명령으로 사용자 ID와 그룹 ID를 1337로 설정한 뒤 `/bin/sh`를 실행합니다. 이 숫자를 0(즉 root 사용자)으로 바꿉니다.
```bash
setsid cttyhack setuidgid 0 sh
```
또한 자세한 내용은 [다음 장](security.html)에서 설명하지만, 일부 보안 기법을 비활성화하기 위해 다음 줄도 주석 처리해 두세요.
```diff
-echo 2 > /proc/sys/kernel/kptr_restrict    # 변경 전
+#echo 2 > /proc/sys/kernel/kptr_restrict   # 변경 후
```
수정이 끝났다면 `cpio`로 다시 패킹하고 `run.sh`를 실행하세요. 그러면 아래 스크린샷처럼 root 권한 셸을 사용할 수 있을 것입니다. (패킹 방법은 [앞 장](introduction.html#디스크-이미지)을 참고하세요.)

<center>
  <img src="img/rooted.png" alt="root 권한 셸 실행" style="width:340px;">
</center>

## qemu에 attach하기
qemu에는 `gdb`로 디버깅하기 위한 기능이 들어 있습니다. qemu에 `-gdb` 옵션을 넘기면 지정한 프로토콜, 호스트, 포트 번호로 listen하도록 만들 수 있습니다. 예를 들어 `run.sh`를 수정해서 다음 옵션을 추가하면 로컬호스트의 TCP 12345번 포트에서 `gdb` 접속을 기다리게 됩니다.
```
-gdb tcp::12345
```
이후 연습에서는 별도 언급 없이 12345번 포트를 사용하지만, 원하는 번호를 사용해도 됩니다.

`gdb`에서 attach하려면 `target` 명령으로 대상을 지정합니다.
```
pwndbg> target remote localhost:12345
```
이렇게 연결이 성공하면 준비가 끝난 것입니다. 이후에는 일반적인 `gdb` 명령을 이용해 레지스터와 메모리를 읽고 쓰고, 브레이크포인트를 설정하는 등의 작업이 가능합니다. 메모리 주소는 "그 브레이크포인트를 설정한 컨텍스트에서의 가상 주소"로 해석됩니다. 즉 커널 드라이버나 사용자 공간 프로그램이 사용하는 익숙한 주소에 그대로 브레이크포인트를 걸어도 됩니다.

이번 대상은 x86-64입니다. 만약 여러분의 `gdb`가 기본적으로 대상 아키텍처를 인식하지 못한다면, 다음처럼 아키텍처를 설정할 수 있습니다. (보통은 자동 인식됩니다.)
```
pwndbg> set arch i386:x86-64:intel
```

## 커널 디버깅
`/proc/kallsyms`라는 procfs 파일을 통해 Linux 커널 내부에 정의된 주소와 심볼 목록을 볼 수 있습니다. [다음 장의 KADR 절](security.html#kadr-kernel-address-display-restriction)에서 설명하듯이, 보안 기법 때문에 root 권한이어도 커널 주소가 보이지 않을 수 있습니다.
[root 권한 셸 얻기 절](#root-권한-셸-얻기)에서 이미 처리했지만, init 스크립트의 다음 줄을 주석 처리하는 것을 잊지 마세요. 그렇지 않으면 커널 공간 포인터가 보이지 않게 됩니다.
```bash
echo 2 > /proc/sys/kernel/kptr_restrict     # 변경 전
#echo 2 > /proc/sys/kernel/kptr_restrict    # 변경 후
```
이제 실제로 `kallsyms`를 확인해 봅시다. 양이 매우 많으므로 `head` 같은 명령으로 앞부분만 살펴보면 됩니다.

<center>
  <img src="img/kallsyms_head.png" alt="/proc/kallsyms의 앞부분" style="width:480px;">
</center>

이 출력은 심볼의 주소, 주소가 속한 섹션, 심볼 이름의 순서로 나옵니다. 예를 들어 `T`는 text 섹션, `D`는 data 섹션을 의미하며, 대문자는 전역으로 export된 심볼을 의미합니다. 이 문자들의 자세한 뜻은 `man nm`에서 확인할 수 있습니다.
예를 들어 위 그림에서는 `0xffffffff81000000`이 `_stext`라는 심볼의 주소라는 것을 알 수 있습니다. 이것이 커널이 로드된 베이스 주소에 해당합니다.

그다음 `commit_creds`라는 이름의 함수 주소를 `grep`으로 찾아 보세요. `0xffffffff8106e390`이 나올 것입니다. 이 함수에 `gdb`에서 브레이크포인트를 설정하고 실행을 계속합니다.
```
pwndbg> break *0xffffffff8106e390
pwndbg> conti
```
이 함수는 실제로 새 프로세스가 생성될 때 등 여러 상황에서 호출됩니다. 셸에서 `ls` 같은 명령을 실행하면 `gdb`가 브레이크포인트에 반응할 것입니다.

<center>
  <img src="img/commit_creds_bp.png" alt="commit_creds에서 브레이크포인트로 멈춘 모습" style="width:720px;">
</center>

첫 번째 인자인 `RDI`에는 커널 공간 포인터가 들어 있습니다. 이 포인터가 가리키는 메모리를 확인해 봅시다.

<center>
  <img src="img/commit_creds_rdi.png" alt="commit_creds에서 메모리 확인" style="width:620px;">
</center>

이처럼 커널 공간에서도 유저랜드와 같은 `gdb` 명령을 사용할 수 있습니다. `pwndbg` 같은 확장 기능도 쓸 수 있지만, 물론 커널 디버깅을 염두에 두고 작성되지 않은 기능은 제대로 동작하지 않을 수 있습니다.
커널 디버깅 기능이 [추가된 디버거](https://github.com/bata24/gef)도 있으니, 각자 취향에 맞는 디버거를 사용하면 됩니다.

## 드라이버 디버깅
이번에는 커널 모듈을 디버깅해 봅시다.
LK01에는 `vuln`이라는 이름의 커널 모듈이 로드되어 있습니다. 현재 로드된 모듈 목록과 베이스 주소는 `/proc/modules`에서 확인할 수 있습니다.

<center>
  <img src="img/modules.png" alt="/proc/modules의 내용" style="width:420px;">
</center>

이를 보면 `vuln` 모듈이 `0xffffffffc0000000`에 로드되어 있다는 것을 알 수 있습니다. 참고로 이 모듈의 소스 코드와 바이너리는 배포 파일의 `src` 디렉터리에 있습니다. 소스 코드의 상세 분석은 다른 장에서 하겠지만, 우선 이 모듈 함수에 브레이크포인트를 걸어 봅시다.
IDA 등으로 `src/vuln.ko`를 열어 보면 여러 함수가 보입니다. 예를 들어 `module_close`의 상대 주소는 `0x20f`입니다.

<center>
  <img src="img/module_close.png" alt="IDA에서 본 module_close 함수" style="width:360px;">
</center>

따라서 현재 커널 상에서는 `0xffffffffc0000000 + 0x20f` 위치에 이 함수의 시작이 있어야 합니다. 여기에 브레이크포인트를 걸어 봅시다.

<center>
  <img src="img/module_close_bp.png" alt="gdb에서 module_close에 브레이크포인트 설정" style="width:520px;">
</center>

자세한 내용은 다음 장에서 분석하겠지만, 이 모듈은 `/dev/holstein`이라는 파일에 매핑되어 있습니다. `cat` 명령을 사용하면 `module_close`가 호출됩니다. 브레이크포인트에서 멈추는지 확인해 보세요.

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="늑대" ></div>
  <p class="says">
    드라이버의 심볼 정보가 필요하다면 <code>add-symbol-file</code> 명령을 사용하면 돼. 첫 번째 인수에 로컬 드라이버 파일, 두 번째 인수에 베이스 주소를 넘기면 심볼 정보를 읽어 와서 함수 이름으로 브레이크포인트를 걸 수 있어.
  </p>
</div>

```
# cat /dev/holstein
```

`stepi`, `nexti` 같은 명령도 그대로 사용할 수 있습니다. 즉 커널 공간 디버깅은 attach 방법만 다를 뿐, 사용할 수 있는 명령이나 디버깅 방식 자체는 유저 공간과 거의 다르지 않습니다.

----

<div class="column" title="예제">
  이 장에서는 <code>commit_creds</code>에서 멈춘 뒤 RDI 레지스터가 가리키는 메모리 영역을 확인했습니다. 이번에는 일반 사용자 권한 셸(cttyhack에서 uid를 1337로 설정한 경우)에서 같은 작업을 해 봅시다.<br>또한 root 권한(uid=0)과 일반 사용자 권한(uid=1337 등)을 비교해서, <code>commit_creds</code>의 첫 번째 인자로 전달되는 데이터에 어떤 차이가 있는지 확인해 보세요.
</div>
