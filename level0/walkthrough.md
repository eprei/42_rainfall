# Walkthrough for Level 0

The information displayed immediately after logging in is caused by the execution of `checksec`, as specified in the
user's `.bashrc` file. `Checksec` is a bash script used to check the security properties of executables (such as PIE,
RELRO, PaX, Canaries, ASLR, Fortify Source), library calls (Fortify Source), and kernel security options (such as
GRSECURITY and SELinux). In this case, it is used to show the security properties of the `level1` binary.

```shell
└─$ ssh -p 4242 level0@192.168.56.6
	  _____       _       ______    _ _
	 |  __ \     (_)     |  ____|  | | |
	 | |__) |__ _ _ _ __ | |__ __ _| | |
	 |  _  /  _` | | '_ \|  __/ _` | | |
	 | | \ \ (_| | | | | | | | (_| | | |
	 |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                 Good luck & Have fun

  To start, ssh with level0/level0 on 192.168.56.6:4242
Load key "/home/kali/.ssh/id_rsa": error in libcrypto
level0@192.168.56.6's password:
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/level0/level0
level0@RainFall:~$ cat .bashrc | grep checksec
checksec --file /home/user/level0/level0
```

In the level0 user's home directory, we find that the level0 binary belongs to the user level1 and has the SUID bit set,
which means it will run with the permissions of its owner (level1) when executed by any user.

```shell
level0@RainFall:~$ ls -l
total 732
-rwsr-x---+ 1 level1 users 747441 Mar  6  2016 level0
```

To understand how this binary works, we need to decompile it, and for this task we use `ghidra`.
After renaming some variables to make the code more readable, we discover the logic behind this program.
`level0` takes an argument and checks if it is equal to 0x1a7 (423 in decimal). If this is the case, it will spawn a shell.
Since `level0` has the SUID bit set, the resulting shell will run with the permissions of `level1`.

```shell
level0@RainFall:~$ ./level0 423
$ whoami
level1
```

From here, we can read the `.pass` file of `level1`.

```shell
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

We can now exit the shell and switch to `level1` using the password we just found.

```shell
$ exit
level0@RainFall:~$ su level1
Password:
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level1/level1
level1@RainFall:~$
```

```shell
level1@RainFall:~$ cat .bashrc | grep checksec
checksec --file /home/user/level1/level1
```