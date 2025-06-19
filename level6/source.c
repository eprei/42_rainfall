#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void n(void)
{
  system("/bin/cat /home/user/level7/.pass");
  return;
}

void m()
{
  puts("Nope");
  return;
}

void main(int argc,char **argv)

{
  char *buffer;
  void (*function_pointer)(void);

  buffer = (char *)malloc(64);
  function_pointer = malloc(4);
  function_pointer = &m;
  strcpy(buffer,argv[1]);
  function_pointer();
  return;
}
