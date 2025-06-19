#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void p(void)
{
  unsigned int return_address;
  char buffer [76];

  fflush(stdout);
  gets(buffer);
  if ((return_address & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n", return_address);
                        /* WARNING: Subroutine does not return */
    exit(1);
  }
  puts(buffer);
  strdup(buffer);
  return;
}

int main(void)
{
  p();
  return 0;
}
