#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

char c[68];

void m()
{
  time_t t;

  t = time((time_t *)0);
  printf("%s - %d\n",c,t);
  return;
}

int main(int argc,char **argv)
{
  char **heap_1;
  char *tmp_pointer;
  char **heap_2;
  FILE *password_file;

  heap_1 = (char **)malloc(8);
  heap_1[0] = (char *)1;
  tmp_pointer = malloc(8);
  heap_1[1] = tmp_pointer;

  heap_2 = (char **)malloc(8);
  heap_2[0] = (char *)2;
  tmp_pointer = malloc(8);
  heap_2[1] = tmp_pointer;

  strcpy(heap_1[1],argv[1]);
  strcpy(heap_2[1],argv[2]);

  password_file = fopen("/home/user/level8/.pass","r");
  fgets(c,68,password_file);
  puts("~~");

  return 0;
}
