#define _GNU_SOURCE
#include <stdlib.h> source.c
#include <string.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc,char **argv)

{
  int user_input;
  char *command;
  uid_t uid;
  gid_t gid;

  user_input = atoi(argv[1]);
  if (user_input == 423) {
    command = strdup("/bin/sh");
    gid = getegid();
    uid = geteuid();
    setresgid(gid,gid,gid);
    setresuid(uid,uid,uid);
    execv("/bin/sh",&command);
  }
  else {
    fwrite("No !\n",1,5,(FILE *)stderr);
  }
  return 0;
}
