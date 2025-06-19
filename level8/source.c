#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth = NULL;
char *service = NULL;

int main(void) {
    char buffer[8];

    while (1) {
        printf("%p, %p \n", auth, service);

        if (!fgets(buffer, sizeof(buffer), stdin))
            break;

        else if (strncmp(buffer, "auth ", 5) == 0) {
            auth = malloc(4);
            bzero(auth, 4);
            if (strlen(buffer + 5) < 31) {
                strcpy(auth, buffer + 5);
            }
        }

        else if (strncmp(buffer, "reset", 5) == 0) {
            free(auth);
        }

        else if (strncmp(buffer, "service", 7) == 0) {
            service = strdup(buffer + 8);
        }

        else if (strncmp(buffer, "login", 5) == 0) {
            if (*(int*)(auth + 32) == 0) {
                puts("Password:");
            } else {
                system("/bin/sh");
            }
        }
    }
}