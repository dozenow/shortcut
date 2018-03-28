#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main (int argc, char* argv[])
{
    int start_range = 1000;
    int stop_range = 9999;
    int status, rc;
    pid_t pid;

    do {
	pid = fork();
	if (pid == 0) return 0;
	rc = waitpid (pid, &status, 0);
	printf ("child %d created, wait rc = %d\n", pid, rc);
    } while (pid < start_range || pid > stop_range);

    return 0;
}
