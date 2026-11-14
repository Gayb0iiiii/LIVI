#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    setbuf(stdout, NULL);
    if (setpgid(0, 0)) return 1;
    int ready[2]; if (pipe(ready)) return 1;
    pid_t p = fork();
    if (p < 0) return 1;
    if (!p) {
        close(ready[0]);
        int f = open("/dev/null", O_RDONLY);
        if (f < 0 || dup2(f, 13) < 0) _exit(2);
        if (f != 13) close(f);
        if (write(ready[1], "R", 1) != 1) _exit(3);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    char mark; if (read(ready[0], &mark, 1) != 1 || mark != 'R') return 2;
    close(ready[0]);
    printf("%ld %ld\n", (long)getpid(), (long)p);
    for (;;) { int status; if (waitpid(p, &status, 0) == p) return 0; }
}
