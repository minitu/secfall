#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>

int main() {
    pid_t child;
    long orig_rax;
    
    child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // this stops the child
        execl("/bin/ls", "ls", NULL);
        // UNREACHABLE
    }
    else {
        wait(NULL); // wait for child to stop
        orig_rax = ptrace(PTRACE_PEEKUSER, // start tracing
                child, 8 * ORIG_RAX,
                NULL);
        printf("The child made a "
                "system call %ld\n", orig_rax);
        ptrace(PTRACE_CONT, child, NULL, NULL);
    }
    return 0;
}
