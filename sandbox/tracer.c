#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <asm/ptrace-abi.h>
#include <wait.h>
#include <stdlib.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
    pid_t child;
    struct user_regs_struct regs;
    int i;

    child = fork();

    if (child == 0) { // tracee
        ptrace(PTRACE_TRACEME, 0, NULL);
        argv++;
        execvp(argv[0], argv); // execute tracee
    }
    else { // tracer
        int status;
        int in_syscall = 0;
        unsigned long long int r[6];

        // print headers
        printf("---------------------------------------------------------\n");
        printf("syscall #%6creturn value%10carguments\n", ' ', ' ');
        printf("---------------------------------------------------------\n");

        while (1) {
            waitpid(child, &status, 0); // wait for tracee to stop

            if (WIFEXITED(status) || WIFSIGNALED(status)) // quit if tracee exits
                break;

            ptrace(PTRACE_GETREGS, child, NULL, &regs); // get tracee's register values

            if ((regs.orig_rax == __NR_execve && regs.rax == 0) || regs.orig_rax == __NR_exit
                    || regs.orig_rax == __NR_exit_group) { // syscalls with no return values
                printf("%-15llu", regs.orig_rax); // print syscall #

                printf("%-22s", "none"); // no return value

                // print arguments
                printf("0x%llx\n", regs.rdi);
                printf("%37c0x%llx\n", ' ', regs.rsi);
                printf("%37c0x%llx\n", ' ', regs.rdx);
                printf("%37c0x%llx\n", ' ', regs.r10);
                printf("%37c0x%llx\n", ' ', regs.r8);
                printf("%37c0x%llx\n", ' ', regs.r9);
                printf("---------------------------------------------------------\n");
            }
            else {
                if (in_syscall == 0) { // syscall entry
                    in_syscall = 1;

                    printf("%-15llu", regs.orig_rax); // print syscall #

                    // save argument registers
                    r[0] = regs.rdi;
                    r[1] = regs.rsi;
                    r[2] = regs.rdx;
                    r[3] = regs.r10;
                    r[4] = regs.r8;
                    r[5] = regs.r9;
                }
                else { // syscall exit
                    in_syscall = 0;

                    printf("0x%-20llx", regs.rax); // print return value

                    // print arguments
                    printf("0x%llx\n", r[0]);
                    for (i = 1; i < 6; i++) {
                        printf("%37c0x%llx\n", ' ', r[i]);
                    }
                    printf("---------------------------------------------------------\n");
                }
            }


            /*
            if (regs.orig_rax == SYS_write) {
                if (in_syscall == 0) {
                    in_syscall = 1;
                    printf("write entry\t");
                    printf("write(%llu, %p, %llu)\n", regs.rdi, regs.rsi, regs.rdx);

                    regs.rdi = STDOUT_FILENO;
                    ptrace(PTRACE_SETREGS, child, NULL, &regs);

                    char data = 'B';
                    ptrace(PTRACE_POKEDATA, child, regs.rsi, &data); // rsi change?
                }
                else {
                    in_syscall = 0;
                    printf("write exit\t");
                    printf("rax: %llu\n", regs.orig_rax); // syscall value
                }
            }
            */

            ptrace(PTRACE_SYSCALL, child, NULL, NULL); // stop at next syscall (includes CONT)
        }
        //printf("tracee exited\n");
    }

    return 0;
}
