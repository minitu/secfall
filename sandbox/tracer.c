#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <asm/ptrace-abi.h>
#include <wait.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>

#define MAX_LINES   128
#define WRONG_OPT   "wrong option: use -h for help\n"
#define POLICY_NEX  "policy file does not exist\n"
#define DOT_LINE     "-------------------------------------------------------------\n"
    
int line_count = 0;
char *line[MAX_LINES] = {NULL};
size_t len[MAX_LINES] = {0};

void change_regs(unsigned long long int syscall, int line_num, 
        struct user_regs_struct *regs_p) {
    long ret = 0;
    char *l = line[line_num];
    char *token[8], *orig_token[8], *saveptr;
    int i = 0;
    int token_count = 0;
    int tlen;

    // parse line
    while (1) {
        if (i >= 8)
            break;
        orig_token[i] = strtok_r(l, " ", &saveptr);
        if (orig_token[i] == NULL)
            break;
        tlen = strlen(orig_token[i]);
        token[i] = malloc(sizeof(char) * (tlen + 1));
        strcpy(token[i], orig_token[i]);
        l = NULL;
        i++;
    }

    token_count = i;

    // remove newline character
    tlen = strlen(token[token_count-1]);
    token[token_count-1][tlen-1] = '\0';

    // DEBUG
    for (i = 0; i < token_count; i++) {
        printf("%s\n", token[i]);
    }

    // syscall no match
    if (strtoull(token[0], NULL, 0) != syscall)
        return;

    // change register values
    switch(token_count) {
        case 8:
            regs_p->r9 = strtoull(token[7], NULL, 0);
        case 7:
            regs_p->r8 = strtoull(token[6], NULL, 0);
        case 6:
            regs_p->r10 = strtoull(token[5], NULL, 0);
        case 5:
            regs_p->rdx = strtoull(token[4], NULL, 0);
        case 4:
            regs_p->rsi = strtoull(token[3], NULL, 0);
        case 3:
            regs_p->rdi = strtoull(token[2], NULL, 0);
        case 2:
            regs_p->orig_rax = strtoull(token[1], NULL, 0); // TODO: correct?
            break;
        default:
            break;
    }
}

int main(int argc, char **argv) {
    pid_t child;
    struct user_regs_struct regs;
    int option = 0;
    int i = 0;
    FILE *fp;

    if (argc < 2)
        return -1;

    if (strcmp(argv[1], "-p") == 0) {
        if (argc < 3)
            return -1;

        argv++;
    }
    else if (strcmp(argv[1], "-c") == 0) {
        if (argc <= 3) {
            printf(WRONG_OPT);
            return -1;
        }

        // read policy file
        fp = fopen(argv[2], "r");
        if (fp == NULL) {
            printf(POLICY_NEX);
            return -1;
        }

        while (getline(&line[i], &len[i], fp) != -1) {
            i++;
        }
        line_count = i;

        fclose(fp);

        option = 1;
        argv += 2;
    }
    else if (strcmp(argv[1], "-w") == 0) {
        if (argc <= 3)
            return -1;

        // TODO

        option = 2;
        argv += 2;
    }
    else if (strcmp(argv[1], "-h") == 0) {
        printf("TRACER HELP\n\n\t-p [tracee]\n");
        printf("\t\tprints out system call numbers and their arguments\n\n");
        printf("\t-c [policy file] [tracee]\n");
        printf("\t\tchanges system calls according to given policy file\n\n");
        printf("\t-w [policy file] [tracee]\n");
        printf("\t\toverwrites memory address according to given policy file\n\n");
        printf("\t-h\n\t\tshow options\n\n");
        return 0;
    }
    else if (argv[1][0] == '-') {
        printf(WRONG_OPT);
        return -1;
    }

    // fork into tracee & tracer
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
        printf(DOT_LINE);
        printf("syscall #%6creturn value%10carguments\n", ' ', ' ');
        printf(DOT_LINE);

        while (1) {
            waitpid(child, &status, 0); // wait for tracee to stop

            if (WIFEXITED(status) || WIFSIGNALED(status)) // quit if tracee exits
                break;

            ptrace(PTRACE_GETREGS, child, NULL, &regs); // get tracee's register values

            if ((regs.orig_rax == __NR_execve && regs.rax == 0) || regs.orig_rax == __NR_exit
                    || regs.orig_rax == __NR_exit_group) { // syscalls with no return values

                // change syscall # and/or arguments TODO call only once per syscall
                if (option == 1) {
                    for (i = 0; i < line_count; i++) {
                        change_regs(regs.orig_rax, i, &regs);
                    }
                    ptrace(PTRACE_SETREGS, child, NULL, &regs);

                    ptrace(PTRACE_GETREGS, child, NULL, &regs); // make sure change was correct
                }

                printf("%-15llu", regs.orig_rax); // print syscall #

                printf("%-22s", "none"); // no return value

                // print arguments
                printf("rdi: 0x%llx\n", regs.rdi);
                printf("%37crsi: 0x%llx\n", ' ', regs.rsi);
                printf("%37crdx: 0x%llx\n", ' ', regs.rdx);
                printf("%37cr10: 0x%llx\n", ' ', regs.r10);
                printf("%37cr8:  0x%llx\n", ' ', regs.r8);
                printf("%37cr9:  0x%llx\n", ' ', regs.r9);
                printf(DOT_LINE);
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
                    printf("rdi: 0x%llx\n", r[0]);
                    printf("%37crsi: 0x%llx\n", ' ', r[1]);
                    printf("%37crdx: 0x%llx\n", ' ', r[2]);
                    printf("%37cr10: 0x%llx\n", ' ', r[3]);
                    printf("%37cr8:  0x%llx\n", ' ', r[4]);
                    printf("%37cr9:  0x%llx\n", ' ', r[5]);
                    printf(DOT_LINE);
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
    }

    return 0;
}
