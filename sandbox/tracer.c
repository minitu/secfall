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
#include <sys/uio.h>

#define MAX_LINES   128
#define NO_TRACEE   "please specify tracee file\n"
#define WRONG_OPT   "wrong option: use -h for help\n"
#define POLICY_NEX  "policy file does not exist\n"
#define DOT_LINE     "-------------------------------------------------------------\n"

int line_count = 0;
char *line[MAX_LINES] = {NULL};
char *line_token[MAX_LINES][8] = {NULL};
int token_count[MAX_LINES] = {0};
size_t len[MAX_LINES] = {0};

void modify_regs_line(int line_num, unsigned long long int syscall, struct user_regs_struct *regs_p) {
	long ret = 0;
	long long int check = 0;

	// syscall no match
	if (strtoull(line_token[line_num][0], NULL, 0) != syscall)
		return;

	// change register values
	switch(token_count[line_num]) {
		case 8:
			if (strtoll(line_token[line_num][7], NULL, 0) != -1)
				regs_p->r9 = strtoull(line_token[line_num][7], NULL, 0);
		case 7:
			if (strtoll(line_token[line_num][6], NULL, 0) != -1)
				regs_p->r8 = strtoull(line_token[line_num][6], NULL, 0);
		case 6:
			if (strtoll(line_token[line_num][5], NULL, 0) != -1)
				regs_p->r10 = strtoull(line_token[line_num][5], NULL, 0);
		case 5:
			if (strtoll(line_token[line_num][4], NULL, 0) != -1)
				regs_p->rdx = strtoull(line_token[line_num][4], NULL, 0);
		case 4:
			if (strtoll(line_token[line_num][3], NULL, 0) != -1)
				regs_p->rsi = strtoull(line_token[line_num][3], NULL, 0);
		case 3:
			if (strtoll(line_token[line_num][2], NULL, 0) != -1)
				regs_p->rdi = strtoull(line_token[line_num][2], NULL, 0);
		case 2:
			if (strtoll(line_token[line_num][1], NULL, 0) != -1)
				regs_p->orig_rax = strtoull(line_token[line_num][1], NULL, 0);
			break;
		default:
			break;
	}
}

int main(int argc, char **argv) {
	pid_t child;
	struct user_regs_struct regs;
	int option = 0;
	int verbose = 0;
	int i = 0;
	

	if (argc < 2) {
		printf(NO_TRACEE);
		return -1;
	}

	if (strcmp(argv[1], "-v") == 0) {
		verbose = 1;
		argv++;
	}

	if (strcmp(argv[1], "-p") == 0) {
		FILE *fp;
		int j;
		char *l, *token[8], *saveptr;
		int tlen;

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

		for (i = 0; i < line_count; i++) {
			l = line[i];
			j = 0;

			while(1) {
				if (j >= 8)
					break;
				token[j] = strtok_r(l, " ", &saveptr);
				if (token[j] == NULL)
					break;
				tlen = strlen(token[j]);
				line_token[i][j] = malloc(sizeof(char) * (tlen + 1));
				strcpy(line_token[i][j], token[j]);
				l = NULL;
				j++;
			}

			token_count[i] = j;

			tlen = strlen(line_token[i][token_count[i]-1]);
			if (line_token[i][token_count[i]-1][tlen-1] = '\n')
				line_token[i][token_count[i]-1][tlen-1] = '\0';
		}

		option = 1;
		argv += 2;
	}
	else if (strcmp(argv[1], "-a") == 0) {
		option = 2;
		argv++;
	}
	else if (strcmp(argv[1], "-b") == 0) {
		option = 3;
		argv++;
	}
	else if (strcmp(argv[1], "-c") == 0) {
		option = 4;
		argv++;
	}
	else if (strcmp(argv[1], "-h") == 0) {
		printf("TRACER HELP\n\n");
		printf("\t-v\n");
		printf("\t\tVerbosely print tracee's system call numbers & arguments.\n");
		printf("\t\tCan be used with other options, but must be the first.\n\n");
		printf("\tOnly one of the options below should be used. (-a, -b, -c, -p)\n");
		printf("\t-a\n");
		printf("\t\tChange all writes' destinations to stdout.\n");
		printf("\t-b\n");
		printf("\t\tChange buffer content of writes to stdout to NULL.\n");
		printf("\t-c\n");
		printf("\t\tChange all wirtes to reads.\n");
		printf("\t-p [policy file]\n");
		printf("\t\tModify tracee's system calls according to given policy file.\n");
		printf("\t\tPolicy file is read line by line. For example, a line of\n");
		printf("\t\t'1 2 3 4' will modify system call #1 to #2, and modify the\n");
		printf("\t\tfirst and second arguments to 3 and 4, respectively. If an\n");
		printf("\t\targument is -1, it will be ignored. Only up to 6 arguments\n");
		printf("\t\tare allowed, and if the number of arguments do not match \n");
		printf("\t\tthe modified system call, it may not execute properly.\n\n");
		printf("\t-h\n\t\tShow help on command line options.\n\n");
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
		int has_return = 0;
		unsigned long long int r[6];

		if (verbose) {
			printf(DOT_LINE);
			printf("syscall #%6creturn value%10carguments\n", ' ', ' ');
			printf(DOT_LINE);
		}

		while (1) { // trace loop
			has_return = 0;

			waitpid(child, &status, 0);

			if (WIFEXITED(status) || WIFSIGNALED(status))
				break;

			ptrace(PTRACE_GETREGS, child, NULL, &regs);

			if ((regs.orig_rax == __NR_execve && regs.rax == 0)
					|| regs.orig_rax == __NR_exit
					|| regs.orig_rax == __NR_exit_group) { // syscalls with no return values

				if (option == 1) { // modify syscall
					for (i = 0; i < line_count; i++)
						modify_regs_line(i, regs.orig_rax, &regs);

					ptrace(PTRACE_SETREGS, child, NULL, &regs);
					ptrace(PTRACE_GETREGS, child, NULL, &regs);

					if (regs.orig_rax != __NR_execve && regs.orig_rax != __NR_exit
							&& regs.orig_rax != __NR_exit_group) {
						has_return = 1;
						in_syscall = 1;
					}
				}

				if (!has_return) {
					if (verbose) {
						printf("%-15llu", regs.orig_rax);

						printf("%-22s", "none");

						printf("rdi: 0x%llx\n", regs.rdi);
						printf("%37crsi: 0x%llx\n", ' ', regs.rsi);
						printf("%37crdx: 0x%llx\n", ' ', regs.rdx);
						printf("%37cr10: 0x%llx\n", ' ', regs.r10);
						printf("%37cr8:  0x%llx\n", ' ', regs.r8);
						printf("%37cr9:  0x%llx\n", ' ', regs.r9);
						printf(DOT_LINE);
					}
					else
						printf("%llu ", regs.orig_rax);
				}
				else {
					if (verbose) {
						printf("%-15llu", regs.orig_rax);

						r[0] = regs.rdi;
						r[1] = regs.rsi;
						r[2] = regs.rdx;
						r[3] = regs.r10;
						r[4] = regs.r8;
						r[5] = regs.r9;
					}
					else {
						printf("%llu ", regs.orig_rax);
					}
				}

			}
			else { // syscalls with entry & exit
				if (in_syscall == 0) { // syscall entry
					in_syscall = 1;

					if (option == 1) { // modify syscall
						for (i = 0; i < line_count; i++)
							modify_regs_line(i, regs.orig_rax, &regs);

						ptrace(PTRACE_SETREGS, child, NULL, &regs);
						ptrace(PTRACE_GETREGS, child, NULL, &regs);
					}
					else if (option == 2) { // write to stdout
						if (regs.orig_rax == __NR_write) {
							regs.rdi = STDOUT_FILENO;

							ptrace(PTRACE_SETREGS, child, NULL, &regs);
						}
					}
					else if (option == 3) { // nullify write buffer
						if (regs.orig_rax == __NR_write && regs.rdi == STDOUT_FILENO) {
							ptrace(PTRACE_POKEDATA, child, regs.rsi, 0x00);
						}
					}
					else if (option == 4) { // change writes to reads
						if (regs.orig_rax == __NR_write) {
							regs.orig_rax = __NR_read;

							ptrace(PTRACE_SETREGS, child, NULL, &regs);
						}
					}

					if (verbose) {
						printf("%-15llu", regs.orig_rax);

						r[0] = regs.rdi;
						r[1] = regs.rsi;
						r[2] = regs.rdx;
						r[3] = regs.r10;
						r[4] = regs.r8;
						r[5] = regs.r9;
					}
					else
						printf("%llu ", regs.orig_rax);
				}
				else { // syscall exit
					in_syscall = 0;

					if (verbose) {
						printf("0x%-20llx", regs.rax);

						printf("rdi: 0x%llx\n", r[0]);
						printf("%37crsi: 0x%llx\n", ' ', r[1]);
						printf("%37crdx: 0x%llx\n", ' ', r[2]);
						printf("%37cr10: 0x%llx\n", ' ', r[3]);
						printf("%37cr8:  0x%llx\n", ' ', r[4]);
						printf("%37cr9:  0x%llx\n", ' ', r[5]);
						printf(DOT_LINE);
					}
				}
			}

			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}

		if (!verbose)
			printf("\n");

		if (option == 1) {
			for (i = 0; i < line_count; i++) {
				free(line[i]);
			}
		}
	}

	return 0;
}
