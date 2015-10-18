#include <stdio.h>
#include <stddef.h>
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
#include <signal.h>
#include <sys/prctl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define MAX_REJECTS		1024
#define NUM_FILE		57
#define NUM_IPC			12
#define NUM_NETWORK		19
#define NUM_PROCESS		11
#define NUM_SIGNAL		15
#define NUM_DESC		86
#define NUM_MEMORY		20

#define MAX_LINES   128
#define NO_TARGET   "please specify target file\n"
#define WRONG_OPT   "wrong option: use -h for help\n"
#define POLICY_NEX  "policy file does not exist\n"
#define POLICY_NG	"wrong policy format\n"
#define DOT_LINE     "-------------------------------------------------------------\n"
#define SC_DETECT	"WARNING: DISABLED SYSTEM CALL"
#define SC_KILL		"WARNING: KILLING CHILD\n"

unsigned long long int sc_file[NUM_FILE] = {2, 4, 6, 21, 59, 76, 79, 80, 82, 83, 84, 85,
	86, 87, 88, 89, 90, 92, 94, 132, 133, 134, 137, 155, 161, 163, 165, 166, 167, 168,
	179, 188, 189, 191, 192, 194, 195, 197, 198, 235, 257, 258, 259, 260, 261, 262, 263,
	264, 265, 266, 267, 268, 269, 280, 301, 303, 316};
unsigned long long int sc_ipc[NUM_IPC] = {29, 30, 31, 64, 65, 66, 67, 68, 69, 70, 71, 220};
unsigned long long int sc_network[NUM_NETWORK] = {40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
	50, 51, 52, 53, 54, 55, 288, 299, 307};
unsigned long long int sc_process[NUM_PROCESS] = {56, 57, 58, 59, 60, 61, 158, 231, 247,
	272, 297};
unsigned long long int sc_signal[NUM_SIGNAL] = {13, 14, 15, 34, 62, 127, 128, 129, 130, 131,
	200, 234, 282, 289, 297};
unsigned long long int sc_desc[NUM_DESC] = {0, 1, 2, 3, 5, 7, 8, 9, 16, 17, 18, 19, 20, 22,
	23, 32, 33, 40, 72, 73, 74, 75, 77, 78, 81, 85, 91, 93, 138, 187, 190, 193, 196, 199,
	213, 217, 221, 232, 233, 253, 254, 255, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266,
	267, 268, 269, 270, 271, 275, 276, 277, 278, 280, 281, 282, 283, 284, 285, 286, 287, 289,
	290, 291, 292, 293, 294, 295, 296, 298, 300, 301, 303, 304, 306, 308, 313, 316};
unsigned long long int sc_memory[NUM_MEMORY] = {9, 10, 11, 12, 25, 26, 27, 28, 30, 67, 149,
	150, 151, 152, 216, 237, 238, 239, 256, 279};

unsigned long long int rejects[MAX_REJECTS];
int reject_count = 0;

char *line[MAX_LINES] = {NULL};
int line_count = 0;
size_t len[MAX_LINES] = {0};

void install_filter() {
	int i;
	struct sock_filter filter[4 + 2*reject_count + 1];

	filter[0] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			(offsetof(struct seccomp_data, arch)));
	filter[1] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
			AUDIT_ARCH_X86_64, 1, 0);
	filter[2] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
	filter[3] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			(offsetof(struct seccomp_data, nr)));

	for (i = 0; i < reject_count; i++) {
		if (rejects[i] == __NR_execve)
			rejects[i] = -1;
		filter[4 + 2*i] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, rejects[i],
				0, 1);
		filter[4 + 2*i + 1] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE);
	}
	filter[4 + 2*reject_count] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

	struct sock_fprog prog = {
		.len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int main(int argc, char **argv) {
	pid_t child;
	struct user_regs_struct regs;
	int verbose = 0;
	int seccomp = 0;
	int policy = 0;
	int killflag = 0;
	int flags[7] = {1, 1, 1, 0, 0, 0, 1}; // disable filesystem, network, IPC, memory mapping syscalls by default
	int i = 0, j = 0;

	if (argc < 2) {
		printf(NO_TARGET);
		return -1;
	}

	if (strcmp(argv[1], "-v") == 0) {
		verbose = 1;
		argv++;
	}

	if (strcmp(argv[1], "-s") == 0) {
		seccomp = 1;
		argv++;
	}

	if (strcmp(argv[1], "-d") == 0) {
		killflag = 0;
		argv++;
	}
	else if (strcmp(argv[1], "-e") == 0) {
		killflag = 1;
		argv++;
	}

	if (strcmp(argv[1], "-p") == 0) {
		FILE *fp;
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

		if (line_count != 1 && line_count != 2) {
			printf(POLICY_NG);
			return -1;
		}

		tlen = strlen(line[0]);

		if (tlen != 7 && tlen != 8) {
			printf(POLICY_NG);
			return -1;
		}

		for (i = 0; i < 7; i++) {
			if (line[0][i] == '0')
				flags[i] = 0;
		}

		if (line_count == 2) {
			l = line[1];
			j = 0;

			while (1) {
				if (j >= MAX_REJECTS) {
					printf(POLICY_NG);
					return -1;
				}
				token[j] = strtok_r(l, " ", &saveptr);
				if (token[j] == NULL)
					break;
				rejects[j] = strtoull(token[j], NULL, 0);
				reject_count++;
				l = NULL;
				j++;
			}
		}

		policy = 1;
		argv += 2;
	}
	else if (strcmp(argv[1], "-h") == 0) {
		printf("SANDBOX HELP\n\n");
		printf("\tOptions must be placed in the order stated below, but\n");
		printf("\t-h should be used independently.\n\n");
		printf("\t-v\n");
		printf("\t\tVerbosely print system call numbers & arguments.\n\n");
		printf("\t-s\n");
		printf("\t\tUse seccomp to filter system calls at the kernel level.\n\n");
		printf("\t-d/-e\n");
		printf("\t\tContinue/terminate target program after printing out\n");
		printf("\t\tsystem call information.\n\n");
		printf("\t-p [policy file]\n");
		printf("\t\tAllow/disallow system calls according to policy file.\n");
		printf("\t\tFirst line should be a binary of 7 digits, for example\n");
		printf("\t\t1010001. The digits represent the 7 system call types:\n");
		printf("\t\tFILE, IPC, NETWORK, PROCESS, SIGNAL, DESC, and MEMORY.\n");
		printf("\t\tA 1 will disallow the set of system calls, and 0 will\n");
		printf("\t\tallow them. Second line is optional; if given, it is \n");
		printf("\t\ta set of system call numbers to be disallowed; space\n");
		printf("\t\tacting as the delimiter.\n\n");
		printf("\t-h\n\t\tShow help on command line options.\n\n");
		return 0;
	}
	else if (argv[1][0] == '-') {
		printf(WRONG_OPT);
		return -1;
	}

	if (flags[0] == 1) {
		printf("DISABLED: file system calls\n");
		for (i = 0; i < NUM_FILE; i++, j++) {
			rejects[j] = sc_file[i];
			reject_count++;
		}
	}
	if (flags[1] == 1) {
		printf("DISABLED: IPC system calls\n");
		for (i = 0; i < NUM_IPC; i++, j++) {
			rejects[j] = sc_ipc[i];
			reject_count++;
		}
	}
	if (flags[2] == 1) {
		printf("DISABLED: NETWORK system calls\n");
		for (i = 0; i < NUM_NETWORK; i++, j++) {
			rejects[j] = sc_network[i];
			reject_count++;
		}
	}
	if (flags[3] == 1) {
		printf("DISABLED: PROCESS system calls\n");
		for (i = 0; i < NUM_PROCESS; i++, j++) {
			rejects[j] = sc_process[i];
			reject_count++;
		}
	}
	if (flags[4] == 1) {
		printf("DISABLED: SIGNAL system calls\n");
		for (i = 0; i < NUM_SIGNAL; i++, j++) {
			rejects[j] = sc_signal[i];
			reject_count++;
		}
	}
	if (flags[5] == 1) {
		printf("DISABLED: DESC system calls\n");
		for (i = 0; i < NUM_DESC; i++, j++) {
			rejects[j] = sc_desc[i];
			reject_count++;
		}
	}
	if (flags[6] == 1) {
		printf("DISABLED: MEMORY system calls\n");
		for (i = 0; i < NUM_MEMORY; i++, j++) {
			rejects[j] = sc_memory[i];
			reject_count++;
		}
	}

	// fork into tracee & tracer
	child = fork();

	if (child == 0) { // tracee
		ptrace(PTRACE_TRACEME, 0, NULL);

		if (seccomp)
			install_filter(); // install seccomp/BPF filter

		argv++;
		execvp(argv[0], argv); // execute tracee
	}
	else { // tracer
		int status;
		int detect = 0;
		int in_syscall = 0;
		unsigned long long int r[6];

		if (verbose) {
			printf(DOT_LINE);
			printf("syscall #%6creturn value%10carguments\n", ' ', ' ');
			printf(DOT_LINE);
		}

		if (seccomp) {
			waitpid(child, &status, 0); // wait for execve

			ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESECCOMP);

			// check if execve is disallowed
			for (i = 0; i < reject_count; i++) {
				if (rejects[i] == __NR_execve) {

					if (verbose) {
						printf("%-15d", __NR_execve);
						printf("%-22s", "none");
						printf("\n");
						printf(DOT_LINE);
					}
					else
						printf("%d ", __NR_execve);

					if (killflag) {
						kill(child, SIGKILL);
						printf(SC_KILL);
						return 0;
					}

					break;
				}
			}

			ptrace(PTRACE_CONT, child, NULL, NULL);
		}

		while (1) { // trace loop
			detect = 0;

			waitpid(child, &status, 0);

			if (WIFEXITED(status) || WIFSIGNALED(status))
				break;

			ptrace(PTRACE_GETREGS, child, NULL, &regs);

			if (!seccomp) { // no seccomp
				for (i = 0; i < reject_count; i++) {
					if (regs.orig_rax == rejects[i]) {
						detect = 1;
						break;
					}
				}

				if ((regs.orig_rax == __NR_execve && regs.rax == 0)
						|| regs.orig_rax == __NR_exit
						|| regs.orig_rax == __NR_exit_group) { // syscalls with no return values

					if (verbose) {
						if (detect)
							printf(SC_DETECT"\n");
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
					else {
						printf("%llu ", regs.orig_rax);
						if (detect)
							printf(SC_DETECT"\n");
					}

					if (detect && killflag) {
						kill(child, SIGKILL);
						printf(SC_KILL);
					}
				}
				else { // syscalls with entry & exit
					if (in_syscall == 0) { // syscall entry
						in_syscall = 1;

						if (verbose) {
							if (detect)
								printf(SC_DETECT"\n");
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
							if (detect)
								printf(SC_DETECT"\n");
						}

						if (detect && killflag) {
							kill(child, SIGKILL);
							if (verbose)
								printf("\n");
							printf(SC_KILL);
							return 0;
						}
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
			else { // seccomp

				if (verbose) {
						printf("%-15llu", regs.orig_rax);
						printf("%-22s", "unknown");
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

				if (killflag) {
					kill(child, SIGKILL);
					printf(SC_KILL);
				}

				ptrace(PTRACE_CONT, child, NULL, NULL);
			}
		}

		if (!verbose)
			printf("\n");

		if (policy) {
			for (i = 0; i < line_count; i++) {
				free(line[i]);
			}
		}
	}

	return 0;
}
