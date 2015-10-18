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
#include <sys/prctl.h>
#include <signal.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

void install_filter(void) {
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				(offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
				AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				(offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1,
				1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE)
	};

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

	// fork into tracee & tracer
	child = fork();

	if (child == 0) { // tracee
		ptrace(PTRACE_TRACEME, 0, NULL);

		install_filter();

		argv++;
		execvp(argv[0], argv); // execute tracee
	}
	else { // tracer
		int status;
		siginfo_t siginfo;

		waitpid(child, &status, 0); // wait for execve

		ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESECCOMP);

		ptrace(PTRACE_CONT, child, NULL, NULL);

		while (1) { // trace loop
			waitpid(child, &status, 0);

			if (WIFEXITED(status) || WIFSIGNALED(status))
				break;

			ptrace(PTRACE_GETSIGINFO, child, NULL, &siginfo);
			printf("signal %d ", siginfo.si_signo);

			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			printf("syscall %llu\n", regs.orig_rax);

			ptrace(PTRACE_CONT, child, NULL, NULL);
		}

		printf("\n");
	}

	return 0;
}
