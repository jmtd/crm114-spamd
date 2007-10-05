#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sysexits.h>
#include <sys/wait.h>
#include <ident.h>
#include <sys/socket.h>
#include <errno.h>

static void ERROR(int code, char *descr)
{
	printf("SPAMD/1.1 %d %s\r\n", code, descr);
	fflush(stdout);
	exit(0);
}

static int read_stdin_line(char *buf, int bufsize)
{
	int i = 0;
	unsigned char c;

	while (1) {
		if (read(0, &c, 1) != 1)
			ERROR(EX_PROTOCOL, "unexpected end of input");
		if (i >= bufsize - 1)
			ERROR(EX_PROTOCOL, "line too long");
		buf[i] = c;
		i++;
		if (c == '\n') {
			buf[i-1] = '\0';
			break;
		}
	}

	return i;
}

int main(int argc, char **argv)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	struct passwd *ps;
	char *id;
	char buf[20000];
	char cmd[50];
	char version[50];
	char user[50];
	int length, res;
	int crm_out[2];
	pid_t pid;
	char *statusline, status[100];
	float score;

	if (argc < 2)
		ERROR(EX_PROTOCOL, "need mailreaver binary");
	if (argc > 2)
		chdir(argv[2]);

	if (getpeername(0, (struct sockaddr *)&addr, &addrlen)) {
		if (errno == ENOTSOCK) {
			/* most likely started from terminal */
			ps = getpwuid(getuid());
			if (ps) {
				id = ps->pw_name;
				goto cont_after_permcheck;
			}
			ERROR(EX_NOPERM, "couldn't look up your username");
		}
		ERROR(EX_NOPERM, "couldn't look up your host address");
	}
	if (addr.sin_family != AF_INET
	    || addr.sin_addr.s_addr != htonl(0x7f000001))
		ERROR(EX_NOPERM, "not connected from localhost");
	id = ident_id(0, 30);
	if (!id)
		ERROR(EX_NOPERM, "permission denied, run an ident server");

 cont_after_permcheck:
	signal(SIGPIPE, SIG_IGN);
	/* read command */
	read_stdin_line(buf, sizeof(buf));

	if (sscanf(buf, "%s SPAMC/%s", cmd, version) != 2)
		ERROR(EX_PROTOCOL, "invalid input line (cmd)");
	if (strcmp(cmd, "REPORT"))
		ERROR(EX_PROTOCOL, "can only handle REPORT query");
	if (strcmp(version, "1.2") != 0)
		ERROR(EX_PROTOCOL, "can only handle version 1.2");

	/* read user line */
	read_stdin_line(buf, sizeof(buf));
	if (sscanf(buf, "User: %s", user) < 1)
		ERROR(EX_PROTOCOL, "invalid input line (user)");

	/* allow root and Debian-exim to check for anyone */
	if (strcmp(id, user) &&
	    strcmp(id, "root") && strcmp(id, "Debian-exim"))
		ERROR(EX_NOPERM, "you can only check spam for yourself"
		      "(unless priviledged)");

	ps = getpwnam(user);
	if (!ps)
		ERROR(EX_TEMPFAIL, "user not found");
	if (setuid(ps->pw_uid))
		ERROR(EX_TEMPFAIL, "cannot setuid");
	setenv("HOME", ps->pw_dir, 1);

	/* read content-length line */
	read_stdin_line(buf, sizeof(buf));
	if (sscanf(buf, "Content-length: %d", &length) != 1)
		ERROR(EX_PROTOCOL, "invalid input line (length)");

	/* now an empty line */
	read_stdin_line(buf, sizeof(buf));
	if (strlen(buf) == 1 && buf[0] == '\r')
		buf[0] = '\0';
	if (strlen(buf))
		ERROR(EX_PROTOCOL, "expected empty line");

	if (pipe(crm_out))
		ERROR(EX_TEMPFAIL, "failed to create pipe");

	pid = fork();
	if (pid < 0)
		ERROR(EX_TEMPFAIL, "failed to fork");

	if (pid == 0) {
		/* in child */
		close(1);
		close(2);
		close(crm_out[0]);
		dup2(crm_out[1], 1);
		dup2(crm_out[1], 2);
		close(crm_out[1]);

		execl(argv[1], argv[1], "--report_only", NULL);
		return 1;
	}

	/* parent */

	/* close stdin, rest of data goes to crm114 now */
	close(0);
	/* close child end of pipe */
	close(crm_out[1]);

	length = 0;
	res = 1;
	while (res > 0) {
		res = read(crm_out[0], buf + length, sizeof(buf) - length);
		if (res > 0)
			length += res;
		if (res < 0 && errno != EINTR)
			ERROR(EX_TEMPFAIL, "failed to read data from crm");
	}
	buf[length] = '\0';

	if (waitpid(pid, &res, 0) != pid)
		ERROR(EX_TEMPFAIL, "failed to wait for crm114");

	if (!WIFEXITED(res) || WEXITSTATUS(res))
		ERROR(EX_TEMPFAIL, "crm114 failed");

	statusline = strstr(buf, "X-CRM114-Status: ");
	if (!statusline)
		ERROR(EX_TEMPFAIL, "crm114 didn't give status");

	sscanf(statusline, "X-CRM114-Status: %s ( %f )", status, &score);

	printf("SPAMD/1.2 0 EX_OK\r\n");
	printf("Spam: %s ; %.2f / %.2f\r\n", status, -score, 0.0);
	printf("\r\n");

	printf("%s", buf);

	/* always return ok status to (x)inetd */
	return 0;
}
