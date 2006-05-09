#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sysexits.h>
#include <sys/wait.h>

#define ERROR(code,descr) do {						\
		printf("SPAMD/1.1 %d %s\r\n", code, descr);		\
		exit(0);						\
	} while (0)

#define MAXSIZE	(5*1024*1024)

/* we have no arguments ... */
int main() {
	char buf[200];
	char cmd[50];
	char version[50];
	char user[50], userarg[60];
	char *message;
	int length;
	int fork_result;
	int dspam_in[2], dspam_out[2], dspam_err[2];
	int status;
	char *lflf, *crlfcrlf;


	signal(SIGPIPE, SIG_IGN);
	/* read command */
	fgets(buf, sizeof(buf), stdin);
	buf[sizeof(buf)-1] = '\0';
	if (strlen(buf) > 50)
		ERROR(EX_PROTOCOL, "line too long");

	if (sscanf(buf, "%s SPAMC/%s", cmd, version) != 2) {
		ERROR(EX_PROTOCOL, "invalid input line");
	}
	if (strcmp(cmd, "PROCESS") != 0)
		ERROR(EX_PROTOCOL, "can only handle PROCESS");
	if (strcmp(version, "1.2") != 0)
		ERROR(EX_PROTOCOL, "can only handle version 1.2");

	/* read content-length line */
	fgets(buf, sizeof(buf), stdin);
	buf[sizeof(buf)-1] = '\0';
	if (strlen(buf) > 50)
		ERROR(EX_PROTOCOL, "line too long");

	if (sscanf(buf, "Content-Length: %d", &length) != 1)
		ERROR(EX_PROTOCOL, "invalid input line");

	/* read user line */
	fgets(buf, sizeof(buf), stdin);
	buf[sizeof(buf)-1] = '\0';
	if (strlen(buf) > 50)
		ERROR(EX_PROTOCOL, "line too long");

	if (sscanf(buf, "User: %s", user) != 1)
		ERROR(EX_PROTOCOL, "invalid input line");

	struct passwd *ps;
	ps = getpwnam(user);
	if (!ps)
		ERROR(EX_TEMPFAIL, "user not found");
	if (!setuid(ps->pw_uid))
		ERROR(EX_TEMPFAIL, "cannot setuid");

	/* now an empty line */
	fgets(buf, sizeof(buf), stdin);
	buf[sizeof(buf)-1] = '\0';
	if (buf[1] == '\n') {
		buf[1] = '\0';
		if (buf[0] == '\r')
			buf[0] = '\0';
	}
	if (strlen(buf) > 2)
		ERROR(EX_PROTOCOL, "expected empty line");

	/* now read the message */
	if (length > MAXSIZE)
		ERROR(EX_IOERR, "message too big");

	message = malloc(length+1);
	fread(message, 1, length, stdin);
	fclose(stdin);

	if (pipe(dspam_in) || pipe(dspam_out) || pipe(dspam_err))
		ERROR(EX_TEMPFAIL, "failed to create pipes");

	fork_result = fork();
	if (fork_result < 0)
		ERROR(EX_TEMPFAIL, "failed to fork");

	if (fork_result == 0) {
		close(dspam_in[1]);
		close(dspam_out[0]);
		close(dspam_err[0]);
		dup2(dspam_in[0], 0);
		dup2(dspam_out[1], 1);
		dup2(dspam_err[1], 2);
		sprintf(userarg, "--user=%s", user);
		execl("/usr/bin/dspam", "/usr/bin/dspam", "--mode=toe", "--deliver=innocent,spam", "--stdout", userarg, NULL);
		return 1;
	}

	FILE *fdspam_in, *fdspam_out, *fdspam_err;
	/* assume that at most 1024 bytes are added */
	char *processed = malloc(length+1024+2);
	char dspamresult[1024], *dspamres = dspamresult;
	char *tmp = processed+1, *tmp2;
	int readlen = 0;

	/* dirty trick */
	*processed = '\n';

	close(dspam_in[0]);
	close(dspam_out[1]);
	close(dspam_err[1]);

	fdspam_in = fdopen(dspam_in[1], "w");
	fdspam_out = fdopen(dspam_out[0], "r");
	fdspam_err = fdopen(dspam_err[0], "r");

	fwrite(message, length, 1, fdspam_in);
	fclose(fdspam_in);

	while (!feof(fdspam_out)) {
		int r;
		r = fread(tmp, 1, length+1024-readlen, fdspam_out);
		if (r==0) break;
		readlen += r;
		tmp += r;
		if (readlen == length+1024) {
			/* too long! */
			fclose(fdspam_out);
			/* leave zombie around */
			ERROR(EX_TEMPFAIL, "dspam inflated message too much");
		}
	}

	/* rely on the fact that dspam doesn't dump a lot of data on stderr */
	if (length = fread(buf, 1, sizeof(buf), fdspam_err))
		ERROR(EX_TEMPFAIL, "dspam printed something to stderr");

	status = 0;
	waitpid(fork_result, &status, 0);
	if (!(WIFEXITED(status)) || (WEXITSTATUS(status) != 0))
		ERROR(EX_TEMPFAIL, "dspam exited with non-zero code");

	/* Now we have the message as processed by dspam.
	 * The only valid command right now is PROCESS so we
	 * extract the lines dspam added to the header first. */

	/* null terminate message */
	processed[readlen] = '\0';
	lflf = strstr(processed, "\n\n");
	crlfcrlf = strstr(processed, "\r\n\r\n");
	if (lflf) *lflf='\0';
	if (crlfcrlf) *crlfcrlf='\0';
	if (!lflf && !crlfcrlf)
		ERROR(EX_TEMPFAIL, "dspam failed to return a proper message");

	/* second part of dirty trick */
	tmp2 = processed;

	while (tmp2 && (tmp = strstr(tmp2, "\nX-DSPAM"))) {
		tmp++;
		tmp2 = strchr(tmp, '\n');
		if (tmp2) *tmp2 = '\0';
		strcpy(dspamres, tmp);
		dspamres += strlen(tmp);
		*dspamres = '\n';
		dspamres++;
		if (tmp2) *tmp2 = '\n';
	}
	*dspamres = '\0';

	/* now we have everything dspam gave us */
	char *res = strstr(dspamresult, "X-DSPAM-Result: ");
	if (!res)
		ERROR(EX_TEMPFAIL, "no dspam result!");

	char spamtag[20];
	strncpy(spamtag, res + strlen("X-DSPAM-Result: "), sizeof(spamtag));
	int i;
	for (i = 0; i < 20; i++)
		if (spamtag[i] == '\n') spamtag[i] = '\0';
	spamtag[19] = '\0';

	char *conf = strstr(dspamresult, "X-DSPAM-Confidence: ");
	if (!conf)
		ERROR(EX_TEMPFAIL, "no dspam confidence!");
	float confidence;
	if (sscanf(conf, "X-DSPAM-Confidence: %f", &confidence) != 1)
		ERROR(EX_TEMPFAIL, "could not parse dspam confidence");
	confidence *= 10;

	int isspam = strcasecmp(spamtag,"Spam")==0;
	if (!isspam) confidence = 0;
	printf("SPAMD/1.1 0 EX_OK\r\n");
	printf("Spam: %s", isspam?"True":"False");
	printf(" ; %f / 0\r\n\r\n", confidence);

	printf("%s", dspamresult);

	/* always return ok status to (x)inetd */
	return 0;
}
