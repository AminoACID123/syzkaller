#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

int main()
{
	int pt = posix_openpt(O_RDWR);
	if (pt == -1) {
		perror("Could not open pseudo terminal.\n");
		return EXIT_FAILURE;
	}
	char *ptname = ptsname(pt);
	if (!ptname) {
		perror("Could not get pseudo terminal device name.\n");
		close(pt);
		return EXIT_FAILURE;
	}

	if (unlockpt(pt) == -1) {
		perror("Could not get pseudo terminal device name.\n");
		close(pt);
		return EXIT_FAILURE;
	}
	char cmd[100];
	int pts;
	sscanf((strrchr(ptname, '/') + 1), "%d", &pts);
	sprintf(cmd, "xterm -fa monaco -fs 14 -bg black -S%d/%d &", pts, pt);
	system(cmd);

	int xterm_fd = open(ptname, O_RDWR);

	char c;
	do {
		read(xterm_fd, &c, 1);
	} while (c != '\n');

	if (dup2(pt, 1) < 0) {
		perror("Could not redirect standard output.\n");
		close(pt);
		return EXIT_FAILURE;
	}
	if (dup2(pt, 2) < 0) {
		perror("Could not redirect standard error output.\n");
		close(pt);
		return EXIT_FAILURE;
	}

	int i = 0;
	while (1) {
		printf("%d\n",i);
		sleep(1);
		i++;
	}
	close(pt);
	return EXIT_SUCCESS;
}