#include "../common/example_cmds.h"
#include "tclie.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static bool quit = false;

static void sigint(void *arg) { quit = true;
	return 0;
}

static struct termios saved_term;

static void restore_term(void)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
}

int main(int argc, char **argv)
{
	tcgetattr(STDIN_FILENO, &saved_term);
	atexit(restore_term);

	struct termios term = saved_term;
	term.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(STDIN_FILENO, TCSANOW, &term);

	tclie_t tclie;
	tclie_init(&tclie, output, NULL);
#if TCLIE_ENABLE_USERS
	assert(tclie_reg_users(&tclie, users, ARRAY_SIZE(users)));
#endif
	assert(tclie_reg_cmds(&tclie, cmds, ARRAY_SIZE(cmds)));
	tclie_set_sigint(&tclie, sigint);

	int counter = 0;

	while (!quit) {
		const int c = getchar();

		if (c == EOF)
			break;

		tclie_input_char(&tclie, (char)c);

		if (++counter % 100 == 0) {
			tclie_log(&tclie, "Logging stuff... \r\n");
			counter = 0;
		}
	}

	printf("\r\nExiting...");
	return 0;
}

static int cmd_echo(void *const arg, const int argc, const char **const argv)
{
	if (argc <= 1)
		return 0;

	if (strcmp(argv[0], "echo") != 0)
		printf("%s %s", argv[0], argv[1]);
	else
		printf("%s", argv[1]);

	for (int i = 2; i < argc; i++)
		printf(" %s", argv[i]);

	printf("\r\n");

	return 0;
}

static int cmd_fail(void *const arg, const int argc, const char **const argv)
{
	printf("Command failed...\r\n");
	return -1;
}

static int cmd_exit(void *const arg, const int argc, const char **const argv)
{
	quit = true;
	return 0;
}

static void output(void *const arg, const char *const str)
{
	printf("%s", str);
}
