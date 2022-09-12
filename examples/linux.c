#include "tclie.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static int echo(void *arg, int argc, const char **argv);
static int fail(void *arg, int argc, const char **argv);
static void output(void *arg, const char *str);

enum { USER_LEVEL_DEFAULT = 0, USER_LEVEL_DEBUG, USER_LEVEL_ADMIN };

#if TCLIE_ENABLE_USERS
static const tclie_user_t users[] = {{"debug", NULL, USER_LEVEL_DEBUG},
									 {"admin", "12345", USER_LEVEL_ADMIN}};
#endif

static const tclie_cmd_t cmds[] = {
	{"echo", echo, USER_LEVEL_DEFAULT,
#if TCLIE_PATTERN_MATCH
	 "echo ...",
#endif
	 "Echo input."},
	{"fail", fail, USER_LEVEL_ADMIN,
#if TCLIE_PATTERN_MATCH
	 "fail ...",
#endif
	 "A command that will fail."},
#if TCLIE_PATTERN_MATCH
	{"reset", echo, USER_LEVEL_DEFAULT, "reset",
	 "Single word command, must match exactly."},
	{"config", echo, USER_LEVEL_DEFAULT, "config save",
	 "Two word command, spaces around the words are ignored."},
	{"can", echo, USER_LEVEL_DEFAULT, "can speed <rate>",
	 "Two word command, with mandatory argument."},
	{"set", echo, USER_LEVEL_DEFAULT, "set <attr> [<value>]",
	 "One word command, with mandatory and optional argument."},
	{"=", echo, USER_LEVEL_DEFAULT, "<reg> = <value>",
	 "One word command ('=') embedded between mandatory arguments."},
	{"when", echo, USER_LEVEL_DEFAULT, "when <reg> is <value> echo ...",
	 "Three word command, with two mandatory arguments and arbitrary "
	 "optional."},
	{"or", echo, USER_LEVEL_DEFAULT, "or a|b|c",
	 "Two word command, with mandatory argument selected from options."},
	{"complex", echo, USER_LEVEL_DEFAULT,
	 "complex {set|reset} [a|(b c)] 1|2 <var> [<opt>] end ...",
	 "Complex example."},
#endif
};

static bool quit = false;

static void sigint(void *arg) { quit = true; }

int main(int argc, char **argv)
{
	system("/bin/stty raw");

	struct termios term;
	tcgetattr(STDIN_FILENO, &term);
	term.c_lflag &= ~ECHO;
	term.c_lflag &= ~ICANON;
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

static int echo(void *const arg, const int argc, const char **const argv)
{
	if (argc <= 1)
		return 0;

	printf("%s", argv[1]);
	for (int i = 2; i < argc; i++) {
		printf(" %s", argv[i]);
	}
	printf("\r\n");

	return 0;
}

static int fail(void *const arg, const int argc, const char **const argv)
{
	printf("Command failed...\r\n");
	return -1;
}

static void output(void *const arg, const char *const str)
{
	printf("%s", str);
}
