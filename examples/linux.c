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

static const tclie_cmd_opt_t options[] = {
	{'v', "verbose", "Simple option."},
	{'t', "test", "Simple option."},
	{'r', "required", "Option with required argument.", "<arg>"},
	{'o', "optional", "Option with optional argument.", "[a]"},
};

static const tclie_cmd_t cmds[] = {
	{"echo", echo, USER_LEVEL_DEFAULT, "Echo input.",
#if TCLIE_PATTERN_MATCH
	 "echo ..."
#endif
	},
	{"fail", fail, USER_LEVEL_ADMIN, "A command that will fail.",
#if TCLIE_PATTERN_MATCH
	 "fail ..."
#endif
	},
#if TCLIE_PATTERN_MATCH
	{"reset", echo, USER_LEVEL_DEFAULT,
	 "Single word command, must match exactly.", "reset"},
	{"config", echo, USER_LEVEL_DEFAULT,
	 "Two word command, spaces around the words are ignored.", "config save"},
	{"can", echo, USER_LEVEL_DEFAULT,
	 "Two word command, with mandatory argument.", "can speed <rate>"},
	{"set", echo, USER_LEVEL_DEFAULT,
	 "One word command, with mandatory and optional argument.",
	 "set <attr> [<value>]"},
	{"=", echo, USER_LEVEL_DEFAULT,
	 "One word command ('=') embedded between mandatory arguments.",
	 "<reg> = <value>"},
	{"when", echo, USER_LEVEL_DEFAULT,
	 "Three word command, with two mandatory arguments and arbitrary "
	 "optional.",
	 "when <reg> is <value> echo ..."},
	{"or", echo, USER_LEVEL_DEFAULT,
	 "Two word command, with mandatory argument selected from options.",
	 "or a|b|c"},
	{"complex", echo, USER_LEVEL_DEFAULT, "Complex example.",
	 "complex {set|reset} [a|(b c)] 1|2 <var> [<opt>] end ..."},
	{"options",
	 echo,
	 USER_LEVEL_DEFAULT,
	 "Example with options.",
	 "options <attr>",
	 {options, ARRAY_SIZE(options)}},
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
