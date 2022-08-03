#include "tcli_ext.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static int echo(__attribute__((unused)) void *arg, int argc,
				const char *const *argv);
static int fail(__attribute__((unused)) void *arg,
				__attribute__((unused)) int argc,
				__attribute__((unused)) const char *const *argv);
static void output(__attribute__((unused)) void *arg, const char *str);

enum { USER_LEVEL_DEFAULT = 0, USER_LEVEL_DEBUG, USER_LEVEL_ADMIN };

#if TCLIE_ENABLE_USERS
static const tclie_user_t users[] = {{"debug", NULL, USER_LEVEL_DEBUG},
									 {"admin", "12345", USER_LEVEL_ADMIN}};
#endif

static const tclie_cmd_t cmds[] = {
	{"echo", echo, USER_LEVEL_DEFAULT, 0, 1, "Echo input."},
	{"fail", fail, USER_LEVEL_ADMIN, 1, 2, "A command that will fail."},
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
	assert(tclie_init(&tclie, output, NULL));
#if TCLIE_ENABLE_USERS
	assert(tclie_reg_users(&tclie, users, ARRAY_SIZE(users)));
#endif
	assert(tclie_reg_cmds(&tclie, cmds, ARRAY_SIZE(cmds)));
	assert(tclie_set_sigint(&tclie, sigint));

	int counter = 0;

	while (!quit) {
		const int c = getchar();

		if (c == EOF)
			break;

		tclie_input_char(&tclie, (char)c);

		if (++counter % 100 == 0) {
			tclie_log_str(&tclie, true, "Logging stuff...");
			counter = 0;
		}
	}

	printf("\r\nExiting...");
	return 0;
}

static int echo(__attribute__((unused)) void *const arg, const int argc,
				const char *const *const argv)
{
	if (argc != 2)
		return 0;

	printf("%s\r\n", argv[1]);
	return 0;
}

static int fail(__attribute__((unused)) void *const arg,
				__attribute__((unused)) const int argc,
				__attribute__((unused)) const char *const *const argv)
{
	printf("Command failed...\n");
	return -1;
}

static void output(__attribute__((unused)) void *const arg,
				   const char *const str)
{
	printf("%s", str);
}
