#include "../common/example_cmds.h"
#include "tclie.h"
#include <assert.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static bool quit = false;

static void output(void *arg, const char *str)
{
	(void)arg;

	printf("%s", str);
}

static void sigint(void *arg)
{
	(void)arg;

	quit = true;
}

int example_cmd_echo(void *const arg, const int argc, const char **const argv)
{
	(void)arg;

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

int example_cmd_fail(void *const arg, const int argc, const char **const argv)
{
	(void)arg;
	(void)argc;
	(void)argv;

	printf("Command failed...\r\n");
	return -1;
}

int example_cmd_exit(void *const arg, const int argc, const char **const argv)
{
	(void)arg;
	(void)argc;
	(void)argv;

	quit = true;
	return 0;
}

static DWORD saved_in_mode;
static DWORD saved_out_mode;

static void restore_console(void)
{
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), saved_in_mode);
	SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), saved_out_mode);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	const HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
	const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);

	GetConsoleMode(in, &saved_in_mode);
	GetConsoleMode(out, &saved_out_mode);
	atexit(restore_console);

	// Interpret the escape sequences emitted by the library instead of printing
	// them literally (virtual terminal processing requires processed output).
	SetConsoleMode(out, saved_out_mode | ENABLE_PROCESSED_OUTPUT |
							ENABLE_VIRTUAL_TERMINAL_PROCESSING);

	// Dropping ENABLE_PROCESSED_INPUT delivers ctrl+c as a character to the
	// registered handler instead of raising a console control event, and
	// ENABLE_VIRTUAL_TERMINAL_INPUT turns arrow keys and similar into the
	// escape sequences the library expects.
	SetConsoleMode(in,
				   (saved_in_mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
									  ENABLE_PROCESSED_INPUT)) |
					   ENABLE_VIRTUAL_TERMINAL_INPUT);

	// Binary mode keeps the byte stream intact: no <CR><LF> translation in
	// either direction, and no ctrl+z ending the input.
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);

	// There is no line buffering here (_IOLBF behaves like _IOFBF) and reading
	// input does not flush output, so buffering has to be turned off for the
	// prompt to appear before the buffer fills up.
	setvbuf(stdout, NULL, _IONBF, 0);

	tclie_t tclie;
	tclie_init(&tclie, output, NULL);
#if TCLIE_ENABLE_USERS
	assert(tclie_reg_users(&tclie, example_users, EXAMPLE_USERS_COUNT));
#endif
	assert(tclie_reg_cmds(&tclie, example_cmds, EXAMPLE_CMDS_COUNT));
	tclie_set_sigint(&tclie, sigint);

	int counter = 0;

	while (!quit) {
		const int c = getchar();

		if (c == EOF)
			break;

		tclie_in_char(&tclie, (char)c);

		if (++counter % 100 == 0) {
			tclie_log(&tclie, "Logging stuff... \r\n");
			counter = 0;
		}
	}

	printf("\r\nExiting...");
	return 0;
}
