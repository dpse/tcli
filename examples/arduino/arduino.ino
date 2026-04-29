// Minimal Arduino integration for TinyCLI. Uses the shared example command
// set (examples/common/example_cmds.h).

#include "../common/example_cmds.h"
#include "tclie.h"

static tclie_t tclie;

static void on_output(void *const arg, const char *const str)
{
	(void)arg;

	Serial.print(str);
}

int example_cmd_echo(void *const arg, const int argc, const char **const argv)
{
	(void)arg;

	if (argc <= 1)
		return 0;

	if (strcmp(argv[0], "echo") != 0) {
		Serial.print(argv[0]);
		Serial.print(' ');
		Serial.print(argv[1]);
	} else
		Serial.print(argv[1]);

	for (int i = 2; i < argc; i++) {
		Serial.print(' ');
		Serial.print(argv[i]);
	}

	Serial.print("\r\n");
	return 0;
}

int example_cmd_fail(void *const arg, const int argc, const char **const argv)
{
	(void)arg;
	(void)argc;
	(void)argv;

	Serial.print("Command failed...\r\n");
	return -1;
}

int example_cmd_exit(void *const arg, const int argc, const char **const argv)
{
	(void)arg;
	(void)argc;
	(void)argv;

	// no-op
	return 0;
}

void setup()
{
	Serial.begin(115200);
	while (!Serial) {
	}

	tclie_init(&tclie, on_output, nullptr);
#if TCLIE_ENABLE_USERS
	tclie_reg_users(&tclie, example_users, EXAMPLE_USERS_COUNT);
#endif
	tclie_reg_cmds(&tclie, example_cmds, EXAMPLE_CMDS_COUNT);
}

void loop()
{
	while (Serial.available() > 0) {
		const int c = Serial.read();
		if (c >= 0)
			tclie_input_char(&tclie, (char)c);
	}
}
