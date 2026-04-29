#include "../examples/common/example_cmds.h"
#include "greatest.h"
#include "tclie.h"
#include <string.h>

GREATEST_MAIN_DEFS();

int example_cmd_echo(void *const arg, const int argc, const char **const argv)
{
	(void)arg;
	(void)argc;
	(void)argv;
	return 0;
}

int example_cmd_fail(void *const arg, const int argc, const char **const argv)
{
	(void)arg;
	(void)argc;
	(void)argv;
	return -1;
}

int example_cmd_exit(void *const arg, const int argc, const char **const argv)
{
	(void)arg;
	(void)argc;
	(void)argv;
	return 0;
}

static void out_sink(void *const arg, const char *const str)
{
	(void)arg;
	(void)str;
}

TEST registration_succeeds(void)
{
	tclie_t tclie;
	tclie_init(&tclie, out_sink, NULL);
#if TCLIE_ENABLE_USERS
	ASSERT(tclie_reg_users(&tclie, example_users, EXAMPLE_USERS_COUNT));
#endif
	ASSERT(tclie_reg_cmds(&tclie, example_cmds, EXAMPLE_CMDS_COUNT));
	PASS();
}

TEST representative_inputs_do_not_crash(void)
{
	tclie_t tclie;
	tclie_init(&tclie, out_sink, NULL);
#if TCLIE_ENABLE_USERS
	tclie_reg_users(&tclie, example_users, EXAMPLE_USERS_COUNT);
#endif
	tclie_reg_cmds(&tclie, example_cmds, EXAMPLE_CMDS_COUNT);

	// Representative commands across the registered patterns.
	const char *inputs[] = {
		"echo hi\r",
		"echo\r",
		"sub one\r",
		"sub other\r",
		"set attr value\r",
		"set attr\r",
		"can speed 100\r",
		"or a\r",
		"or b\r",
		"or c\r",
		"reg = value\r",
		"complex set 1 var end extra stuff\r",
		"options foo bar\r",
		"options --verbose foo\r",
		"options --required arg foo\r",
		"options -s --long foo\r",
		"options --doesnotexist foo\r",
		"help\r",
		"quit\r",
	};

	for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++)
		tclie_input_str(&tclie, inputs[i]);

	PASS();
}

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	RUN_TEST(registration_succeeds);
	RUN_TEST(representative_inputs_do_not_crash);
	GREATEST_MAIN_END();
}
