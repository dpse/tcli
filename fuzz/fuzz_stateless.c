#include "../examples/common/example_cmds.h"
#include "tclie.h"
#include <stddef.h>
#include <stdint.h>

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

int LLVMFuzzerTestOneInput(const uint8_t *const data, const size_t size)
{
	tclie_t tclie;
	tclie_init(&tclie, out_sink, NULL);
#if TCLIE_ENABLE_USERS
	tclie_reg_users(&tclie, example_users, EXAMPLE_USERS_COUNT);
#endif
	tclie_reg_cmds(&tclie, example_cmds, EXAMPLE_CMDS_COUNT);
	tclie_input(&tclie, data, size);
	return 0;
}
