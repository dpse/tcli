#include "../examples/common/example_cmds.h"
#include "tclie.h"
#include <stddef.h>
#include <stdint.h>

int example_cmd_echo(void *arg, int argc, const char **argv)
{
	(void)arg;
	(void)argc;
	(void)argv;
	return 0;
}

int example_cmd_fail(void *arg, int argc, const char **argv)
{
	(void)arg;
	(void)argc;
	(void)argv;
	return -1;
}

int example_cmd_exit(void *arg, int argc, const char **argv)
{
	(void)arg;
	(void)argc;
	(void)argv;
	return 0;
}

static void out_sink(void *arg, const char *str)
{
	(void)arg;
	(void)str;
}

static tclie_t tclie;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	tclie_init(&tclie, out_sink, NULL);
#if TCLIE_ENABLE_USERS
	tclie_reg_users(&tclie, example_users, EXAMPLE_USERS_COUNT);
#endif
	tclie_reg_cmds(&tclie, example_cmds, EXAMPLE_CMDS_COUNT);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	tclie_input(&tclie, data, size);
	return 0;
}
