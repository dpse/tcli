#include "greatest.h"
#include "tclie.h"
#include <string.h>

GREATEST_MAIN_DEFS();

typedef struct {
	int calls;
	int last_argc;
	char last_argv0[64];
} test_ctx_t;

static void test_out(void *arg, const char *str)
{
	(void)arg;
	(void)str;
}

static int cmd_capture(void *arg, int argc, const char **argv)
{
	test_ctx_t *ctx = arg;
	ctx->calls++;
	ctx->last_argc = argc;
	if (argc > 0) {
		strncpy(ctx->last_argv0, argv[0], sizeof(ctx->last_argv0) - 1);
		ctx->last_argv0[sizeof(ctx->last_argv0) - 1] = '\0';
	} else
		ctx->last_argv0[0] = '\0';
	return 0;
}

#if TCLIE_PATTERN_MATCH

static const tclie_cmd_t cmds_simple[] = {
	{"echo", cmd_capture, 0, "Echo.", "echo ..."},
	{"set", cmd_capture, 0, "Set attr.", "set <attr> [<value>]"},
};

TEST simple_command_matches(void)
{
	tclie_t tclie;
	test_ctx_t ctx = {0};
	tclie_init(&tclie, test_out, &ctx);
	ASSERT(tclie_reg_cmds(&tclie, cmds_simple,
						  sizeof(cmds_simple) / sizeof(cmds_simple[0])));

	tclie_input_str(&tclie, "echo hi\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("echo", ctx.last_argv0);
	PASS();
}

TEST mandatory_arg_required(void)
{
	tclie_t tclie;
	test_ctx_t ctx = {0};
	tclie_init(&tclie, test_out, &ctx);
	ASSERT(tclie_reg_cmds(&tclie, cmds_simple,
						  sizeof(cmds_simple) / sizeof(cmds_simple[0])));

	// "set" alone has no <attr> — should not invoke callback.
	tclie_input_str(&tclie, "set\r");

	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST optional_arg_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx = {0};
	tclie_init(&tclie, test_out, &ctx);
	ASSERT(tclie_reg_cmds(&tclie, cmds_simple,
						  sizeof(cmds_simple) / sizeof(cmds_simple[0])));

	tclie_input_str(&tclie, "set foo\r");
	ASSERT_EQ(1, ctx.calls);
	tclie_input_str(&tclie, "set foo bar\r");
	ASSERT_EQ(2, ctx.calls);
	PASS();
}

#endif

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
#if TCLIE_PATTERN_MATCH
	RUN_TEST(simple_command_matches);
	RUN_TEST(mandatory_arg_required);
	RUN_TEST(optional_arg_accepted);
#endif
	GREATEST_MAIN_END();
}
