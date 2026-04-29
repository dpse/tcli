#include "greatest.h"
#include "tclie.h"
#include <string.h>

GREATEST_MAIN_DEFS();

typedef struct {
	int calls;
	int last_argc;
} test_ctx_t;

static void test_out(void *const arg, const char *const str)
{
	(void)arg;
	(void)str;
}

static int cmd_capture(void *const arg, const int argc, const char **const argv)
{
	(void)argv;
	test_ctx_t *const ctx = arg;
	ctx->calls++;
	ctx->last_argc = argc;
	return 0;
}

#if TCLIE_PATTERN_MATCH

static const tclie_cmd_opt_t opts_mixed[] = {
	{'v', "verbose", "Simple option."},
	{'r', "required", "With required arg.", "<arg>"},
	{0, "longonly", "Long-only option."},
};

static const tclie_cmd_t cmds_with_opts[] = {
	{"run",
	 cmd_capture,
	 0,
	 "Run with opts.",
	 "run",
	 {opts_mixed, sizeof(opts_mixed) / sizeof(opts_mixed[0])}},
};

TEST short_option_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx = {0};
	tclie_init(&tclie, test_out, &ctx);
	ASSERT(tclie_reg_cmds(&tclie, cmds_with_opts,
						  sizeof(cmds_with_opts) / sizeof(cmds_with_opts[0])));

	tclie_input_str(&tclie, "run -v\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST long_option_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx = {0};
	tclie_init(&tclie, test_out, &ctx);
	ASSERT(tclie_reg_cmds(&tclie, cmds_with_opts,
						  sizeof(cmds_with_opts) / sizeof(cmds_with_opts[0])));

	tclie_input_str(&tclie, "run --verbose\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST long_only_option_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx = {0};
	tclie_init(&tclie, test_out, &ctx);
	ASSERT(tclie_reg_cmds(&tclie, cmds_with_opts,
						  sizeof(cmds_with_opts) / sizeof(cmds_with_opts[0])));

	tclie_input_str(&tclie, "run --longonly\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST option_with_required_arg(void)
{
	tclie_t tclie;
	test_ctx_t ctx = {0};
	tclie_init(&tclie, test_out, &ctx);
	ASSERT(tclie_reg_cmds(&tclie, cmds_with_opts,
						  sizeof(cmds_with_opts) / sizeof(cmds_with_opts[0])));

	tclie_input_str(&tclie, "run --required value\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST unknown_long_option_does_not_crash(void)
{
	tclie_t tclie;
	test_ctx_t ctx = {0};
	tclie_init(&tclie, test_out, &ctx);
	ASSERT(tclie_reg_cmds(&tclie, cmds_with_opts,
						  sizeof(cmds_with_opts) / sizeof(cmds_with_opts[0])));

	tclie_input_str(&tclie, "run --doesnotexist\r");
	PASS();
}

TEST unknown_short_option_does_not_crash(void)
{
	tclie_t tclie;
	test_ctx_t ctx = {0};
	tclie_init(&tclie, test_out, &ctx);
	ASSERT(tclie_reg_cmds(&tclie, cmds_with_opts,
						  sizeof(cmds_with_opts) / sizeof(cmds_with_opts[0])));

	tclie_input_str(&tclie, "run -x\r");
	PASS();
}

#endif

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
#if TCLIE_PATTERN_MATCH
	RUN_TEST(short_option_accepted);
	RUN_TEST(long_option_accepted);
	RUN_TEST(long_only_option_accepted);
	RUN_TEST(option_with_required_arg);
	RUN_TEST(unknown_long_option_does_not_crash);
	RUN_TEST(unknown_short_option_does_not_crash);
#endif
	GREATEST_MAIN_END();
}
