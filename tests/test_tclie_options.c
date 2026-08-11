#include "greatest.h"
#include "tclie.h"
#include "test_helpers.h"
#include <assert.h>

GREATEST_MAIN_DEFS();

#if TCLIE_PATTERN_MATCH

static int cmd_capture(void *const arg, const int argc, const char **const argv)
{
	return test_exec(arg, argc, argv);
}

static const tclie_cmd_opt_t opts_mixed[] = {
	{.short_opt = 'v', .long_opt = "verbose", .desc = "Simple option."},
	{.short_opt = 'r',
	 .long_opt = "required",
	 .desc = "With required arg.",
	 .pattern = "<arg>"},
	{.short_opt = 'o',
	 .long_opt = "optional",
	 .desc = "With optional arg.",
	 .pattern = "[<arg>]"},
	{.long_opt = "longonly", .desc = "Long-only option."},
	{.short_opt = 's', .desc = "Short-only option."},
};

static const tclie_cmd_t cmds_with_opts[] = {
	{.name = "run",
	 .fn = cmd_capture,
	 .desc = "Run with opts.",
	 .pattern = "run",
	 .options = {opts_mixed, sizeof(opts_mixed) / sizeof(opts_mixed[0])}},
};

#define CMDS_COUNT (sizeof(cmds_with_opts) / sizeof(cmds_with_opts[0]))

static void init(tclie_t *const tclie, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tclie_init(tclie, test_out, ctx);
	assert(tclie_reg_cmds(tclie, cmds_with_opts, CMDS_COUNT));
}

TEST short_option_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run -v\r");
	ASSERT_EQ(1, ctx.calls);
	// Options are passed through to the callback untouched.
	ASSERT_EQ(2, ctx.argc);
	ASSERT_STR_EQ("-v", test_arg(&ctx, 1));
	PASS();
}

TEST long_option_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run --verbose\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST long_only_option_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run --longonly\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST short_only_option_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run -s\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST option_with_required_arg(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run --required value\r");
	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(3, ctx.argc);
	ASSERT_STR_EQ("value", test_arg(&ctx, 2));
	PASS();
}

TEST option_missing_required_arg_rejected(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run --required\r");
	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST option_with_optional_arg(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run --optional\r");
	ASSERT_EQ(1, ctx.calls);

	tclie_in_str(&tclie, "run --optional value\r");
	ASSERT_EQ(2, ctx.calls);
	PASS();
}

TEST two_options_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run -v -s\r");
	ASSERT_EQ(1, ctx.calls);

	tclie_in_str(&tclie, "run --verbose --longonly\r");
	ASSERT_EQ(2, ctx.calls);
	PASS();
}

TEST combined_short_options_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run -vs\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST many_separate_options_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run -v -s --longonly\r");
	ASSERT_EQ(1, ctx.calls);

	tclie_in_str(&tclie, "run -v -s --longonly --optional\r");
	ASSERT_EQ(2, ctx.calls);

	tclie_in_str(&tclie, "run -v --required arg -s --longonly\r");
	ASSERT_EQ(3, ctx.calls);
	PASS();
}

TEST options_may_precede_the_command(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "-v -s run\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST unknown_long_option_rejected(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run --doesnotexist\r");
	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST unknown_short_option_rejected(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "run -x\r");
	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST options_are_listed_in_help(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "help run\r");

	ASSERT(test_out_has(&ctx, "--verbose"));
	ASSERT(test_out_has(&ctx, "Simple option."));
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
	RUN_TEST(short_only_option_accepted);
	RUN_TEST(option_with_required_arg);
	RUN_TEST(option_missing_required_arg_rejected);
	RUN_TEST(option_with_optional_arg);
	RUN_TEST(two_options_accepted);
	RUN_TEST(combined_short_options_accepted);
	RUN_TEST(many_separate_options_accepted);
	RUN_TEST(options_may_precede_the_command);
	RUN_TEST(unknown_long_option_rejected);
	RUN_TEST(unknown_short_option_rejected);
	RUN_TEST(options_are_listed_in_help);
#endif
	GREATEST_MAIN_END();
}
