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

static const tclie_cmd_t cmds_simple[] = {
	{.name = "echo", .fn = cmd_capture, .desc = "Echo.", .pattern = "echo ..."},
	{.name = "set",
	 .fn = cmd_capture,
	 .desc = "Set attr.",
	 .pattern = "set <attr> [<value>]"},
	{.name = "reset",
	 .fn = cmd_capture,
	 .desc = "Reset, exact match only.",
	 .pattern = "reset"},
	{.name = "or",
	 .fn = cmd_capture,
	 .desc = "One of a few words.",
	 .pattern = "or a|b|c"},
	{.name = "when",
	 .fn = cmd_capture,
	 .desc = "Words interleaved with arguments.",
	 .pattern = "when <reg> is <value> echo ..."},
};

#define CMDS_SIMPLE_COUNT (sizeof(cmds_simple) / sizeof(cmds_simple[0]))

static void init(tclie_t *const tclie, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tclie_init(tclie, test_out, ctx);
	assert(tclie_reg_cmds(tclie, cmds_simple, CMDS_SIMPLE_COUNT));
}

TEST simple_command_matches(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "echo hi\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(2, ctx.argc);
	ASSERT_STR_EQ("echo", test_arg(&ctx, 0));
	ASSERT_STR_EQ("hi", test_arg(&ctx, 1));
	PASS();
}

TEST mandatory_arg_required(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	// "set" alone has no <attr> — should not invoke callback.
	tclie_in_str(&tclie, "set\r");

	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST optional_arg_accepted(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "set foo\r");
	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(2, ctx.argc);

	tclie_in_str(&tclie, "set foo bar\r");
	ASSERT_EQ(2, ctx.calls);
	ASSERT_EQ(3, ctx.argc);
	ASSERT_STR_EQ("foo", test_arg(&ctx, 1));
	ASSERT_STR_EQ("bar", test_arg(&ctx, 2));
	PASS();
}

TEST too_many_args_rejected(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	// The pattern takes at most two arguments.
	tclie_in_str(&tclie, "set foo bar baz\r");

	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST exact_pattern_rejects_extra_words(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "reset\r");
	ASSERT_EQ(1, ctx.calls);

	tclie_in_str(&tclie, "reset now\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST alternatives_accept_only_listed_words(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "or a\r");
	tclie_in_str(&tclie, "or c\r");
	ASSERT_EQ(2, ctx.calls);

	tclie_in_str(&tclie, "or d\r");
	ASSERT_EQ(2, ctx.calls);

	// The alternative is mandatory.
	tclie_in_str(&tclie, "or\r");
	ASSERT_EQ(2, ctx.calls);
	PASS();
}

TEST rest_pattern_takes_all_remaining_tokens(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "echo one two three\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(4, ctx.argc);
	ASSERT_STR_EQ("three", test_arg(&ctx, 3));
	PASS();
}

TEST rest_pattern_accepts_no_tokens(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "echo\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(1, ctx.argc);
	PASS();
}

#if TCLI_MAX_TOKENS >= 6
TEST literal_words_inside_pattern_must_match(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "when reg is 1 echo hello\r");
	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("is", test_arg(&ctx, 2));

	// "was" is not the literal the pattern asks for.
	tclie_in_str(&tclie, "when reg was 1 echo hello\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}
#endif

TEST quoted_argument_stays_one_token(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "set \"a b\"\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(2, ctx.argc);
	ASSERT_STR_EQ("a b", test_arg(&ctx, 1));
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
	RUN_TEST(too_many_args_rejected);
	RUN_TEST(exact_pattern_rejects_extra_words);
	RUN_TEST(alternatives_accept_only_listed_words);
	RUN_TEST(rest_pattern_takes_all_remaining_tokens);
	RUN_TEST(rest_pattern_accepts_no_tokens);
#if TCLI_MAX_TOKENS >= 6
	RUN_TEST(literal_words_inside_pattern_must_match);
#endif
	RUN_TEST(quoted_argument_stays_one_token);
#endif
	GREATEST_MAIN_END();
}
