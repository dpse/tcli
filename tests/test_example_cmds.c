#include "../examples/common/example_cmds.h"
#include "greatest.h"
#include "tclie.h"
#include "test_helpers.h"
#include <assert.h>

GREATEST_MAIN_DEFS();

int example_cmd_echo(void *const arg, const int argc, const char **const argv)
{
	return test_exec(arg, argc, argv);
}

int example_cmd_fail(void *const arg, const int argc, const char **const argv)
{
	test_exec(arg, argc, argv);
	return -1;
}

int example_cmd_exit(void *const arg, const int argc, const char **const argv)
{
	return test_exec(arg, argc, argv);
}

static void init(tclie_t *const tclie, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tclie_init(tclie, test_out, ctx);
#if TCLIE_ENABLE_USERS
	assert(tclie_reg_users(tclie, example_users, EXAMPLE_USERS_COUNT));
#endif
	assert(tclie_reg_cmds(tclie, example_cmds, EXAMPLE_CMDS_COUNT));
}

TEST registration_succeeds(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	tclie_init(&tclie, test_out, &ctx);
#if TCLIE_ENABLE_USERS
	ASSERT(tclie_reg_users(&tclie, example_users, EXAMPLE_USERS_COUNT));
#endif
	ASSERT(tclie_reg_cmds(&tclie, example_cmds, EXAMPLE_CMDS_COUNT));
	PASS();
}

TEST echo_command_receives_its_arguments(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "echo one two\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(3, ctx.argc);
	ASSERT_STR_EQ("one", test_arg(&ctx, 1));
	ASSERT_STR_EQ("two", test_arg(&ctx, 2));
	PASS();
}

TEST subcommands_are_dispatched(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "sub one\r");
	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("sub", test_arg(&ctx, 0));
	ASSERT_STR_EQ("one", test_arg(&ctx, 1));

	tclie_in_str(&tclie, "sub other\r");
	ASSERT_EQ(2, ctx.calls);

	tclie_in_str(&tclie, "sub missing\r");
	ASSERT_EQ(2, ctx.calls);
	PASS();
}

#if TCLIE_ENABLE_USERS
TEST restricted_command_needs_its_level(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	// "fail" is registered for admins only.
	tclie_in_str(&tclie, "fail now\r");
	ASSERT_EQ(0, ctx.calls);

	tclie_set_user_level(&tclie, USER_LEVEL_ADMIN);
	tclie_in_str(&tclie, "fail now\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST example_user_can_log_in(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "login\r");
#if TCLIE_ENABLE_USERNAMES
	tclie_in_str(&tclie, "admin\r");
#endif
	tclie_in_str(&tclie, "12345\r");

	ASSERT_EQ((unsigned)USER_LEVEL_ADMIN, tclie_get_user_level(&tclie));
	PASS();
}
#endif

#if TCLIE_PATTERN_MATCH
TEST patterns_validate_arguments(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "can speed 100\r");
	ASSERT_EQ(1, ctx.calls);

	// <rate> is mandatory.
	tclie_in_str(&tclie, "can speed\r");
	ASSERT_EQ(1, ctx.calls);

	// "config save" is the only accepted form.
	tclie_in_str(&tclie, "config save\r");
	ASSERT_EQ(2, ctx.calls);
	tclie_in_str(&tclie, "config load\r");
	ASSERT_EQ(2, ctx.calls);
	PASS();
}

TEST embedded_literal_pattern_matches(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "r0 = 42\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(3, ctx.argc);
	ASSERT_STR_EQ("=", test_arg(&ctx, 1));
	PASS();
}
#endif

TEST representative_inputs_do_not_crash(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

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
		tclie_in_str(&tclie, inputs[i]);

	ASSERT(ctx.calls > 0);
	PASS();
}

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	RUN_TEST(registration_succeeds);
	RUN_TEST(echo_command_receives_its_arguments);
	RUN_TEST(subcommands_are_dispatched);
#if TCLIE_ENABLE_USERS
	RUN_TEST(restricted_command_needs_its_level);
	RUN_TEST(example_user_can_log_in);
#endif
#if TCLIE_PATTERN_MATCH
	RUN_TEST(patterns_validate_arguments);
	RUN_TEST(embedded_literal_pattern_matches);
#endif
	RUN_TEST(representative_inputs_do_not_crash);
	GREATEST_MAIN_END();
}
