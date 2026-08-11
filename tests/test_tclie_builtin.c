#include "greatest.h"
#include "tclie.h"
#include "test_helpers.h"
#include <assert.h>

GREATEST_MAIN_DEFS();

#define UP "\x1b[A"

enum { LEVEL_DEFAULT = 0, LEVEL_ADMIN = 2 };

static int cmd_capture(void *const arg, const int argc, const char **const argv)
{
	return test_exec(arg, argc, argv);
}

static const tclie_cmd_t cmds[] = {
	{.name = "visible",
	 .fn = cmd_capture,
	 .desc = "Visible to everyone."
#if TCLIE_PATTERN_MATCH
	 ,
	 .pattern = "visible"
#endif
	},
	{.name = "other",
	 .fn = cmd_capture,
	 .desc = "Also visible to everyone."
#if TCLIE_PATTERN_MATCH
	 ,
	 .pattern = "other"
#endif
	},
#if TCLIE_ENABLE_USERS
	{.name = "privileged",
	 .fn = cmd_capture,
	 .min_user_level = LEVEL_ADMIN,
	 .desc = "Restricted command."
#if TCLIE_PATTERN_MATCH
	 ,
	 .pattern = "privileged"
#endif
	},
#endif
};

#if TCLIE_ENABLE_USERS
static const tclie_user_t users[] = {
#if TCLIE_ENABLE_USERNAMES
	{.name = "admin", .password = "12345", .level = LEVEL_ADMIN},
#else
	{.password = "12345", .level = LEVEL_ADMIN},
#endif
};
#endif

static void init(tclie_t *const tclie, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tclie_init(tclie, test_out, ctx);
	assert(tclie_reg_cmds(tclie, cmds, sizeof(cmds) / sizeof(cmds[0])));
}

TEST help_lists_registered_commands(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "help\r");

	ASSERT(test_out_has(&ctx, "visible"));
	ASSERT(test_out_has(&ctx, "Visible to everyone."));
	// The built-ins list themselves as well.
	ASSERT(test_out_has(&ctx, "help"));
	PASS();
}

#if TCLIE_PATTERN_MATCH
// The alias comes from the built-in pattern "help|? [<command>] ...", so it
// only exists when pattern matching is compiled in.
TEST question_mark_is_an_alias_for_help(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "?\r");

	ASSERT(test_out_has(&ctx, "visible"));
	PASS();
}
#endif

TEST help_with_argument_describes_one_command(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "help visible\r");

	ASSERT(test_out_has(&ctx, "visible"));
	ASSERT_FALSE(test_out_has(&ctx, "other"));
	PASS();
}

TEST clear_emits_clear_screen_sequence(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "clear\r");

	ASSERT(test_out_has(&ctx, "\033[2J"));
	PASS();
}

TEST unknown_command_is_reported(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "doesnotexist\r");

	ASSERT_EQ(0, ctx.calls);
	ASSERT(test_out_has(&ctx, "Unknown command"));
	ASSERT(test_out_has(&ctx, "doesnotexist"));
	PASS();
}

TEST registered_command_runs(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "visible\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("visible", test_arg(&ctx, 0));
	PASS();
}

#if TCLIE_ENABLE_USERS

TEST help_hides_commands_above_user_level(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "help\r");
	ASSERT_FALSE(test_out_has(&ctx, "privileged"));

	test_clear_out(&ctx);
	tclie_set_user_level(&tclie, LEVEL_ADMIN);
	tclie_in_str(&tclie, "help\r");
	ASSERT(test_out_has(&ctx, "privileged"));
	PASS();
}

TEST logout_is_hidden_until_logged_in(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_in_str(&tclie, "logout\r");
	ASSERT(test_out_has(&ctx, "Unknown command"));
	PASS();
}

TEST logout_drops_privileges(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	tclie_set_user_level(&tclie, LEVEL_ADMIN);

	tclie_in_str(&tclie, "logout\r");

	ASSERT_EQ(LEVEL_DEFAULT, (int)tclie_get_user_level(&tclie));
	tclie_in_str(&tclie, "privileged\r");
	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST login_grants_the_user_level(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	assert(tclie_reg_users(&tclie, users, sizeof(users) / sizeof(users[0])));

	tclie_in_str(&tclie, "login\r");
#if TCLIE_ENABLE_USERNAMES
	tclie_in_str(&tclie, "admin\r");
#endif
	tclie_in_str(&tclie, "12345\r");

	ASSERT_EQ(LEVEL_ADMIN, (int)tclie_get_user_level(&tclie));

	tclie_in_str(&tclie, "privileged\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST password_is_not_echoed(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	assert(tclie_reg_users(&tclie, users, sizeof(users) / sizeof(users[0])));

	tclie_in_str(&tclie, "login\r");
#if TCLIE_ENABLE_USERNAMES
	tclie_in_str(&tclie, "admin\r");
#endif
	test_clear_out(&ctx);
	tclie_in_str(&tclie, "12345\r");

	ASSERT_FALSE(test_out_has(&ctx, "12345"));
	ASSERT(test_out_has(&ctx, "*"));
	PASS();
}

TEST password_is_not_kept_in_history(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	assert(tclie_reg_users(&tclie, users, sizeof(users) / sizeof(users[0])));

	tclie_in_str(&tclie, "login\r");
#if TCLIE_ENABLE_USERNAMES
	tclie_in_str(&tclie, "admin\r");
#endif
	tclie_in_str(&tclie, "12345\r");

#if TCLI_HISTORY_BUF_LEN > 0
	// Walking the whole history must never surface the credentials.
	for (int i = 0; i < 5; i++) {
		test_clear_out(&ctx);
		tclie_in_str(&tclie, UP);
		ASSERT_FALSE(test_out_has(&ctx, "12345"));
#if TCLIE_ENABLE_USERNAMES
		ASSERT_FALSE(test_out_has(&ctx, "admin"));
#endif
	}
#endif
	PASS();
}

TEST wrong_password_keeps_default_level(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	assert(tclie_reg_users(&tclie, users, sizeof(users) / sizeof(users[0])));

	tclie_in_str(&tclie, "login\r");
#if TCLIE_ENABLE_USERNAMES
	tclie_in_str(&tclie, "admin\r");
#endif
	tclie_in_str(&tclie, "wrong\r");

	ASSERT_EQ(LEVEL_DEFAULT, (int)tclie_get_user_level(&tclie));
	PASS();
}

TEST login_gives_up_after_repeated_failures(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	assert(tclie_reg_users(&tclie, users, sizeof(users) / sizeof(users[0])));

	tclie_in_str(&tclie, "login\r");
#if TCLIE_ENABLE_USERNAMES
	tclie_in_str(&tclie, "admin\r");
#endif

	for (unsigned i = 0; i <= TCLIE_LOGIN_ATTEMPTS; i++)
		tclie_in_str(&tclie, "wrong\r");

	ASSERT(test_out_has(&ctx, "Failed!"));

	// The attempt is over: the correct password is now just an unknown command.
	test_clear_out(&ctx);
	tclie_in_str(&tclie, "12345\r");
	ASSERT_EQ(LEVEL_DEFAULT, (int)tclie_get_user_level(&tclie));
	ASSERT(test_out_has(&ctx, "Unknown command"));
	PASS();
}

TEST sigint_aborts_login(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	assert(tclie_reg_users(&tclie, users, sizeof(users) / sizeof(users[0])));

	tclie_in_str(&tclie, "login\r");
	tclie_in_str(&tclie, "\x03");

	ASSERT(test_out_has(&ctx, "Aborted!"));

	// Not in the login dialogue any more, so the password is not accepted.
	test_clear_out(&ctx);
	tclie_in_str(&tclie, "12345\r");
	ASSERT_EQ(LEVEL_DEFAULT, (int)tclie_get_user_level(&tclie));
	PASS();
}

#endif

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	RUN_TEST(help_lists_registered_commands);
#if TCLIE_PATTERN_MATCH
	RUN_TEST(question_mark_is_an_alias_for_help);
#endif
	RUN_TEST(help_with_argument_describes_one_command);
	RUN_TEST(clear_emits_clear_screen_sequence);
	RUN_TEST(unknown_command_is_reported);
	RUN_TEST(registered_command_runs);
#if TCLIE_ENABLE_USERS
	RUN_TEST(help_hides_commands_above_user_level);
	RUN_TEST(logout_is_hidden_until_logged_in);
	RUN_TEST(logout_drops_privileges);
	RUN_TEST(login_grants_the_user_level);
	RUN_TEST(password_is_not_echoed);
	RUN_TEST(password_is_not_kept_in_history);
	RUN_TEST(wrong_password_keeps_default_level);
	RUN_TEST(login_gives_up_after_repeated_failures);
	RUN_TEST(sigint_aborts_login);
#endif
	GREATEST_MAIN_END();
}
