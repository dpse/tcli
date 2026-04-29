#include "greatest.h"
#include "tclie.h"
#include <assert.h>
#include <string.h>

GREATEST_MAIN_DEFS();

enum { LEVEL_DEFAULT = 0, LEVEL_USER = 1, LEVEL_ADMIN = 2 };

typedef struct {
	int default_calls;
	int user_calls;
	int admin_calls;
} test_ctx_t;

static void test_out(void *const arg, const char *const str)
{
	(void)arg;
	(void)str;
}

static int cmd_default(void *const arg, const int argc, const char **const argv)
{
	(void)argc;
	(void)argv;
	((test_ctx_t *)arg)->default_calls++;
	return 0;
}

static int cmd_user(void *const arg, const int argc, const char **const argv)
{
	(void)argc;
	(void)argv;
	((test_ctx_t *)arg)->user_calls++;
	return 0;
}

static int cmd_admin(void *const arg, const int argc, const char **const argv)
{
	(void)argc;
	(void)argv;
	((test_ctx_t *)arg)->admin_calls++;
	return 0;
}

#if TCLIE_ENABLE_USERS

static const tclie_cmd_t cmds[] = {
	{"public", cmd_default, LEVEL_DEFAULT, "Public command."
#if TCLIE_PATTERN_MATCH
	 ,
	 "public"
#endif
	},
	{"userspace", cmd_user, LEVEL_USER, "Requires user."
#if TCLIE_PATTERN_MATCH
	 ,
	 "userspace"
#endif
	},
	{"adminspace", cmd_admin, LEVEL_ADMIN, "Admin only."
#if TCLIE_PATTERN_MATCH
	 ,
	 "adminspace"
#endif
	},
};

static const tclie_user_t login_users[] = {
#if TCLIE_ENABLE_USERNAMES
	{"debug", NULL, LEVEL_USER},
	{"admin", "12345", LEVEL_ADMIN},
#else
	{NULL, "12345", LEVEL_ADMIN},
#endif
};

#define LOGIN_USERS_COUNT (sizeof(login_users) / sizeof(login_users[0]))

static void init(tclie_t *const tclie, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tclie_init(tclie, test_out, ctx);
	assert(tclie_reg_cmds(tclie, cmds, sizeof(cmds) / sizeof(cmds[0])));
}

TEST default_level_can_run_public(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_input_str(&tclie, "public\r");
	ASSERT_EQ(1, ctx.default_calls);
	PASS();
}

TEST default_level_blocked_from_user(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_input_str(&tclie, "userspace\r");
	ASSERT_EQ(0, ctx.user_calls);
	PASS();
}

TEST default_level_blocked_from_admin(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_input_str(&tclie, "adminspace\r");
	ASSERT_EQ(0, ctx.admin_calls);
	PASS();
}

TEST user_level_unlocks_user_command(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	tclie_set_user_level(&tclie, LEVEL_USER);

	tclie_input_str(&tclie, "userspace\r");
	ASSERT_EQ(1, ctx.user_calls);

	tclie_input_str(&tclie, "adminspace\r");
	ASSERT_EQ(0, ctx.admin_calls);
	PASS();
}

TEST admin_level_unlocks_all(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	tclie_set_user_level(&tclie, LEVEL_ADMIN);

	tclie_input_str(&tclie, "public\r");
	tclie_input_str(&tclie, "userspace\r");
	tclie_input_str(&tclie, "adminspace\r");
	ASSERT_EQ(1, ctx.default_calls);
	ASSERT_EQ(1, ctx.user_calls);
	ASSERT_EQ(1, ctx.admin_calls);
	PASS();
}

TEST get_user_level_reflects_set(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	ASSERT_EQ(LEVEL_DEFAULT, (int)tclie_get_user_level(&tclie));
	tclie_set_user_level(&tclie, LEVEL_ADMIN);
	ASSERT_EQ(LEVEL_ADMIN, (int)tclie_get_user_level(&tclie));
	PASS();
}

TEST login_with_correct_password_unlocks_admin(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	assert(tclie_reg_users(&tclie, login_users, LOGIN_USERS_COUNT));

	ASSERT_EQ(LEVEL_DEFAULT, (int)tclie_get_user_level(&tclie));

#if TCLIE_ENABLE_USERNAMES
	tclie_input_str(&tclie, "login\r");
	tclie_input_str(&tclie, "admin\r");
	tclie_input_str(&tclie, "12345\r");
#else
	tclie_input_str(&tclie, "login\r");
	tclie_input_str(&tclie, "12345\r");
#endif

	ASSERT_EQ(LEVEL_ADMIN, (int)tclie_get_user_level(&tclie));

	tclie_input_str(&tclie, "adminspace\r");
	ASSERT_EQ(1, ctx.admin_calls);
	PASS();
}

TEST login_with_wrong_password_keeps_default_level(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	assert(tclie_reg_users(&tclie, login_users, LOGIN_USERS_COUNT));

#if TCLIE_ENABLE_USERNAMES
	tclie_input_str(&tclie, "login\r");
	tclie_input_str(&tclie, "admin\r");
	tclie_input_str(&tclie, "wrong\r");
#else
	tclie_input_str(&tclie, "login\r");
	tclie_input_str(&tclie, "wrong\r");
#endif

	ASSERT_EQ(LEVEL_DEFAULT, (int)tclie_get_user_level(&tclie));

	tclie_input_str(&tclie, "adminspace\r");
	ASSERT_EQ(0, ctx.admin_calls);
	PASS();
}

#if TCLIE_ENABLE_USERNAMES
TEST login_with_passwordless_user(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);
	assert(tclie_reg_users(&tclie, login_users, LOGIN_USERS_COUNT));

	tclie_input_str(&tclie, "login\r");
	tclie_input_str(&tclie, "debug\r");

	ASSERT_EQ(LEVEL_USER, (int)tclie_get_user_level(&tclie));
	PASS();
}
#endif

#endif

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
#if TCLIE_ENABLE_USERS
	RUN_TEST(default_level_can_run_public);
	RUN_TEST(default_level_blocked_from_user);
	RUN_TEST(default_level_blocked_from_admin);
	RUN_TEST(user_level_unlocks_user_command);
	RUN_TEST(admin_level_unlocks_all);
	RUN_TEST(get_user_level_reflects_set);
	RUN_TEST(login_with_correct_password_unlocks_admin);
	RUN_TEST(login_with_wrong_password_keeps_default_level);
#if TCLIE_ENABLE_USERNAMES
	RUN_TEST(login_with_passwordless_user);
#endif
#endif
	GREATEST_MAIN_END();
}
