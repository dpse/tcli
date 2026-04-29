#include "greatest.h"
#include "tclie.h"
#include <assert.h>
#include <string.h>

GREATEST_MAIN_DEFS();

#define ORDER_LEN 8

typedef struct {
	int pre_calls;
	int post_calls;
	int exec_calls;
	int last_pre_argc;
	char last_pre_argv0[32];
	int last_post_argc;
	int last_post_res;
	char order[ORDER_LEN + 1];
	size_t order_len;
} test_ctx_t;

static void record(test_ctx_t *ctx, char tag)
{
	if (ctx->order_len < ORDER_LEN) {
		ctx->order[ctx->order_len++] = tag;
		ctx->order[ctx->order_len] = '\0';
	}
}

static void test_out(void *arg, const char *str)
{
	(void)arg;
	(void)str;
}

static void pre_cmd(void *arg, int argc, const char **argv)
{
	test_ctx_t *ctx = arg;
	ctx->pre_calls++;
	ctx->last_pre_argc = argc;
	if (argc > 0) {
		strncpy(ctx->last_pre_argv0, argv[0],
				sizeof(ctx->last_pre_argv0) - 1);
		ctx->last_pre_argv0[sizeof(ctx->last_pre_argv0) - 1] = '\0';
	}
	record(ctx, 'P');
}

static void post_cmd(void *arg, int argc, const char **argv, int res)
{
	(void)argv;
	test_ctx_t *ctx = arg;
	ctx->post_calls++;
	ctx->last_post_argc = argc;
	ctx->last_post_res = res;
	record(ctx, 'p');
}

static int cmd_ok(void *arg, int argc, const char **argv)
{
	(void)argc;
	(void)argv;
	test_ctx_t *ctx = arg;
	ctx->exec_calls++;
	record(ctx, 'E');
	return 0;
}

static int cmd_fail(void *arg, int argc, const char **argv)
{
	(void)argc;
	(void)argv;
	test_ctx_t *ctx = arg;
	ctx->exec_calls++;
	record(ctx, 'E');
	return -1;
}

static const tclie_cmd_t cmds[] = {
	{"ok", cmd_ok, 0, "Returns 0."
#if TCLIE_PATTERN_MATCH
	 ,
	 "ok"
#endif
	},
	{"fail", cmd_fail, 0, "Returns -1."
#if TCLIE_PATTERN_MATCH
	 ,
	 "fail"
#endif
	},
};

static void init(tclie_t *tclie, test_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tclie_init(tclie, test_out, ctx);
	tclie_set_pre_cmd(tclie, pre_cmd);
	tclie_set_post_cmd(tclie, post_cmd);
	assert(tclie_reg_cmds(tclie, cmds, sizeof(cmds) / sizeof(cmds[0])));
}

TEST hooks_fire_in_order_around_exec(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_input_str(&tclie, "ok\r");
	ASSERT_EQ(1, ctx.pre_calls);
	ASSERT_EQ(1, ctx.exec_calls);
	ASSERT_EQ(1, ctx.post_calls);
	ASSERT_STR_EQ("PEp", ctx.order);
	PASS();
}

TEST pre_hook_sees_command_args(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_input_str(&tclie, "ok\r");
	ASSERT_EQ(1, ctx.last_pre_argc);
	ASSERT_STR_EQ("ok", ctx.last_pre_argv0);
	PASS();
}

TEST post_hook_receives_exec_result(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_input_str(&tclie, "ok\r");
	ASSERT_EQ(0, ctx.last_post_res);

	tclie_input_str(&tclie, "fail\r");
	ASSERT_EQ(-1, ctx.last_post_res);
	PASS();
}

TEST hooks_not_called_for_unknown_command(void)
{
	tclie_t tclie;
	test_ctx_t ctx;
	init(&tclie, &ctx);

	tclie_input_str(&tclie, "doesnotexist\r");
	ASSERT_EQ(0, ctx.exec_calls);
	ASSERT_EQ(0, ctx.pre_calls);
	ASSERT_EQ(0, ctx.post_calls);
	PASS();
}

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	RUN_TEST(hooks_fire_in_order_around_exec);
	RUN_TEST(pre_hook_sees_command_args);
	RUN_TEST(post_hook_receives_exec_result);
	RUN_TEST(hooks_not_called_for_unknown_command);
	GREATEST_MAIN_END();
}
