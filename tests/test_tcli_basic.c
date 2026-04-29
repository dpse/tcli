#include "greatest.h"
#include "tcli.h"
#include <string.h>

GREATEST_MAIN_DEFS();

#define OUT_BUF_LEN 256

typedef struct {
	char out_buf[OUT_BUF_LEN];
	size_t out_len;
	int exec_argc;
	char exec_argv0[64];
	int exec_calls;
} test_ctx_t;

static void test_out(void *const arg, const char *const str)
{
	test_ctx_t *const ctx = arg;
	const size_t len = strlen(str);
	if (ctx->out_len + len < sizeof(ctx->out_buf)) {
		memcpy(ctx->out_buf + ctx->out_len, str, len);
		ctx->out_len += len;
		ctx->out_buf[ctx->out_len] = '\0';
	}
}

static int test_exec(void *const arg, const int argc, const char **const argv)
{
	test_ctx_t *const ctx = arg;
	ctx->exec_calls++;
	ctx->exec_argc = argc;
	if (argc > 0) {
		strncpy(ctx->exec_argv0, argv[0], sizeof(ctx->exec_argv0) - 1);
		ctx->exec_argv0[sizeof(ctx->exec_argv0) - 1] = '\0';
	} else
		ctx->exec_argv0[0] = '\0';
	return 0;
}

TEST init_does_not_crash(void)
{
	tcli_t tcli;
	test_ctx_t ctx = {0};
	tcli_init(&tcli, test_out, &ctx);
	PASS();
}

TEST exec_fires_on_enter(void)
{
	tcli_t tcli;
	test_ctx_t ctx = {0};
	tcli_init(&tcli, test_out, &ctx);
	tcli_set_exec(&tcli, test_exec);

	tcli_input_str(&tcli, "hello\r");

	ASSERT_EQ(1, ctx.exec_calls);
	ASSERT_EQ(1, ctx.exec_argc);
	ASSERT_STR_EQ("hello", ctx.exec_argv0);
	PASS();
}

TEST exec_argc_counts_tokens(void)
{
	tcli_t tcli;
	test_ctx_t ctx = {0};
	tcli_init(&tcli, test_out, &ctx);
	tcli_set_exec(&tcli, test_exec);

	tcli_input_str(&tcli, "one two three\r");

	ASSERT_EQ(1, ctx.exec_calls);
	ASSERT_EQ(3, ctx.exec_argc);
	PASS();
}

TEST exec_not_called_without_enter(void)
{
	tcli_t tcli;
	test_ctx_t ctx = {0};
	tcli_init(&tcli, test_out, &ctx);
	tcli_set_exec(&tcli, test_exec);

	tcli_input_str(&tcli, "incomplete");

	ASSERT_EQ(0, ctx.exec_calls);
	PASS();
}

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	RUN_TEST(init_does_not_crash);
	RUN_TEST(exec_fires_on_enter);
	RUN_TEST(exec_argc_counts_tokens);
	RUN_TEST(exec_not_called_without_enter);
	GREATEST_MAIN_END();
}
