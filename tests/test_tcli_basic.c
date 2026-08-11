#include "greatest.h"
#include "tcli.h"
#include "test_helpers.h"

GREATEST_MAIN_DEFS();

static void init(tcli_t *const tcli, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tcli_init(tcli, test_out, ctx);
	tcli_set_exec(tcli, test_exec);
}

TEST init_writes_the_prompt(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	tcli_init(&tcli, test_out, &ctx);

	ASSERT(test_out_has(&ctx, "> "));
	PASS();
}

TEST exec_fires_on_enter(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "hello\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(1, ctx.argc);
	ASSERT_STR_EQ("hello", test_arg(&ctx, 0));
	PASS();
}

TEST exec_argc_counts_tokens(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "one two three\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(3, ctx.argc);
	ASSERT_STR_EQ("one", test_arg(&ctx, 0));
	ASSERT_STR_EQ("two", test_arg(&ctx, 1));
	ASSERT_STR_EQ("three", test_arg(&ctx, 2));
	PASS();
}

TEST exec_not_called_without_enter(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "incomplete");

	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST input_is_echoed(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	test_clear_out(&ctx);
	tcli_in_str(&tcli, "abc");

	ASSERT(test_out_has(&ctx, "a"));
	ASSERT(test_out_has(&ctx, "c"));
	PASS();
}

TEST line_is_cleared_after_execution(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "hello\r");
	// A second enter has nothing left to run.
	tcli_in_str(&tcli, "\r");

	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST exec_can_be_replaced(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_set_exec(&tcli, NULL);
	tcli_in_str(&tcli, "hello\r");
	ASSERT_EQ(0, ctx.calls);

	tcli_set_exec(&tcli, test_exec);
	tcli_in_str(&tcli, "hello\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	RUN_TEST(init_writes_the_prompt);
	RUN_TEST(exec_fires_on_enter);
	RUN_TEST(exec_argc_counts_tokens);
	RUN_TEST(exec_not_called_without_enter);
	RUN_TEST(input_is_echoed);
	RUN_TEST(line_is_cleared_after_execution);
	RUN_TEST(exec_can_be_replaced);
	GREATEST_MAIN_END();
}
