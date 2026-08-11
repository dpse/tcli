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

TEST cr_executes_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "cmd\r");
	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("cmd", test_arg(&ctx, 0));
	PASS();
}

TEST lf_executes_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "cmd\n");
	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("cmd", test_arg(&ctx, 0));
	PASS();
}

TEST crlf_executes_once(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "cmd\r\n");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST lfcr_executes_once(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "cmd\n\r");
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST telnet_cr_nul_executes_once(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	// Telnet sends <CR><NUL> for a newline; the NUL must not start a line of
	// its own. tcli_in is used since the NUL cannot travel in a C string.
	static const char input[] = {'o', 'n', 'e', '\r', '\0',
								 't', 'w', 'o', '\r', '\0'};
	tcli_in(&tcli, input, sizeof(input));

	ASSERT_EQ(2, ctx.calls);
	ASSERT_STR_EQ("two", test_arg(&ctx, 0));
	PASS();
}

TEST empty_lines_do_not_execute(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "\r\r\n   \r");
	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST in_char_and_in_str_agree(void)
{
	tcli_t tcli_a;
	tcli_t tcli_b;
	test_ctx_t ctx_a;
	test_ctx_t ctx_b;
	init(&tcli_a, &ctx_a);
	init(&tcli_b, &ctx_b);

	tcli_in_str(&tcli_a, "one two\r");
	for (const char *c = "one two\r"; *c != '\0'; c++)
		tcli_in_char(&tcli_b, *c);

	ASSERT_EQ(ctx_a.calls, ctx_b.calls);
	ASSERT_EQ(ctx_a.argc, ctx_b.argc);
	ASSERT_STR_EQ(test_arg(&ctx_a, 1), test_arg(&ctx_b, 1));
	ASSERT_STR_EQ(ctx_a.out, ctx_b.out);
	PASS();
}

TEST tokens_split_on_whitespace_runs(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "   one    two  three   \r");
	ASSERT_EQ(3, ctx.argc);
	ASSERT_STR_EQ("one", test_arg(&ctx, 0));
	ASSERT_STR_EQ("two", test_arg(&ctx, 1));
	ASSERT_STR_EQ("three", test_arg(&ctx, 2));
	PASS();
}

TEST double_quoted_token_keeps_spaces(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "echo \"a b\" c\r");
	ASSERT_EQ(3, ctx.argc);
	ASSERT_STR_EQ("a b", test_arg(&ctx, 1));
	ASSERT_STR_EQ("c", test_arg(&ctx, 2));
	PASS();
}

TEST single_quoted_token_keeps_spaces(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "echo 'a b'\r");
	ASSERT_EQ(2, ctx.argc);
	ASSERT_STR_EQ("a b", test_arg(&ctx, 1));
	PASS();
}

TEST line_length_is_clamped(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	for (int i = 0; i < TCLI_CMDLINE_MAX_LEN + 32; i++)
		tcli_in_char(&tcli, 'a');
	tcli_in_char(&tcli, '\r');

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(1, ctx.argc);
	ASSERT_EQ((size_t)TCLI_CMDLINE_MAX_LEN, strlen(test_arg(&ctx, 0)));
	PASS();
}

TEST token_count_is_clamped(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	for (int i = 0; i < TCLI_MAX_TOKENS + 4; i++)
		tcli_in_str(&tcli, "t ");
	tcli_in_char(&tcli, '\r');

	ASSERT_EQ(1, ctx.calls);
	ASSERT_EQ(TCLI_MAX_TOKENS, ctx.argc);
	PASS();
}

TEST non_printable_input_is_ignored(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	static const char input[] = {'a', 0x1f, 'b', (char)0x80, 'c', '\r'};
	tcli_in(&tcli, input, sizeof(input));

	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("abc", test_arg(&ctx, 0));
	PASS();
}

TEST error_prompt_follows_failed_command(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_prompt(&tcli, "ok>");
	tcli_set_error_prompt(&tcli, "err>");

	ctx.res = -1;
	tcli_in_str(&tcli, "fail\r");
	ASSERT(test_out_has(&ctx, "err>"));

	test_clear_out(&ctx);
	ctx.res = 0;
	tcli_in_str(&tcli, "pass\r");
	ASSERT(test_out_has(&ctx, "ok>"));
	PASS();
}

TEST default_prompt_restored_when_set_to_null(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_set_prompt(&tcli, "custom>");
	test_clear_out(&ctx);
	tcli_set_prompt(&tcli, NULL);

	ASSERT_FALSE(test_out_has(&ctx, "custom>"));
	ASSERT(test_out_has(&ctx, "> "));
	PASS();
}

TEST echo_off_once_masks_the_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_echo(&tcli, TCLI_ECHO_OFF_ONCE);

	tcli_in_str(&tcli, "secret\r");
	ASSERT_FALSE(test_out_has(&ctx, "secret"));
	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("secret", test_arg(&ctx, 0));
	PASS();
}

TEST echo_off_once_is_cleared_after_the_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_echo(&tcli, TCLI_ECHO_OFF_ONCE);

	tcli_in_str(&tcli, "secret\r");

	test_clear_out(&ctx);
	tcli_in_str(&tcli, "shown\r");
	ASSERT(test_out_has(&ctx, "shown"));
	PASS();
}

TEST echo_off_masks_input(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_echo(&tcli, TCLI_ECHO_OFF);

	tcli_in_str(&tcli, "pw");
	ASSERT_FALSE(test_out_has(&ctx, "pw"));
	ASSERT(test_out_has(&ctx, "*"));
	PASS();
}

TEST log_at_prompt_redraws_prompt(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc");
	test_clear_out(&ctx);
	tcli_log(&tcli, "note\r\n");

	ASSERT(test_out_has(&ctx, "note"));
	ASSERT(test_out_has(&ctx, "> "));
	ASSERT(test_out_has(&ctx, "abc"));
	PASS();
}

static tcli_t *log_target = NULL;

static int exec_logging(void *const arg, const int argc,
						const char **const argv)
{
	const int res = test_exec(arg, argc, argv);
	tcli_log(log_target, "from-command\r\n");
	return res;
}

TEST log_during_execution_is_written_directly(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	log_target = &tcli;
	tcli_set_exec(&tcli, exec_logging);

	test_clear_out(&ctx);
	tcli_in_str(&tcli, "cmd\r");

	ASSERT(test_out_has(&ctx, "from-command"));
	ASSERT_EQ(1, ctx.calls);
	PASS();
}

TEST null_instance_is_tolerated(void)
{
	tcli_in_char(NULL, 'a');
	tcli_in_str(NULL, "abc");
	tcli_in(NULL, "abc", 3);
	tcli_flush(NULL);
	tcli_log(NULL, "abc");
	tcli_clear_screen(NULL);
	PASS();
}

TEST null_string_is_tolerated(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, NULL);
	tcli_in(&tcli, NULL, 3);
	tcli_out(&tcli, NULL);
	tcli_log(&tcli, NULL);
	ASSERT_EQ(0, ctx.calls);
	PASS();
}

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	RUN_TEST(cr_executes_line);
	RUN_TEST(lf_executes_line);
	RUN_TEST(crlf_executes_once);
	RUN_TEST(lfcr_executes_once);
	RUN_TEST(telnet_cr_nul_executes_once);
	RUN_TEST(empty_lines_do_not_execute);
	RUN_TEST(in_char_and_in_str_agree);
	RUN_TEST(tokens_split_on_whitespace_runs);
	RUN_TEST(double_quoted_token_keeps_spaces);
	RUN_TEST(single_quoted_token_keeps_spaces);
	RUN_TEST(line_length_is_clamped);
	RUN_TEST(token_count_is_clamped);
	RUN_TEST(non_printable_input_is_ignored);
	RUN_TEST(error_prompt_follows_failed_command);
	RUN_TEST(default_prompt_restored_when_set_to_null);
	RUN_TEST(echo_off_once_masks_the_line);
	RUN_TEST(echo_off_once_is_cleared_after_the_line);
	RUN_TEST(echo_off_masks_input);
	RUN_TEST(log_at_prompt_redraws_prompt);
	RUN_TEST(log_during_execution_is_written_directly);
	RUN_TEST(null_instance_is_tolerated);
	RUN_TEST(null_string_is_tolerated);
	GREATEST_MAIN_END();
}
