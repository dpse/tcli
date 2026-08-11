#include "greatest.h"
#include "tcli.h"
#include "test_helpers.h"
#include <stdio.h>

GREATEST_MAIN_DEFS();

#define UP "\x1b[A"
#define DOWN "\x1b[B"
#define CTRL_P "\x10"
#define CTRL_N "\x0e"
#define CTRL_R "\x12"
#define CTRL_G "\x07"
#define CTRL_U "\x15"
#define CTRL_K "\x0b"
#define ALT_R                                                                  \
	"\x1b"                                                                     \
	"r"
#define DEL "\x7f"

#if TCLI_HISTORY_BUF_LEN > 0

static void init(tcli_t *const tcli, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tcli_init(tcli, test_out, ctx);
	tcli_set_exec(tcli, test_exec);
}

TEST previous_lines_are_recalled_newest_first(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "one\r");
	tcli_in_str(&tcli, "two\r");

	tcli_in_str(&tcli, UP "\r");
	ASSERT_STR_EQ("two", test_arg(&ctx, 0));

	tcli_in_str(&tcli, UP UP "\r");
	ASSERT_STR_EQ("one", test_arg(&ctx, 0));
	PASS();
}

TEST ctrl_p_and_ctrl_n_walk_history(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "one\r");
	tcli_in_str(&tcli, "two\r");

	tcli_in_str(&tcli, CTRL_P CTRL_P CTRL_N "\r");
	ASSERT_STR_EQ("two", test_arg(&ctx, 0));
	PASS();
}

TEST down_past_newest_clears_the_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "one\r");
	const int before = ctx.calls;

	tcli_in_str(&tcli, UP DOWN "\r");
	ASSERT_EQ(before, ctx.calls);
	PASS();
}

TEST up_past_oldest_keeps_oldest(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "one\r");

	tcli_in_str(&tcli, UP UP UP "\r");
	ASSERT_STR_EQ("one", test_arg(&ctx, 0));
	PASS();
}

TEST consecutive_duplicates_are_stored_once(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "a\r");
	tcli_in_str(&tcli, "b\r");
	tcli_in_str(&tcli, "b\r");
	tcli_in_str(&tcli, "c\r");

	// Three entries, so three steps back reaches "a" rather than the repeat.
	tcli_in_str(&tcli, UP UP UP "\r");
	ASSERT_STR_EQ("a", test_arg(&ctx, 0));
	PASS();
}

TEST trailing_spaces_are_not_stored(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "cmd   \r");

	test_clear_out(&ctx);
	tcli_in_str(&tcli, UP);
	ASSERT(test_out_has(&ctx, "cmd"));

	tcli_in_str(&tcli, "X\r");
	ASSERT_EQ(1, ctx.argc);
	ASSERT_STR_EQ("cmdX", test_arg(&ctx, 0));
	PASS();
}

TEST edited_recall_does_not_replace_stored_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "original\r");

	tcli_in_str(&tcli, UP DEL DEL CTRL_U "\r");

	tcli_in_str(&tcli, UP "\r");
	ASSERT_STR_EQ("original", test_arg(&ctx, 0));
	PASS();
}

TEST alt_r_restores_the_recalled_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "original\r");

	tcli_in_str(&tcli, UP DEL DEL ALT_R "\r");
	ASSERT_STR_EQ("original", test_arg(&ctx, 0));
	PASS();
}

TEST history_off_does_not_record(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_hist(&tcli, TCLI_HIST_OFF);

	tcli_in_str(&tcli, "hidden\r");
	const int before = ctx.calls;

	tcli_in_str(&tcli, UP "\r");
	ASSERT_EQ(before, ctx.calls);
	PASS();
}

TEST history_off_once_skips_the_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_hist(&tcli, TCLI_HIST_OFF_ONCE);

	tcli_in_str(&tcli, "hidden\r");

	const int before = ctx.calls;
	tcli_in_str(&tcli, UP "\r");
	ASSERT_EQ(before, ctx.calls);
	PASS();
}

TEST history_off_once_is_cleared_after_the_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_hist(&tcli, TCLI_HIST_OFF_ONCE);

	tcli_in_str(&tcli, "hidden\r");
	tcli_in_str(&tcli, "kept\r");

	const int before = ctx.calls;
	tcli_in_str(&tcli, UP "\r");
	ASSERT_EQ(before + 1, ctx.calls);
	ASSERT_STR_EQ("kept", test_arg(&ctx, 0));
	PASS();
}

TEST masked_lines_are_not_recorded(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_set_echo(&tcli, TCLI_ECHO_OFF);
	tcli_in_str(&tcli, "secret\r");
	tcli_set_echo(&tcli, TCLI_ECHO_ON);
	tcli_in_str(&tcli, "public\r");

	// Exactly one entry is recallable, and it is the visible one.
	const int before = ctx.calls;
	tcli_in_str(&tcli, UP UP "\r");
	ASSERT_EQ(before + 1, ctx.calls);
	ASSERT_STR_EQ("public", test_arg(&ctx, 0));
	PASS();
}

TEST oldest_entries_are_evicted_when_full(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	// Overfill the ring by a wide margin (entries are 7 bytes each here).
	const int lines = (TCLI_HISTORY_BUF_LEN / 4) + 8;
	for (int i = 0; i < lines; i++) {
		char line[16];
		snprintf(line, sizeof(line), "l%05d\r", i);
		tcli_in_str(&tcli, line);
	}

	// Walk further back than the ring can hold; the first line must be gone.
	for (int i = 0; i < lines; i++)
		tcli_in_str(&tcli, UP);
	tcli_in_str(&tcli, "\r");

	ASSERT_EQ(1, ctx.argc);
	ASSERT(strcmp("l00000", test_arg(&ctx, 0)) != 0);
	PASS();
}

TEST search_finds_matching_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "alpha\r");
	tcli_in_str(&tcli, "beta\r");

	tcli_in_str(&tcli, CTRL_R "al"
							  "\r");
	ASSERT_STR_EQ("alpha", test_arg(&ctx, 0));
	PASS();
}

TEST search_prompt_is_shown(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_search_prompt(&tcli, "search>");

	tcli_in_str(&tcli, "alpha\r");
	test_clear_out(&ctx);
	tcli_in_str(&tcli, CTRL_R);

	ASSERT(test_out_has(&ctx, "search>"));
	PASS();
}

TEST search_without_match_keeps_typed_text(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "alpha\r");
	tcli_in_str(&tcli, CTRL_R "zz"
							  "\r");

	ASSERT_STR_EQ("zz", test_arg(&ctx, 0));
	PASS();
}

TEST ctrl_g_leaves_search_mode(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "alpha\r");

	// Ctrl+u and ctrl+k clear before and after the cursor respectively.
	tcli_in_str(&tcli, CTRL_R "al" CTRL_G CTRL_U CTRL_K "plain\r");
	ASSERT_STR_EQ("plain", test_arg(&ctx, 0));

	test_clear_out(&ctx);
	tcli_in_str(&tcli, "x");
	ASSERT_FALSE(test_out_has(&ctx, "alpha"));
	PASS();
}

#endif

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
#if TCLI_HISTORY_BUF_LEN > 0
	RUN_TEST(previous_lines_are_recalled_newest_first);
	RUN_TEST(ctrl_p_and_ctrl_n_walk_history);
	RUN_TEST(down_past_newest_clears_the_line);
	RUN_TEST(up_past_oldest_keeps_oldest);
	RUN_TEST(consecutive_duplicates_are_stored_once);
	RUN_TEST(trailing_spaces_are_not_stored);
	RUN_TEST(edited_recall_does_not_replace_stored_line);
	RUN_TEST(alt_r_restores_the_recalled_line);
	RUN_TEST(history_off_does_not_record);
	RUN_TEST(history_off_once_skips_the_line);
	RUN_TEST(history_off_once_is_cleared_after_the_line);
	RUN_TEST(masked_lines_are_not_recorded);
	RUN_TEST(oldest_entries_are_evicted_when_full);
	RUN_TEST(search_finds_matching_line);
	RUN_TEST(search_prompt_is_shown);
	RUN_TEST(search_without_match_keeps_typed_text);
	RUN_TEST(ctrl_g_leaves_search_mode);
#endif
	GREATEST_MAIN_END();
}
