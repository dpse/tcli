// Editing is asserted through the command line that reaches the exec callback.
#include "greatest.h"
#include "tcli.h"
#include "test_helpers.h"

GREATEST_MAIN_DEFS();

#define CTRL_A "\x01" // Cursor to line start
#define CTRL_B "\x02" // Cursor back one
#define CTRL_D "\x04" // Delete at cursor
#define CTRL_E "\x05" // Cursor to line end
#define CTRL_F "\x06" // Cursor forward one
#define CTRL_H "\x08" // Delete previous
#define CTRL_K "\x0b" // Clear after cursor
#define CTRL_U "\x15" // Clear before cursor
#define CTRL_W "\x17" // Clear word before cursor
#define DEL "\x7f"	  // Delete previous

// Alt+<key> arrives as ESC followed by the key (split to end the hex escape).
#define ALT_B                                                                  \
	"\x1b"                                                                     \
	"b" // Cursor back one word
#define ALT_D                                                                  \
	"\x1b"                                                                     \
	"d" // Delete word after cursor
#define ALT_F                                                                  \
	"\x1b"                                                                     \
	"f" // Cursor forward one word

#define ARROW_LEFT "\x1b[D"
#define ARROW_RIGHT "\x1b[C"
#define KEY_HOME "\x1b[1~"
#define KEY_END "\x1b[4~"
#define KEY_DELETE "\x1b[3~"

static void init(tcli_t *const tcli, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tcli_init(tcli, test_out, ctx);
	tcli_set_exec(tcli, test_exec);
}

TEST ctrl_a_moves_to_line_start(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc" CTRL_A "X\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("Xabc", test_arg(&ctx, 0));
	PASS();
}

TEST ctrl_e_moves_to_line_end(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc" CTRL_A CTRL_E "X\r");

	ASSERT_STR_EQ("abcX", test_arg(&ctx, 0));
	PASS();
}

TEST ctrl_b_and_ctrl_f_move_one_character(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc" CTRL_B "X\r");
	ASSERT_STR_EQ("abXc", test_arg(&ctx, 0));

	tcli_in_str(&tcli, "abc" CTRL_A CTRL_F "X\r");
	ASSERT_STR_EQ("aXbc", test_arg(&ctx, 0));
	PASS();
}

TEST arrow_keys_move_one_character(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc" ARROW_LEFT ARROW_LEFT "X\r");
	ASSERT_STR_EQ("aXbc", test_arg(&ctx, 0));

	tcli_in_str(&tcli, "abc" ARROW_LEFT ARROW_LEFT ARROW_RIGHT "X\r");
	ASSERT_STR_EQ("abXc", test_arg(&ctx, 0));
	PASS();
}

TEST home_and_end_keys_move_to_line_bounds(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc" KEY_HOME "X\r");
	ASSERT_STR_EQ("Xabc", test_arg(&ctx, 0));

	tcli_in_str(&tcli, "abc" KEY_HOME KEY_END "X\r");
	ASSERT_STR_EQ("abcX", test_arg(&ctx, 0));
	PASS();
}

TEST backspace_deletes_previous_character(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc" DEL "\r");
	ASSERT_STR_EQ("ab", test_arg(&ctx, 0));

	tcli_in_str(&tcli, "abc" CTRL_H "\r");
	ASSERT_STR_EQ("ab", test_arg(&ctx, 0));
	PASS();
}

TEST backspace_at_line_start_does_nothing(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, DEL DEL "ab\r");
	ASSERT_STR_EQ("ab", test_arg(&ctx, 0));
	PASS();
}

TEST ctrl_d_deletes_character_at_cursor(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc" CTRL_A CTRL_D "\r");
	ASSERT_STR_EQ("bc", test_arg(&ctx, 0));
	PASS();
}

TEST delete_key_deletes_character_at_cursor(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc" KEY_HOME KEY_DELETE "\r");
	ASSERT_STR_EQ("bc", test_arg(&ctx, 0));
	PASS();
}

TEST ctrl_u_clears_before_cursor(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abcdef" ARROW_LEFT ARROW_LEFT ARROW_LEFT CTRL_U "\r");
	ASSERT_STR_EQ("def", test_arg(&ctx, 0));
	PASS();
}

TEST ctrl_k_clears_after_cursor(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abcdef" ARROW_LEFT ARROW_LEFT ARROW_LEFT CTRL_K "\r");
	ASSERT_STR_EQ("abc", test_arg(&ctx, 0));
	PASS();
}

TEST ctrl_u_on_whole_line_leaves_nothing_to_execute(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc" CTRL_U "\r");
	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST ctrl_w_clears_word_before_cursor(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	// Exactly the word must go, so re-typing gives a two token line back.
	tcli_in_str(&tcli, "foo bar" CTRL_W "baz\r");
	ASSERT_EQ(2, ctx.argc);
	ASSERT_STR_EQ("foo", test_arg(&ctx, 0));
	ASSERT_STR_EQ("baz", test_arg(&ctx, 1));
	PASS();
}

TEST alt_d_deletes_word_after_cursor(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "foo bar" CTRL_A ALT_D "\r");
	ASSERT_EQ(1, ctx.argc);
	ASSERT_STR_EQ("bar", test_arg(&ctx, 0));
	PASS();
}

TEST alt_b_and_alt_f_move_by_word(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "foo bar" ALT_B "X\r");
	ASSERT_EQ(2, ctx.argc);
	ASSERT_STR_EQ("foo", test_arg(&ctx, 0));
	ASSERT_STR_EQ("Xbar", test_arg(&ctx, 1));

	tcli_in_str(&tcli, "foo bar" CTRL_A ALT_F "X\r");
	ASSERT_EQ(2, ctx.argc);
	ASSERT_STR_EQ("fooX", test_arg(&ctx, 0));
	ASSERT_STR_EQ("bar", test_arg(&ctx, 1));
	PASS();
}

TEST cursor_stops_at_line_bounds(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "ab" ARROW_RIGHT ARROW_RIGHT
					   "c" CTRL_A ARROW_LEFT ARROW_LEFT "X\r");
	ASSERT_STR_EQ("Xabc", test_arg(&ctx, 0));
	PASS();
}

TEST insert_in_middle_keeps_remainder(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "ac" ARROW_LEFT "b\r");
	ASSERT_STR_EQ("abc", test_arg(&ctx, 0));
	PASS();
}

TEST ctrl_l_clears_screen_and_keeps_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_in_str(&tcli, "abc\x0c");
	ASSERT(test_out_has(&ctx, "\033[2J"));

	tcli_in_str(&tcli, "\r");
	ASSERT_STR_EQ("abc", test_arg(&ctx, 0));
	PASS();
}

TEST sigint_clears_the_line(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_sigint(&tcli, test_sigint);

	tcli_in_str(&tcli, "abc\x03");
	ASSERT_EQ(1, ctx.sigint_calls);

	// The interrupted line must not resurface on the next enter.
	tcli_in_str(&tcli, "\r");
	ASSERT_EQ(0, ctx.calls);
	PASS();
}

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	RUN_TEST(ctrl_a_moves_to_line_start);
	RUN_TEST(ctrl_e_moves_to_line_end);
	RUN_TEST(ctrl_b_and_ctrl_f_move_one_character);
	RUN_TEST(arrow_keys_move_one_character);
	RUN_TEST(home_and_end_keys_move_to_line_bounds);
	RUN_TEST(backspace_deletes_previous_character);
	RUN_TEST(backspace_at_line_start_does_nothing);
	RUN_TEST(ctrl_d_deletes_character_at_cursor);
	RUN_TEST(delete_key_deletes_character_at_cursor);
	RUN_TEST(ctrl_u_clears_before_cursor);
	RUN_TEST(ctrl_k_clears_after_cursor);
	RUN_TEST(ctrl_u_on_whole_line_leaves_nothing_to_execute);
	RUN_TEST(ctrl_w_clears_word_before_cursor);
	RUN_TEST(alt_d_deletes_word_after_cursor);
	RUN_TEST(alt_b_and_alt_f_move_by_word);
	RUN_TEST(cursor_stops_at_line_bounds);
	RUN_TEST(insert_in_middle_keeps_remainder);
	RUN_TEST(ctrl_l_clears_screen_and_keeps_line);
	RUN_TEST(sigint_clears_the_line);
	GREATEST_MAIN_END();
}
