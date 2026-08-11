#include "greatest.h"
#include "tcli.h"
#include "test_helpers.h"

GREATEST_MAIN_DEFS();

#define TAB "\t"
#define ESC "\x1b\x1b" // Esc has to be pressed twice to be unambiguous
#define CTRL_G "\x07"

#if TCLI_COMPLETE

// The callback filters these by prefix, as an application would.
static const char *candidates[8];
static size_t candidate_count;

static void set_candidates(const char *const a, const char *const b,
						   const char *const c)
{
	candidate_count = 0;
	if (a)
		candidates[candidate_count++] = a;
	if (b)
		candidates[candidate_count++] = b;
	if (c)
		candidates[candidate_count++] = c;
}

static size_t complete_cb(void *const arg, const int argc,
						  const char **const argv, const char *const match,
						  const char **const completions,
						  const size_t max_count)
{
	(void)arg;
	(void)argc;
	(void)argv;

	const size_t match_len = strlen(match);
	size_t count = 0;

	for (size_t i = 0; i < candidate_count && count < max_count; i++) {
		if (strncmp(candidates[i], match, match_len) == 0)
			completions[count++] = candidates[i];
	}

	return count;
}

static void init(tcli_t *const tcli, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tcli_init(tcli, test_out, ctx);
	tcli_set_exec(tcli, test_exec);
	tcli_set_complete(tcli, complete_cb);
}

TEST single_match_is_completed(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("hello", NULL, NULL);

	tcli_in_str(&tcli, "he" TAB "\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("hello", test_arg(&ctx, 0));
	PASS();
}

TEST single_match_appends_separator(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("hello", NULL, NULL);

	// A completed word ends with a space, so the next word is a new token.
	tcli_in_str(&tcli, "he" TAB "world\r");

	ASSERT_EQ(2, ctx.argc);
	ASSERT_STR_EQ("hello", test_arg(&ctx, 0));
	ASSERT_STR_EQ("world", test_arg(&ctx, 1));
	PASS();
}

TEST common_prefix_is_completed(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("test_one", "test_two", NULL);

	tcli_in_str(&tcli, "te" TAB "\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("test_", test_arg(&ctx, 0));
	PASS();
}

TEST matches_are_listed_when_ambiguous(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("alpha", "beta", NULL);

	test_clear_out(&ctx);
	tcli_in_str(&tcli, TAB);

	ASSERT(test_out_has(&ctx, "alpha"));
	ASSERT(test_out_has(&ctx, "beta"));
	PASS();
}

TEST repeated_tab_cycles_through_matches(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("alpha", "beta", NULL);

	// First tab lists, the next ones select in order.
	tcli_in_str(&tcli, TAB TAB "\r");
	ASSERT_STR_EQ("alpha", test_arg(&ctx, 0));

	tcli_in_str(&tcli, TAB TAB TAB "\r");
	ASSERT_STR_EQ("beta", test_arg(&ctx, 0));
	PASS();
}

TEST escape_cancels_selection(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("alpha", "beta", NULL);

	tcli_in_str(&tcli, TAB TAB ESC "\r");

	// The selected candidate is withdrawn, leaving an empty line.
	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST ctrl_g_cancels_selection(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("alpha", "beta", NULL);

	tcli_in_str(&tcli, TAB TAB CTRL_G "\r");

	ASSERT_EQ(0, ctx.calls);
	PASS();
}

TEST completion_applies_to_word_at_cursor(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("second", NULL, NULL);

	tcli_in_str(&tcli, "first se" TAB "\r");

	ASSERT_EQ(2, ctx.argc);
	ASSERT_STR_EQ("first", test_arg(&ctx, 0));
	ASSERT_STR_EQ("second", test_arg(&ctx, 1));
	PASS();
}

TEST no_match_leaves_line_untouched(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("hello", NULL, NULL);

	tcli_in_str(&tcli, "zz" TAB "\r");

	ASSERT_EQ(1, ctx.calls);
	ASSERT_STR_EQ("zz", test_arg(&ctx, 0));
	PASS();
}

TEST completion_is_skipped_without_callback(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_complete(&tcli, NULL);
	set_candidates("hello", NULL, NULL);

	tcli_in_str(&tcli, "he" TAB "\r");

	ASSERT_STR_EQ("he", test_arg(&ctx, 0));
	PASS();
}

TEST completion_is_skipped_when_echo_is_off(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("hello", NULL, NULL);
	tcli_set_echo(&tcli, TCLI_ECHO_OFF);

	// Completing a masked line would leak its content.
	tcli_in_str(&tcli, "he" TAB "\r");

	ASSERT_STR_EQ("he", test_arg(&ctx, 0));
	ASSERT_FALSE(test_out_has(&ctx, "hello"));
	PASS();
}

TEST completion_with_control_characters_is_rejected(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	set_candidates("he\x01lo", NULL, NULL);

	tcli_in_str(&tcli, "he" TAB "\r");

	ASSERT_STR_EQ("he", test_arg(&ctx, 0));
	PASS();
}

#endif

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
#if TCLI_COMPLETE
	RUN_TEST(single_match_is_completed);
	RUN_TEST(single_match_appends_separator);
	RUN_TEST(common_prefix_is_completed);
	RUN_TEST(matches_are_listed_when_ambiguous);
	RUN_TEST(repeated_tab_cycles_through_matches);
	RUN_TEST(escape_cancels_selection);
	RUN_TEST(ctrl_g_cancels_selection);
	RUN_TEST(completion_applies_to_word_at_cursor);
	RUN_TEST(no_match_leaves_line_untouched);
	RUN_TEST(completion_is_skipped_without_callback);
	RUN_TEST(completion_is_skipped_when_echo_is_off);
	RUN_TEST(completion_with_control_characters_is_rejected);
#endif
	GREATEST_MAIN_END();
}
