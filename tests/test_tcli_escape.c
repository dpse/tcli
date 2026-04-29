#include "greatest.h"
#include "tcli.h"
#include <string.h>

GREATEST_MAIN_DEFS();

#define MAX_CALLS 8

typedef struct {
	int call_count;
	char argv0[MAX_CALLS][64];
	int argc[MAX_CALLS];
	int sigint_count;
} test_ctx_t;

static void test_out(void *const arg, const char *const str)
{
	(void)arg;
	(void)str;
}

static int test_exec(void *const arg, const int argc, const char **const argv)
{
	test_ctx_t *const ctx = arg;
	if (ctx->call_count < MAX_CALLS) {
		ctx->argc[ctx->call_count] = argc;
		if (argc > 0) {
			strncpy(ctx->argv0[ctx->call_count], argv[0],
					sizeof(ctx->argv0[0]) - 1);
			ctx->argv0[ctx->call_count][sizeof(ctx->argv0[0]) - 1] = '\0';
		}
	}
	ctx->call_count++;
	return 0;
}

static void test_sigint(void *const arg)
{
	test_ctx_t *const ctx = arg;
	ctx->sigint_count++;
}

static void init(tcli_t *const tcli, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tcli_init(tcli, test_out, ctx);
	tcli_set_exec(tcli, test_exec);
	tcli_set_sigint(tcli, test_sigint);
}

#if TCLI_HISTORY_BUF_LEN > 0
TEST up_arrow_recalls_previous_command(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_input_str(&tcli, "first\r");
	ASSERT_EQ(1, ctx.call_count);
	ASSERT_STR_EQ("first", ctx.argv0[0]);

	// Up arrow then Enter: should re-issue "first".
	tcli_input_str(&tcli, "\x1b[A\r");
	ASSERT_EQ(2, ctx.call_count);
	ASSERT_STR_EQ("first", ctx.argv0[1]);
	PASS();
}

TEST down_arrow_after_up_returns_to_empty(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_input_str(&tcli, "first\r");
	tcli_input_str(&tcli, "\x1b[A");   // up: now showing "first"
	tcli_input_str(&tcli, "\x1b[B\r"); // down: back to empty, then enter
	// Empty line shouldn't fire exec.
	ASSERT_EQ(1, ctx.call_count);
	PASS();
}
#endif

TEST unknown_csi_does_not_leak(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	// ESC [ 9 9 ~ is not in the table. Must be fully consumed; the visible
	// "ok" must be the only content of the line.
	tcli_input_str(&tcli, "\x1b[99~ok\r");
	ASSERT_EQ(1, ctx.call_count);
	ASSERT_EQ(1, ctx.argc[0]);
	ASSERT_STR_EQ("ok", ctx.argv0[0]);
	PASS();
}

TEST multi_param_csi_does_not_leak(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	// ESC [ 1 ; 5 A (Ctrl+Up on xterm) — unknown to us. Should be consumed.
	tcli_input_str(&tcli, "\x1b[1;5Aok\r");
	ASSERT_EQ(1, ctx.call_count);
	ASSERT_STR_EQ("ok", ctx.argv0[0]);
	PASS();
}

TEST unknown_single_byte_escape_does_not_leak(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	// ESC q (just an unknown ESC + letter). Should be consumed.
	tcli_input_str(&tcli, "\x1bqok\r");
	ASSERT_EQ(1, ctx.call_count);
	ASSERT_STR_EQ("ok", ctx.argv0[0]);
	PASS();
}

TEST ctrl_c_mid_escape_triggers_sigint(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	// User starts an escape sequence then hits Ctrl+C (0x03). The escape
	// should be cancelled and the SIGINT handler should fire.
	tcli_input_str(&tcli, "\x1b[\x03");
	ASSERT_EQ(1, ctx.sigint_count);
	PASS();
}

TEST escape_state_resets_between_sequences(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	// Two unknown escapes back-to-back, then a real command. Verify the
	// state machine fully recovers between sequences.
	tcli_input_str(&tcli, "\x1b[99~\x1b[1;5Aok\r");
	ASSERT_EQ(1, ctx.call_count);
	ASSERT_STR_EQ("ok", ctx.argv0[0]);
	PASS();
}

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
#if TCLI_HISTORY_BUF_LEN > 0
	RUN_TEST(up_arrow_recalls_previous_command);
	RUN_TEST(down_arrow_after_up_returns_to_empty);
#endif
	RUN_TEST(unknown_csi_does_not_leak);
	RUN_TEST(multi_param_csi_does_not_leak);
	RUN_TEST(unknown_single_byte_escape_does_not_leak);
	RUN_TEST(ctrl_c_mid_escape_triggers_sigint);
	RUN_TEST(escape_state_resets_between_sequences);
	GREATEST_MAIN_END();
}
