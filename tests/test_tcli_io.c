#include "greatest.h"
#include "tcli.h"
#include <string.h>

GREATEST_MAIN_DEFS();

#define OUT_BUF_LEN 512

typedef struct {
	char buf[OUT_BUF_LEN];
	size_t len;
} test_ctx_t;

static void test_out(void *const arg, const char *const str)
{
	test_ctx_t *const ctx = arg;
	const size_t n = strlen(str);
	if (ctx->len + n < sizeof(ctx->buf)) {
		memcpy(ctx->buf + ctx->len, str, n);
		ctx->len += n;
		ctx->buf[ctx->len] = '\0';
	}
}

static int exec_noop(void *const arg, const int argc, const char **const argv)
{
	(void)arg;
	(void)argc;
	(void)argv;
	return 0;
}

static void init(tcli_t *const tcli, test_ctx_t *const ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	tcli_init(tcli, test_out, ctx);
	tcli_set_exec(tcli, exec_noop);
}

TEST out_delivers_string(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_out(&tcli, "hello");
	tcli_flush(&tcli);

	ASSERT(strstr(ctx.buf, "hello") != NULL);
	PASS();
}

TEST out_concatenates_multiple_calls(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_out(&tcli, "foo");
	tcli_out(&tcli, "bar");
	tcli_flush(&tcli);

	ASSERT(strstr(ctx.buf, "foobar") != NULL);
	PASS();
}

TEST out_printf_formats(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	char fmtbuf[64];
	const int n =
		tcli_out_printf(&tcli, fmtbuf, sizeof(fmtbuf), "x=%d y=%s", 42, "ok");
	tcli_flush(&tcli);

	ASSERT(n > 0);
	ASSERT(strstr(ctx.buf, "x=42 y=ok") != NULL);
	PASS();
}

TEST out_printf_truncation_returns_full_length(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	char small[8];
	const int n = tcli_out_printf(&tcli, small, sizeof(small), "%s",
								  "a string longer than the buffer");
	ASSERT(n >= (int)sizeof(small));
	PASS();
}

TEST log_delivers_string(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_log(&tcli, "log message\r\n");
	tcli_flush(&tcli);

	ASSERT(strstr(ctx.buf, "log message") != NULL);
	PASS();
}

TEST log_printf_formats(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	char fmtbuf[64];
	const int n =
		tcli_log_printf(&tcli, fmtbuf, sizeof(fmtbuf), "value=%d\r\n", 7);
	tcli_flush(&tcli);

	ASSERT(n > 0);
	ASSERT(strstr(ctx.buf, "value=7") != NULL);
	PASS();
}

TEST clear_screen_emits_csi_sequence(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);

	tcli_clear_screen(&tcli);
	tcli_flush(&tcli);

	ASSERT(strstr(ctx.buf, "\033[") != NULL);
	PASS();
}

TEST echo_on_echoes_input(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_echo(&tcli, TCLI_ECHO_ON);

	tcli_input_str(&tcli, "abc");
	tcli_flush(&tcli);

	ASSERT(strstr(ctx.buf, "abc") != NULL);
	PASS();
}

TEST echo_off_suppresses_input(void)
{
	tcli_t tcli;
	test_ctx_t ctx;
	init(&tcli, &ctx);
	tcli_set_echo(&tcli, TCLI_ECHO_OFF);

	tcli_input_str(&tcli, "secret");
	tcli_flush(&tcli);

	ASSERT(strstr(ctx.buf, "secret") == NULL);
	PASS();
}

TEST set_out_redirects_output(void)
{
	tcli_t tcli;
	test_ctx_t ctx_a;
	test_ctx_t ctx_b;
	init(&tcli, &ctx_a);

	tcli_out(&tcli, "to_a");
	tcli_flush(&tcli);
	ASSERT(strstr(ctx_a.buf, "to_a") != NULL);

	memset(&ctx_b, 0, sizeof(ctx_b));
	tcli_set_out(&tcli, test_out);
	tcli_set_arg(&tcli, &ctx_b);

	tcli_out(&tcli, "to_b");
	tcli_flush(&tcli);
	ASSERT(strstr(ctx_b.buf, "to_b") != NULL);
	ASSERT(strstr(ctx_a.buf, "to_b") == NULL);
	PASS();
}

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	RUN_TEST(out_delivers_string);
	RUN_TEST(out_concatenates_multiple_calls);
	RUN_TEST(out_printf_formats);
	RUN_TEST(out_printf_truncation_returns_full_length);
	RUN_TEST(log_delivers_string);
	RUN_TEST(log_printf_formats);
	RUN_TEST(clear_screen_emits_csi_sequence);
	RUN_TEST(echo_on_echoes_input);
	RUN_TEST(echo_off_suppresses_input);
	RUN_TEST(set_out_redirects_output);
	GREATEST_MAIN_END();
}
