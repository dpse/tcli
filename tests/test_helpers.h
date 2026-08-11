// Shared fixtures: an output sink that accumulates everything the library
// emits, and a command callback that records the argument vector it received.
#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define TEST_OUT_BUF_LEN 2048
#define TEST_ARG_LEN 80
#define TEST_MAX_ARGS 16

typedef struct {
	char out[TEST_OUT_BUF_LEN];
	size_t out_len;
	int calls;
	int argc;
	char argv[TEST_MAX_ARGS][TEST_ARG_LEN];
	int res; // Value test_exec returns to the library.
	int sigint_calls;
} test_ctx_t;

static inline void test_copy(char *const dst, const size_t size,
							 const char *const src)
{
	size_t len = strlen(src);

	if (len > size - 1)
		len = size - 1;

	memcpy(dst, src, len);
	dst[len] = '\0';
}

static inline void test_out(void *const arg, const char *const str)
{
	test_ctx_t *const ctx = arg;
	const size_t len = strlen(str);

	if (ctx->out_len + len < sizeof(ctx->out))
		memcpy(ctx->out + ctx->out_len, str, len);
	else
		return;

	ctx->out_len += len;
	ctx->out[ctx->out_len] = '\0';
}

static inline void test_out_sink(void *const arg, const char *const str)
{
	(void)arg;
	(void)str;
}

static inline void test_clear_out(test_ctx_t *const ctx)
{
	ctx->out_len = 0;
	ctx->out[0] = '\0';
}

static inline bool test_out_has(const test_ctx_t *const ctx,
								const char *const needle)
{
	return strstr(ctx->out, needle) != NULL;
}

static inline int test_exec(void *const arg, const int argc,
							const char **const argv)
{
	test_ctx_t *const ctx = arg;

	ctx->calls++;
	ctx->argc = argc;

	for (int i = 0; i < TEST_MAX_ARGS; i++)
		ctx->argv[i][0] = '\0';

	for (int i = 0; i < argc && i < TEST_MAX_ARGS; i++)
		test_copy(ctx->argv[i], TEST_ARG_LEN, argv[i]);

	return ctx->res;
}

static inline void test_sigint(void *const arg)
{
	((test_ctx_t *)arg)->sigint_calls++;
}

static inline const char *test_arg(const test_ctx_t *const ctx, const int index)
{
	return index < TEST_MAX_ARGS ? ctx->argv[index] : "";
}

#endif
