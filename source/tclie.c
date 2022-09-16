#include "tclie.h"
#include <assert.h>
#include <string.h>

#define TCLIE_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#if TCLIE_PATTERN_MATCH
typedef enum tclie_token_type {
	TCLIE_TOKEN_UNKNOWN = 0,
	TCLIE_TOKEN_EXACT,
	TCLIE_TOKEN_WILDCARD,
	TCLIE_TOKEN_MULTI_WILDCARD,
	TCLIE_TOKEN_OPTIONAL,
	TCLIE_TOKEN_REQUIRED,
	TCLIE_TOKEN_COUNT
} tclie_token_type_t;

typedef enum tclie_token_combinator {
	TCLIE_COMBINATOR_AND = 0,
	TCLIE_COMBINATOR_OR,
	TCLIE_COMBINATOR_COUNT
} tclie_token_combinator_t;

typedef struct tclie_token {
	const char *str;
	size_t len;
	tclie_token_type_t type;
} tclie_token_t;

typedef struct tclie_token_delim {
	char start;
	char stop;
	tclie_token_type_t type;
} tclie_token_delim_t;

typedef struct tclie_pattern_param {
	const tclie_cmd_opts_t *const options;
	const int argc;
	const char **const argv;
	int *const arg_index;
#if TCLI_COMPLETE
	struct {
		const char *match;
		const size_t match_len;
		const char **const completions;
		const size_t max_count;
		size_t *const count;
		char *const buf;
		size_t *const buf_len;
	} complete;
#endif
} tclie_pattern_param_t;

static const tclie_token_delim_t tclie_token_delims[] = {
	{'"', '"', TCLIE_TOKEN_EXACT},	  {'\'', '\'', TCLIE_TOKEN_EXACT},
	{'<', '>', TCLIE_TOKEN_WILDCARD}, {'[', ']', TCLIE_TOKEN_OPTIONAL},
	{'(', ')', TCLIE_TOKEN_REQUIRED}, {'{', '}', TCLIE_TOKEN_REQUIRED}};
#endif

static int tclie_cmd_help(void *arg, int argc, const char **argv);
static int tclie_cmd_clear(void *arg, int argc, const char **argv);
#if TCLIE_ENABLE_USERS
static int tclie_cmd_login(void *arg, int argc, const char **argv);
static int tclie_cmd_logout(void *arg, int argc, const char **argv);
#endif

static const tclie_cmd_t tclie_internal_cmds[] = {
	{"help", tclie_cmd_help,
#if TCLIE_ENABLE_USERS
	 0,
#endif
	 "Print available commands.",
#if TCLIE_PATTERN_MATCH
	 "help [<command>] ..."
#endif
	},
	{"clear", tclie_cmd_clear,
#if TCLIE_ENABLE_USERS
	 0,
#endif
	 "Clear screen."},
#if TCLIE_ENABLE_USERS
	{"login", tclie_cmd_login, 0, "Login.",
#if TCLIE_PATTERN_MATCH
	 "login [<username>]"
#endif
	},
	{
		"logout",
		tclie_cmd_logout,
		1,
		"Logout.",
	},
#endif
};

#if TCLI_COMPLETE
extern size_t tcli_str_match(const char *restrict a, const char *restrict b,
							 size_t max_len);
#endif

static inline bool tclie_is_space(const char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
		   c == '\v';
}

#if TCLIE_PATTERN_MATCH
static bool tclie_pattern_compare(const char *restrict target,
								  size_t target_len,
								  const char *restrict subject)
{
	assert(target);
	assert(subject);
	assert(target != subject);

	while (target_len != 0 && *target != '\0' && *subject != '\0') {
		if (*target++ != *subject++)
			break;

		target_len--;
	}

	return target_len == 0 && *subject == '\0';
}

static inline bool tclie_pattern_compare_token(const tclie_token_t *const token,
											   const char *subject)
{
	assert(token);

	return tclie_pattern_compare(token->str, token->len, subject);
}

static bool tclie_pattern_delim(const char start,
								tclie_token_delim_t *const delim)
{
	assert(delim);

	for (size_t i = 0; i < TCLIE_ARRAY_SIZE(tclie_token_delims); i++) {
		if (start != tclie_token_delims[i].start)
			continue;

		*delim = tclie_token_delims[i];
		return true;
	}

	return false;
}

static bool tclie_pattern_tokenize(const char *str, const size_t len,
								   tclie_token_t *const tokens,
								   const size_t max_tokens,
								   const tclie_token_combinator_t combinator,
								   size_t *const count)
{
	assert(str);
	assert(tokens);
	assert(combinator < TCLIE_COMBINATOR_COUNT);
	assert(count);

	const char *const str_max = str + len;
	struct {
		bool active;
		int count;
		tclie_token_delim_t delim;
	} delim = {0};

	while (str < str_max) {
		while (tclie_is_space(*str))
			str++;

		if (*str == '\0')
			break;

		bool esc = false;
		const char *start = str;

		while (*str != '\0' && str < str_max) {
			if (esc) {
				esc = false;
				str++;
				continue;
			}

			if ((esc = *str == '\\')) {
				str++;
				continue;
			}

			if (!delim.active && tclie_pattern_delim(*str, &delim.delim)) {
				delim.active = true;
				delim.count = 0;
			}

			if (delim.active) {
				if (*str == delim.delim.stop)
					delim.count--;
				else if (*str == delim.delim.start)
					delim.count++;

				if (delim.count <= 0)
					delim.active = false;
			} else {
				if (combinator == TCLIE_COMBINATOR_OR) {
					if (*str == '|')
						break;
				} else if (tclie_is_space(*str))
					break;
			}

			str++;
		}

		if (str > start) {
			size_t str_len = str - start;

			if (*count >= max_tokens)
				return false;

			if (str_len >= 2 && tclie_pattern_delim(*start, &delim.delim) &&
				start[str_len - 1] == delim.delim.stop) {
				start++;
				str_len -= 2;
				tokens[*count].type = delim.delim.type;
			} else if (tclie_pattern_compare(start, str_len, "..."))
				tokens[*count].type = TCLIE_TOKEN_MULTI_WILDCARD;
			else
				tokens[*count].type = TCLIE_TOKEN_UNKNOWN;

			if (str_len != 0) {
				tokens[*count].str = start;
				tokens[*count].len = str_len;
				(*count)++;
			}
		}

		if (*str == '\0')
			break;

		str++;
	}

	return true;
}

static inline bool tclie_pattern_tokenize_token(
	const tclie_token_t *const token, tclie_token_t *const tokens,
	const size_t max_tokens, const tclie_token_combinator_t combinator,
	size_t *const count)
{
	assert(token);

	return tclie_pattern_tokenize(token->str, token->len, tokens, max_tokens,
								  combinator, count);
}

static bool
tclie_pattern_reduce_token(const tclie_token_t *const token,
						   tclie_token_t *const tokens, const size_t max_tokens,
						   tclie_token_combinator_t *const combinator,
						   size_t *const count)
{
	assert(token);
	assert(tokens);
	assert(combinator);
	assert(count);

	const tclie_token_combinator_t combinators[] = {TCLIE_COMBINATOR_AND,
													TCLIE_COMBINATOR_OR};

	for (size_t i = 0; i < TCLIE_ARRAY_SIZE(combinators); i++) {
		size_t token_count = 0;
		if (!tclie_pattern_tokenize_token(token, tokens, max_tokens,
										  combinators[i], &token_count))
			return false;

		if (token_count == 0 || token_count > 1 ||
			token->type != tokens[0].type) {
			*combinator = combinators[i];
			*count = token_count;
			return true;
		}
	}

	if (max_tokens == 0)
		return false;

	*combinator = TCLIE_COMBINATOR_AND;
	tokens[0].str = token->str;
	tokens[0].len = token->len;
	tokens[0].type = TCLIE_TOKEN_EXACT;
	*count = 1;
	return true;
}

#if TCLI_COMPLETE
static bool tclie_pattern_match_can_complete(tclie_pattern_param_t *const p)
{
	assert(p);
	assert(p->argc == 0 || p->argv);
	assert(p->complete.match_len == 0 || p->complete.match);

	if (!p->complete.match)
		return false;

	if (!p->complete.completions || !p->complete.count ||
		*p->complete.count >= p->complete.max_count)
		return false;

	return true;
}

static void tclie_pattern_match_complete(const char *const str,
										 const size_t len,
										 tclie_pattern_param_t *const p,
										 bool match, const char *const prefix)
{
	assert(str);
	assert(p);
	assert(p->argc == 0 || p->argv);
	assert(p->complete.match_len == 0 || p->complete.match);

	if (len == 0 || !tclie_pattern_match_can_complete(p))
		return;

	assert(p->complete.buf && p->complete.buf_len);
	const size_t prefix_len = prefix ? strlen(prefix) : 0;

	if (!match && prefix_len > p->complete.match_len)
		return;

	if (*p->complete.buf_len + prefix_len + len + 1 >
		TCLIE_PATTEN_MATCH_BUF_LEN)
		return;

	if (!match) {
		assert(prefix_len <= p->complete.match_len);
		match =
			(!prefix || tcli_str_match(prefix, p->complete.match, prefix_len) ==
							prefix_len) &&
			prefix_len + tcli_str_match(str, p->complete.match + prefix_len,
										p->complete.match_len - prefix_len) ==
				p->complete.match_len;
	}

	if (!match)
		return;

	if (prefix)
		strncpy(p->complete.buf + *p->complete.buf_len, prefix, prefix_len);
	strncpy(p->complete.buf + *p->complete.buf_len + prefix_len, str, len);
	p->complete.buf[*p->complete.buf_len + prefix_len + len] = '\0';
	p->complete.completions[(*p->complete.count)++] =
		&p->complete.buf[*p->complete.buf_len];
	*p->complete.buf_len += prefix_len + len + 1;
}

static void tclie_pattern_match_complete_token(const tclie_token_t *const token,
											   tclie_pattern_param_t *const p,
											   bool match)
{
	assert(token);
	assert(p);
	assert(p->argc == 0 || p->argv);

	if (*p->arg_index >= p->argc)
		return;

	if (p->complete.match != p->argv[(*p->arg_index)])
		return;

	return tclie_pattern_match_complete(token->str, token->len, p, match, NULL);
}

static void tclie_pattern_match_complete_options(tclie_pattern_param_t *const p)
{
	assert(p);
	assert(p->argc == 0 || p->argv);
	assert(p->complete.match_len == 0 || p->complete.match);

	if (!p->options || p->options->count == 0)
		return;

	if (!tclie_pattern_match_can_complete(p))
		return;

	for (size_t i = 0; i < p->options->count; i++) {
		const tclie_cmd_opt_t *const opt = &p->options->option[i];
		assert(opt);

		const bool match = p->complete.match_len == 0;

		if (opt->short_opt) {
			const char str[2] = {opt->short_opt, '\0'};
			tclie_pattern_match_complete(str, 2, p, match, "-");
		}

		if (opt->long_opt) {
			const bool long_match = match || (p->complete.match_len == 1 &&
											  *p->complete.match == '-');
			tclie_pattern_match_complete(opt->long_opt, strlen(opt->long_opt),
										 p, long_match, "--");
		}
	}
}

#endif

static bool tclie_pattern_tokenize_options(tclie_pattern_param_t *const p,
										   tclie_token_t *const tokens,
										   const size_t max_tokens,
										   size_t *const count)
{
	assert(p);
	assert(p->argc == 0 || p->argv);
	assert(p->arg_index);
	assert(tokens);
	assert(count);

	if (!p->options || p->options->count == 0)
		return true;

	assert(p->options->option);

	if (*p->arg_index >= p->argc)
		return true;

	const char *arg = p->argv[*p->arg_index];

	if (*arg++ != '-')
		return true;

	const bool long_opt = *arg == '-';
	if (long_opt)
		arg++;

	if (*arg == '\0')
		return true;

	const size_t old_count = *count;
	while (*arg != '\0') {
		bool match = false;

		for (size_t i = 0; i < p->options->count && !match; i++) {
			const tclie_cmd_opt_t *const opt = &p->options->option[i];
			assert(opt);

			if (long_opt) {
				if (strcmp(opt->long_opt, arg) != 0)
					continue;
			} else if (opt->short_opt != *arg)
				continue;

			match = true;

			if (!opt->pattern)
				break;

			if (*count >= max_tokens)
				return false;

			tokens[*count].type = TCLIE_TOKEN_UNKNOWN;
			tokens[*count].str = opt->pattern;
			tokens[*count].len = strlen(opt->pattern);
			(*count)++;
		}

		if (!match) {
			*count = old_count;
			return true;
		}

		if (long_opt)
			break;

		arg++;
	}

	(*p->arg_index)++;
	return true;
}

static bool tclie_pattern_match_token(const tclie_token_t *token,
									  tclie_pattern_param_t *p);

static bool
tclie_pattern_match_tokens(const tclie_token_t *const tokens,
						   const size_t count, tclie_pattern_param_t *const p,
						   const tclie_token_combinator_t combinator)
{
	assert(tokens);
	assert(p);
	assert(combinator < TCLIE_COMBINATOR_COUNT);

	if (count == 0)
		return false;

	for (size_t i = 0; i < count; i++) {
		const int old_arg_index = *p->arg_index;
		bool match = tclie_pattern_match_token(&tokens[i], p);

		if (match && combinator == TCLIE_COMBINATOR_AND &&
			tokens[i].type == TCLIE_TOKEN_OPTIONAL && i + 1 < count) {
			match = tclie_pattern_match_tokens(&tokens[i + 1], count - i - 1, p,
											   combinator);
		}

		if (!match)
			*p->arg_index = old_arg_index;

		if (tokens[i].type == TCLIE_TOKEN_OPTIONAL ||
			combinator == TCLIE_COMBINATOR_OR) {
			if (match)
				return true;
		} else if (!match)
			return false;
	}

	return combinator == TCLIE_COMBINATOR_AND;
}

static bool tclie_pattern_match_options(tclie_token_t *const tokens,
										const size_t max_tokens,
										tclie_pattern_param_t *const p)
{
	assert(tokens);
	assert(p);

	size_t count = 0;

	if (!tclie_pattern_tokenize_options(p, tokens, max_tokens, &count))
		return false;

	assert(count <= max_tokens);

	if (count == 0)
		return true;

	return tclie_pattern_match_tokens(tokens, count, p, TCLIE_COMBINATOR_AND);
}

static bool tclie_pattern_match_token(const tclie_token_t *const token,
									  tclie_pattern_param_t *const p)
{
	assert(token);
	assert(p);
	assert(p->argc == 0 || p->argv);
	assert(p->arg_index);
	assert(token->type < TCLIE_TOKEN_COUNT);

	tclie_token_t tokens[TCLIE_PATTERN_MATCH_MAX_TOKENS] = {0};

	// Match options at start
	if (!tclie_pattern_match_options(tokens, TCLIE_ARRAY_SIZE(tokens), p))
		return false;

	if (token->type == TCLIE_TOKEN_MULTI_WILDCARD) {
		*p->arg_index = p->argc;
		return true;
	}

	if (token->type == TCLIE_TOKEN_EXACT) {
		if (*p->arg_index >= p->argc)
			return false;

		const bool match =
			tclie_pattern_compare_token(token, p->argv[(*p->arg_index)]);
#if TCLI_COMPLETE
		tclie_pattern_match_complete_token(token, p, match);
#endif
		if (!match)
			return false;

		(*p->arg_index)++;
		goto MATCH_OPTIONS;
	}

	if (token->type == TCLIE_TOKEN_WILDCARD) {
		if (*p->arg_index >= p->argc)
			return false;

		(*p->arg_index)++;
		goto MATCH_OPTIONS;
	}

	size_t count = 0;
	tclie_token_combinator_t combinator = TCLIE_COMBINATOR_AND;

	if (!tclie_pattern_reduce_token(token, tokens, TCLIE_ARRAY_SIZE(tokens),
									&combinator, &count))
		return false;

	assert(count <= TCLIE_ARRAY_SIZE(tokens));

	if (count == 0)
		return false;

	assert(combinator < TCLIE_COMBINATOR_COUNT);

	if (!tclie_pattern_match_tokens(tokens, count, p, combinator))
		return false;

	// Match options at end

MATCH_OPTIONS:
	if (!tclie_pattern_match_options(tokens, TCLIE_ARRAY_SIZE(tokens), p))
		return false;

	return true;
}

static bool tclie_pattern_match(tclie_t *const tclie, const char *pattern,
								const tclie_cmd_opts_t *const options,
								const int argc, const char **const argv,
								const char *const match, const size_t match_len,
								const char **const completions,
								const size_t max_count, size_t *const count)
{
	assert(tclie);
	assert(argc == 0 || argv);
	assert(match_len == 0 || match);
	assert(max_count == 0 || (completions && count));

	if (!pattern)
		return false;

	const tclie_token_t token = {
		.type = TCLIE_TOKEN_UNKNOWN, .str = pattern, .len = strlen(pattern)};
	int arg_index = 0;
	tclie_pattern_param_t p = {
		.options = options,
		.argc = argc,
		.argv = argv,
		.arg_index = &arg_index,
#if TCLI_COMPLETE
		.complete.match = match,
		.complete.match_len = match_len,
		.complete.completions = completions,
		.complete.max_count = max_count,
		.complete.count = count,
		.complete.buf = tclie->complete.buf,
		.complete.buf_len = &tclie->complete.buf_len
#endif
	};

	const bool matches = tclie_pattern_match_token(&token, &p);
	if (arg_index != 0)
		tclie_pattern_match_complete_options(&p);
	return matches && arg_index == argc;
}
#endif

static inline bool tclie_valid_cmd(const tclie_t *const tclie,
								   const tclie_cmd_t *const cmd)
{
	assert(tclie);
	assert(cmd);
	assert(cmd->name);
	assert(cmd->fn);

#if TCLIE_ENABLE_USERS
	if (tclie->user.level < cmd->min_user_level)
		return false;
#endif

	return true;
}

void tclie_out(tclie_t *const tclie, const char *const str)
{
	if (tclie)
		tcli_out(&tclie->tcli, str);
}

int tclie_out_vprintf(tclie_t *const tclie, char *const buf, const size_t len,
					  const char *const format, va_list arg)
{
	return tclie ? tcli_out_vprintf(&tclie->tcli, buf, len, format, arg) : -1;
}

int tclie_out_printf(tclie_t *const tclie, char *const buf, const size_t len,
					 const char *const format, ...)
{
	va_list arg;
	va_start(arg, format);
	const int count = tclie_out_vprintf(tclie, buf, len, format, arg);
	va_end(arg);
	return count;
}

void tclie_flush(tclie_t *const tclie)
{
	assert(tclie);

	if (tclie)
		tcli_flush(&tclie->tcli);
}

static inline void tclie_out_flush(tclie_t *const tclie, const char *const str)
{
	assert(tclie);
	tclie_out(tclie, str);
	tclie_flush(tclie);
}

static void tclie_print_str(tclie_t *const tclie, size_t pre_pad,
							const char *const head_str, const char *const color,
							const size_t pad, const char *const desc_str,
							const bool flush)
{
	assert(tclie);

	while (pre_pad != 0) {
		tclie_out(tclie, " ");
		pre_pad--;
	}
	if (color)
		tclie_out(tclie, color);
	if (head_str)
		tclie_out(tclie, head_str);
	size_t pad_len = 0;
	if (head_str && desc_str)
		pad_len += strlen(head_str);
	if (color)
		tclie_out(tclie, TCLI_FORMAT_RESET);
	while (pad_len++ < pad)
		tclie_out(tclie, " ");
	if (desc_str)
		tclie_out(tclie, desc_str);
	tclie_out(tclie, "\r\n");
	if (flush)
		tclie_flush(tclie);
}

static void tclie_print_cmd(tclie_t *const tclie, const tclie_cmd_t *const cmd,
							const size_t pad, const bool flush)
{
	assert(tclie);
	assert(cmd);
	assert(cmd->name);

#if TCLIE_PATTERN_MATCH
	tclie_print_str(tclie, 0, cmd->name, TCLIE_COMMAND_FORMAT, pad, cmd->desc,
					false);

	if (cmd->pattern)
		tclie_print_str(tclie, pad, cmd->pattern, TCLIE_USAGE_FORMAT, 0, NULL,
						false);

	size_t opt_pad = 0;
	for (size_t i = 0; i < cmd->options.count; i++) {
		assert(cmd->options.option[i].short_opt ||
			   cmd->options.option[i].long_opt);
		size_t opt_len = cmd->options.option[i].short_opt ? 2 : 0;
		if (cmd->options.option[i].long_opt)
			opt_len += strlen(cmd->options.option[i].long_opt) + 2 +
					   (cmd->options.option[i].short_opt ? 1 : 0);
		if (cmd->options.option[i].pattern)
			opt_len += strlen(cmd->options.option[i].pattern) + 1;

		if (opt_len > opt_pad)
			opt_pad = opt_len;
	}
	opt_pad += 1;

	for (size_t i = 0; i < cmd->options.count; i++) {
		size_t pad_len = 0;
		while (pad_len++ < pad)
			tclie_out(tclie, " ");
		pad_len = 0;
		tclie_out(tclie, TCLIE_OPTION_FORMAT);
		if (cmd->options.option[i].short_opt) {
			char buf[3];
			buf[0] = '-';
			buf[1] = cmd->options.option[i].short_opt;
			buf[2] = '\0';
			tclie_out(tclie, buf);
			pad_len += 1;
			if (cmd->options.option[i].long_opt) {
				tclie_out(tclie, "|--");
				pad_len += 1;
			}
		}
		if (cmd->options.option[i].long_opt) {
			tclie_out(tclie, cmd->options.option[i].long_opt);
			pad_len += strlen(cmd->options.option[i].long_opt);
		}
		if (cmd->options.option[i].pattern) {
			tclie_out(tclie, " ");
			tclie_out(tclie, cmd->options.option[i].pattern);
			pad_len += strlen(cmd->options.option[i].pattern) + 1;
		}
		tclie_out(tclie, TCLI_FORMAT_RESET);
		if (cmd->options.option[i].desc) {
			while (pad_len++ < opt_pad)
				tclie_out(tclie, " ");
			tclie_out(tclie, cmd->options.option[i].desc);
		}
		tclie_out(tclie, "\r\n");
	}

	if (flush)
		tclie_flush(tclie);

#else
	tclie_print_str(tclie, 0, cmd->name, TCLIE_COMMAND_FORMAT, pad, cmd->desc,
					flush);
#endif
}

static size_t tclie_calculate_padding(const tclie_t *const tclie,
									  const tclie_cmd_t *const cmds,
									  const size_t len, const char *const match,
									  const size_t match_len, size_t pad)
{
	assert(tclie);
	assert(cmds);

	for (size_t i = 0; i < len; i++) {
		if (!tclie_valid_cmd(tclie, &cmds[i]))
			continue;

		assert(cmds[i].name);
		if (match && strncmp(cmds[i].name, match, match_len) != 0)
			continue;

		const size_t name_len = strlen(cmds[i].name);
		if (name_len > pad)
			pad = name_len;
	}

	return pad;
}

static bool tclie_compare_args(const char *str, const int argc,
							   const char *const *const argv,
							   const bool match_all, const bool partial,
							   const char **const partial_match,
							   const char **const partial_arg)
{
	assert(str);
	assert(argv);

	int i = 0;
	while (i < argc) {
		assert(argv[i]);
		const char *arg = argv[i];
		const char *const start = str;

		while (*str != '\0' && !tclie_is_space(*str)) {
			if (*arg == '\0' && partial && (!match_all || i + 1 == argc)) {
				if (partial_match)
					*partial_match = start;
				if (partial_arg)
					*partial_arg = argv[i];
				return true;
			}

			if (*str++ != *arg++)
				return false;
		}

		if (*arg != '\0')
			return false;

		if (*str == '\0') {
			if (*arg == '\0' && partial && (!match_all || i + 1 == argc)) {
				if (partial_match)
					*partial_match = start;
				if (partial_arg)
					*partial_arg = argv[i];
			}
			return !match_all || i + 1 == argc;
		}

		while (tclie_is_space(*str))
			str++;

		if (*str == '\0')
			return false;

		i++;
	}

	return false;
}

static size_t tclie_print_cmds(tclie_t *const tclie,
							   const tclie_cmd_t *const cmds, const size_t len,
							   const int argc, const char *const *argv,
							   const char *const match, const size_t match_len,
							   const size_t pad, const bool flush)
{
	assert(tclie);
	assert(cmds);
	assert(argc == 0 || argv);

	size_t count = 0;

	for (size_t i = 0; i < len; i++) {
		if (!tclie_valid_cmd(tclie, &cmds[i]))
			continue;

		assert(cmds[i].name);

		if (match && strncmp(cmds[i].name, match, match_len) != 0)
			continue;

		if (!match && argc != 0 && argv &&
			!tclie_compare_args(cmds[i].name, argc, argv, true, true, NULL,
								NULL))
			continue;

		if (count != 0)
			tclie_out(tclie, "\r\n");

		tclie_print_cmd(tclie, &cmds[i], pad, false);
		count++;
	}

	if (flush)
		tclie_flush(tclie);

	return count;
}

#if TCLI_COMPLETE
static void tclie_complete(tclie_t *const tclie, const tclie_cmd_t *const cmds,
						   const size_t cmd_count, const int argc,
						   const char **const argv, const char *const match,
						   const size_t match_len, const bool match_name,
						   const char **const completions,
						   const size_t max_count, size_t *const count)
{
	assert(tclie);
	assert(cmds);
	assert(argc >= 1);
	assert(argv);
	assert(match);
	assert(completions);
	assert(count);

	for (size_t i = 0; i < cmd_count && *count < max_count; i++) {
		const tclie_cmd_t *const cmd = &cmds[i];

		if (!tclie_valid_cmd(tclie, cmd))
			continue;

#if TCLIE_PATTERN_MATCH
		const size_t old_count = *count;
		tclie_pattern_match(tclie, cmd->pattern, &cmd->options, argc, argv,
							match, match_len, completions, max_count, count);

		if (old_count != *count)
			continue;
#endif

		bool full_match =
			(match_name || match == argv[0]) &&
			tcli_str_match(match, cmd->name, match_len) == match_len;
		const char *partial_match = NULL;
		const char *partial_arg = NULL;

		if (!full_match) {
			if (!tclie_compare_args(cmd->name, argc, argv, false, true,
									&partial_match, &partial_arg))
				continue;

			if (!(partial_match && partial_arg))
				full_match = true;
			else if (partial_arg != match)
				partial_match = NULL;
		}

		if (full_match) {
			assert(strlen(cmd->name) >= match_len);
			completions[(*count)++] = cmd->name;
		} else if (partial_match) {
			assert(*partial_match != '\0');
			completions[(*count)++] = partial_match;
		}
	}
}

static size_t tcli_complete(void *const arg, const int argc,
							const char **const argv, const char *const match,
							const char **const completions,
							const size_t max_count)
{
	assert(arg);
	assert(argc > 0);
	assert(argv);
	assert(completions);
	assert(match);

	if (max_count == 0)
		return 0;

	tclie_t *const tclie = arg;
#if TCLIE_PATTERN_MATCH
	tclie->complete.buf_len = 0;
#endif
	size_t count = 0;
	const bool match_name =
		argc >= 2 && match == argv[1] && strcmp(argv[0], "help") == 0;

	const size_t match_len = strlen(match);
	tclie_complete(tclie, tclie_internal_cmds,
				   TCLIE_ARRAY_SIZE(tclie_internal_cmds), argc, argv, match,
				   match_len, match_name, completions, max_count, &count);
	tclie_complete(tclie, tclie->cmd.cmds, tclie->cmd.count, argc, argv, match,
				   match_len, match_name, completions, max_count, &count);

	return count;
}
#endif

static bool tclie_exec(tclie_t *const tclie, const tclie_cmd_t *const cmds,
					   const size_t cmd_count, void *const arg, const int argc,
					   const char **const argv, int *const res)
{
	assert(tclie);
	assert(cmds);
	assert(argc >= 1);
	assert(argv);
	assert(argv[0]);
	assert(res);

	for (size_t i = 0; i < cmd_count; i++) {
		const tclie_cmd_t *const cmd = &cmds[i];

		if (!tclie_valid_cmd(tclie, cmd))
			continue;

#if TCLIE_PATTERN_MATCH
		if (cmd->pattern) {
			if (!tclie_pattern_match(tclie, cmd->pattern, &cmd->options, argc,
									 argv, NULL, 0, NULL, 0, NULL))
				continue;
		} else {
#endif
			if (!tclie_compare_args(cmd->name, argc, argv, false, false, NULL,
									NULL))
				continue;
#if TCLIE_PATTERN_MATCH
		}
#endif

		if (tclie->pre_cmd)
			tclie->pre_cmd(tclie->arg, argc, argv);

		*res = cmd->fn(arg, argc, argv);

		if (tclie->post_cmd)
			tclie->post_cmd(tclie->arg, argc, argv, *res);

		return true;
	}

	return false;
}

#if TCLIE_ENABLE_USERS
static void tclie_login_prompt(tclie_t *const tclie)
{
	assert(tclie);
	assert(tclie->user.login.state >= TCLIE_LOGIN_IDLE &&
		   tclie->user.login.state <= TCLIE_LOGIN_PASSWORD);

	if (tclie->user.login.state == TCLIE_LOGIN_IDLE)
		return;

#if TCLIE_ENABLE_USERNAMES
	if (tclie->user.login.state == TCLIE_LOGIN_USERNAME) {
		tclie_out_flush(tclie, "Enter username:\r\n");
#if TCLI_HISTORY_BUF_LEN > 0
		tcli_set_hist(&tclie->tcli, TCLI_HIST_OFF_ONCE);
#endif
		return;
	}
#endif

	tclie_out_flush(tclie, "Enter password:\r\n");
	tcli_set_echo(&tclie->tcli, TCLI_ECHO_OFF_ONCE);
}

static inline void tclie_login_proceed(tclie_login_t *const login,
									   const tclie_login_state_t state)
{
	assert(login);
	assert(login->state >= TCLIE_LOGIN_IDLE &&
		   login->state <= TCLIE_LOGIN_PASSWORD);
	assert(state >= TCLIE_LOGIN_IDLE && state <= TCLIE_LOGIN_PASSWORD);

	login->state = state;
	login->attempt = 0;
}

static bool tclie_login_process(tclie_t *const tclie, const char *const str,
								int *const res)
{
	assert(tclie);
	assert(res);

	tclie_users_t *const user = &tclie->user;
	tclie_login_t *const login = &user->login;
	assert(login->state >= TCLIE_LOGIN_IDLE &&
		   login->state <= TCLIE_LOGIN_PASSWORD);

	if (login->state == TCLIE_LOGIN_IDLE)
		return false;

	if (!str)
		goto PROMPT;

#if TCLIE_ENABLE_USERNAMES
	if (login->state == TCLIE_LOGIN_USERNAME) {
		for (size_t i = 0; i < user->count; i++) {
			assert(user->users[i].name);

			if (strcmp(str, user->users[i].name) != 0)
				continue;

			login->target_user = i;

			if (!user->users[i].password)
				goto LOGIN;

			tclie_login_proceed(login, TCLIE_LOGIN_PASSWORD);
			break;
		}

		goto PROMPT;
	}

	assert(login->state == TCLIE_LOGIN_PASSWORD);
	assert(login->target_user < user->count);
	assert(user->users[login->target_user].password);

	if (strcmp(str, user->users[login->target_user].password) == 0)
		goto LOGIN;

#else
	assert(login->state == TCLIE_LOGIN_PASSWORD);

	for (size_t i = 0; i < user->count; i++) {
		assert(user->users[i].password);

		if (strcmp(str, user->users[i].password) != 0)
			continue;

		tclie_set_user_level(tclie, user->users[i].level);
		goto LOGIN;
	}
#endif

PROMPT:
	if (login->attempt++ >= TCLIE_LOGIN_ATTEMPTS) {
		tclie_login_proceed(login, TCLIE_LOGIN_IDLE);
		tclie_out_flush(tclie, TCLIE_FAILURE_FORMAT "Failed!" TCLI_FORMAT_RESET
													"\r\n");
		*res = -1;
		return true;
	}

	tclie_login_prompt(tclie);
	*res = 0;
	return true;

LOGIN:
#if TCLIE_ENABLE_USERNAMES
	tclie_set_user_level(tclie, user->users[login->target_user].level);
#endif
	tclie_login_proceed(login, TCLIE_LOGIN_IDLE);
	tclie_out_flush(tclie,
					TCLIE_SUCCESS_FORMAT "Success!" TCLI_FORMAT_RESET "\r\n");
	*res = 0;
	return true;
}

static inline int tclie_login_begin(tclie_t *const tclie, const char *const str)
{
	assert(tclie);

#if TCLIE_ENABLE_USERNAMES
	tclie_login_proceed(&tclie->user.login, TCLIE_LOGIN_USERNAME);
#else
	tclie_login_proceed(&tclie->user.login, TCLIE_LOGIN_PASSWORD);
#endif

	int res = 0;
	tclie_login_process(tclie, str, &res);
	return res;
}
#endif

static int tcli_exec(void *const arg, const int argc, const char **const argv)
{
	assert(arg);
	assert(argc >= 1);
	assert(argv);
	assert(argv[0]);

	tclie_t *const tclie = arg;
	int res = 0;

#if TCLIE_ENABLE_USERS
	if (tclie_login_process(tclie, argv[0], &res))
		return res;
#endif

	if (tclie_exec(tclie, tclie_internal_cmds,
				   TCLIE_ARRAY_SIZE(tclie_internal_cmds), tclie, argc, argv,
				   &res))
		return res;

	if (tclie_exec(tclie, tclie->cmd.cmds, tclie->cmd.count, tclie->arg, argc,
				   argv, &res))
		return res;

	tclie_out(tclie,
			  "Unknown command or invalid syntax: " TCLIE_FAILURE_FORMAT);
	tclie_out(tclie, argv[0]);
	tclie_out_flush(tclie, TCLI_FORMAT_RESET "\r\n");
	return -1;
}

static void tcli_sigint(void *const arg)
{
	assert(arg);
	tclie_t *const tclie = arg;

#if TCLIE_ENABLE_USERS
	if (tclie->user.login.state != TCLIE_LOGIN_IDLE) {
		tcli_log(&tclie->tcli, "Aborted!\r\n");
		tclie_login_proceed(&tclie->user.login, TCLIE_LOGIN_IDLE);
	}
#endif

	if (tclie->sigint)
		tclie->sigint(tclie->arg);
}

static void tcli_output(void *const arg, const char *const str)
{
	assert(arg);
	assert(str);

	tclie_t *const tclie = arg;

	if (!tclie->out)
		return;

	tclie->out(tclie->arg, str);
}

void tclie_set_out(tclie_t *const tclie, tcli_out_fn_t out)
{
	if (!tclie)
		return;

	tclie->out = out;
}

void tclie_set_arg(tclie_t *const tclie, void *const arg)
{
	if (!tclie)
		return;

	tclie->arg = arg;
}

void tclie_set_pre_cmd(tclie_t *const tclie, tclie_pre_cmd_fn_t pre_cmd)
{
	if (!tclie)
		return;

	tclie->pre_cmd = pre_cmd;
}

void tclie_set_post_cmd(tclie_t *const tclie, tclie_post_cmd_fn_t post_cmd)
{
	if (!tclie)
		return;

	tclie->post_cmd = post_cmd;
}

void tclie_set_sigint(tclie_t *const tclie, tclie_sigint_fn_t sigint)
{
	if (!tclie)
		return;

	tclie->sigint = sigint;
}

void tclie_init(tclie_t *tclie, tclie_out_fn_t out, void *arg)
{
	if (!tclie)
		return;

	memset(tclie, 0, sizeof(tclie_t));

	tclie_set_out(tclie, out);
	tclie_set_arg(tclie, arg);
	tclie_set_pre_cmd(tclie, NULL);
	tclie_set_post_cmd(tclie, NULL);
	tclie_set_sigint(tclie, NULL);

	tcli_init(&tclie->tcli, tcli_output, tclie);
	tcli_set_exec(&tclie->tcli, tcli_exec);
	tcli_set_sigint(&tclie->tcli, tcli_sigint);
#if TCLI_COMPLETE
	tcli_set_complete(&tclie->tcli, tcli_complete);
#endif
}

#if TCLIE_ENABLE_USERS
bool tclie_reg_users(tclie_t *tclie, const tclie_user_t *users, size_t count)
{
	if (!tclie)
		return false;

	if (!users && count != 0)
		return false;

	for (size_t i = 0; i < count; i++) {
#if TCLIE_ENABLE_USERNAMES
		if (!users[i].name)
			return false;
#else
		if (!users[i].password)
			return false;
#endif
	}

	tclie->user.users = users;
	tclie->user.count = count;
	return true;
}
#endif

bool tclie_reg_cmds(tclie_t *tclie, const tclie_cmd_t *cmds, size_t count)
{
	if (!tclie)
		return false;

	if (!cmds && count != 0)
		return false;

	for (size_t i = 0; i < count; i++) {
		if (!cmds[i].name || !cmds[i].fn)
			return false;

#if TCLIE_PATTERN_MATCH
		if (cmds[i].options.count != 0 && !cmds[i].options.option)
			return false;

		for (size_t j = 0; j < cmds[i].options.count; j++) {
			if (!cmds[i].options.option[j].short_opt &&
				!cmds[i].options.option[j].long_opt)
				return false;
		}
#endif
	}

	tclie->cmd.cmds = cmds;
	tclie->cmd.count = count;
	return true;
}

#if TCLIE_ENABLE_USERS
void tclie_set_user_level(tclie_t *const tclie, const unsigned user_level)
{
	if (!tclie)
		return;

	tclie->user.level = user_level;
}

unsigned tclie_get_user_level(const tclie_t *const tclie)
{
	if (!tclie)
		return 0;

	return tclie->user.level;
}
#endif

static int tclie_cmd_help(void *arg, const int argc, const char **argv)
{
	assert(arg);
	assert(argc >= 1);
	assert(argv);
	assert(argv[0]);

	const char *const match = argc == 2 ? argv[1] : NULL;
	const size_t match_len = match ? strlen(match) : 0;
	tclie_t *const tclie = arg;
	size_t pad = 0;

	pad = tclie_calculate_padding(tclie, tclie_internal_cmds,
								  TCLIE_ARRAY_SIZE(tclie_internal_cmds), match,
								  match_len, pad);
	pad = tclie_calculate_padding(tclie, tclie->cmd.cmds, tclie->cmd.count,
								  match, match_len, pad);

	pad += 1;
	const char *const *argv1 = argc > 1 ? &argv[1] : NULL;
	if (tclie_print_cmds(tclie, tclie_internal_cmds,
						 TCLIE_ARRAY_SIZE(tclie_internal_cmds), argc - 1, argv1,
						 match, match_len, pad, false) != 0)
		tclie_out(tclie, "\r\n");
	tclie_print_cmds(tclie, tclie->cmd.cmds, tclie->cmd.count, argc - 1, argv1,
					 match, match_len, pad, true);

	return 0;
}

static int tclie_cmd_clear(void *arg, const int argc, const char **argv)
{
	assert(arg);
	assert(argc >= 1);
	assert(argv);
	assert(argv[0]);

	tclie_t *const tclie = arg;
	tclie_clear_screen(tclie);
	return 0;
}

#if TCLIE_ENABLE_USERS
static int tclie_cmd_login(void *arg, const int argc, const char **argv)
{
	assert(arg);
	assert(argc >= 1);
	assert(argv);
	assert(argv[0]);

	tclie_t *const tclie = arg;
	return tclie_login_begin(tclie, argc == 2 ? argv[1] : NULL);
}

static int tclie_cmd_logout(void *arg, const int argc, const char **argv)
{
	assert(arg);
	assert(argc >= 1);
	assert(argv);
	assert(argv[0]);

	tclie_t *const tclie = arg;
	tclie_set_user_level(tclie, 0);
	return 0;
}
#endif

void tclie_input_char(tclie_t *const tclie, const char c)
{
	if (tclie)
		tcli_input_char(&tclie->tcli, c);
}

void tclie_input_str(tclie_t *const tclie, const char *const str)
{
	if (tclie)
		tcli_input_str(&tclie->tcli, str);
}

void tclie_input(tclie_t *const tclie, const void *const buf, const size_t len)
{
	if (tclie)
		tcli_input(&tclie->tcli, buf, len);
}

void tclie_set_echo(tclie_t *const tclie, const tcli_echo_mode_t mode)
{
	if (tclie)
		tcli_set_echo(&tclie->tcli, mode);
}

void tclie_set_prompt(tclie_t *const tclie, const char *const prompt)
{
	if (tclie)
		tcli_set_prompt(&tclie->tcli, prompt);
}

void tclie_set_error_prompt(tclie_t *const tclie,
							const char *const error_prompt)
{
	if (tclie)
		tcli_set_error_prompt(&tclie->tcli, error_prompt);
}

#if TCLI_HISTORY_BUF_LEN > 0
void tclie_set_hist(tclie_t *const tclie, const tcli_history_mode_t mode)
{
	if (tclie)
		tcli_set_hist(&tclie->tcli, mode);
}

void tclie_set_search_prompt(tclie_t *const tclie,
							 const char *const search_prompt)
{
	if (tclie)
		tcli_set_search_prompt(&tclie->tcli, search_prompt);
}
#endif

void tclie_log(tclie_t *const tclie, const char *const str)
{
	if (tclie)
		tcli_log(&tclie->tcli, str);
}

int tclie_log_vprintf(tclie_t *const tclie, char *const buf, const size_t len,
					  const char *const format, va_list arg)
{
	return tclie ? tcli_log_vprintf(&tclie->tcli, buf, len, format, arg) : -1;
}

int tclie_log_printf(tclie_t *const tclie, char *const buf, const size_t len,
					 const char *const format, ...)
{
	va_list arg;
	va_start(arg, format);
	const int count = tclie_log_vprintf(tclie, buf, len, format, arg);
	va_end(arg);
	return count;
}

void tclie_clear_screen(tclie_t *const tclie)
{
	if (tclie)
		tcli_clear_screen(&tclie->tcli);
}
