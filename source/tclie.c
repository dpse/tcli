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
#if TCLIE_PATTERN_MATCH
	 NULL,
#endif
	 "Print available commands."},
	{"clear", tclie_cmd_clear,
#if TCLIE_ENABLE_USERS
	 0,
#endif
#if TCLIE_PATTERN_MATCH
	 NULL,
#endif
	 "Clear screen."},
#if TCLIE_ENABLE_USERS
#if TCLIE_ENABLE_USERNAMES
	{"login", tclie_cmd_login, 0,
#if TCLIE_PATTERN_MATCH
	 "login [<username>]",
#endif
	 "Login as user."},
#else
	{"login", tclie_cmd_login, 0,
#if TCLIE_PATTERN_MATCH
	 NULL,
#endif
	 "Login using password."},
#endif
	{"logout", tclie_cmd_logout, 1,
#if TCLIE_PATTERN_MATCH
	 NULL,
#endif
	 "Logout."},
#endif
};

#if TCLIE_PATTERN_MATCH
static inline bool tclie_is_space(const char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
		   c == '\v';
}

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

static size_t tclie_pattern_tokenize(const char *str, const size_t len,
									 tclie_token_t *const tokens,
									 const size_t max_tokens,
									 const tclie_token_combinator_t combinator)
{
	assert(str);
	assert(tokens);
	assert(combinator < TCLIE_COMBINATOR_COUNT);

	const char *const str_max = str + len;
	size_t found_tokens = 0;
	struct {
		bool active;
		int count;
		tclie_token_delim_t delim;
	} delim = {0};

	while (found_tokens < max_tokens && str < str_max) {
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

			if (str_len >= 2 && tclie_pattern_delim(*start, &delim.delim) &&
				start[str_len - 1] == delim.delim.stop) {
				start++;
				str_len -= 2;
				tokens[found_tokens].type = delim.delim.type;
			} else if (tclie_pattern_compare(start, str_len, "..."))
				tokens[found_tokens].type = TCLIE_TOKEN_MULTI_WILDCARD;
			else
				tokens[found_tokens].type = TCLIE_TOKEN_UNKNOWN;

			if (str_len != 0) {
				tokens[found_tokens].str = start;
				tokens[found_tokens].len = str_len;
				found_tokens++;
			}
		}

		if (*str == '\0')
			break;

		str++;
	}

	return found_tokens;
}

static inline size_t tclie_pattern_tokenize_token(
	const tclie_token_t *const token, tclie_token_t *const tokens,
	const size_t max_tokens, const tclie_token_combinator_t combinator)
{
	assert(token);
	assert(tokens);

	return tclie_pattern_tokenize(token->str, token->len, tokens, max_tokens,
								  combinator);
}

static size_t
tclie_pattern_reduce_token(const tclie_token_t *const token,
						   tclie_token_t *const tokens, const size_t max_tokens,
						   tclie_token_combinator_t *const combinator)
{
	assert(token);
	assert(tokens);
	assert(combinator);
	assert(max_tokens != 0);

	const tclie_token_combinator_t combinators[] = {TCLIE_COMBINATOR_AND,
													TCLIE_COMBINATOR_OR};

	for (size_t i = 0; i < TCLIE_ARRAY_SIZE(combinators); i++) {
		const size_t count = tclie_pattern_tokenize_token(
			token, tokens, max_tokens, combinators[i]);

		if (count == 0 || count > 1 || token->type != tokens[0].type) {
			*combinator = combinators[i];
			return count;
		}
	}

	*combinator = TCLIE_COMBINATOR_AND;
	tokens[0].str = token->str;
	tokens[0].len = token->len;
	tokens[0].type = TCLIE_TOKEN_EXACT;
	return 1;
}

static bool tclie_pattern_match_token(const tclie_token_t *restrict const token,
									  const int argc,
									  const char *restrict *const argv,
									  int *const arg_index)
{
	assert(token);
	assert(argv);
	assert(arg_index);
	assert(token->type < TCLIE_TOKEN_COUNT);

	if (token->type == TCLIE_TOKEN_MULTI_WILDCARD) {
		*arg_index = argc;
		return true;
	}

	if (token->type == TCLIE_TOKEN_EXACT) {
		if (*arg_index >= argc)
			return false;
		return tclie_pattern_compare_token(token, argv[(*arg_index)++]);
	}

	if (token->type == TCLIE_TOKEN_WILDCARD) {
		if (*arg_index >= argc)
			return false;
		(*arg_index)++;
		return true;
	}

	tclie_token_t tokens[TCLIE_PATTERN_MATCH_MAX_TOKENS] = {0};
	tclie_token_combinator_t combinator = TCLIE_COMBINATOR_AND;
	const size_t count = tclie_pattern_reduce_token(
		token, tokens, TCLIE_ARRAY_SIZE(tokens), &combinator);

	if (count == 0)
		return false;

	assert(combinator < TCLIE_COMBINATOR_COUNT);

	for (size_t i = 0; i < count; i++) {
		const int old_arg_index = *arg_index;
		const bool match =
			tclie_pattern_match_token(&tokens[i], argc, argv, arg_index);

		if (!match)
			*arg_index = old_arg_index;

		if (combinator == TCLIE_COMBINATOR_OR) {
			if (match)
				return true;
		} else if (!match)
			return token->type == TCLIE_TOKEN_OPTIONAL;
	}

	return combinator == TCLIE_COMBINATOR_AND;
}

bool tclie_pattern_match(const char *restrict pattern, const int argc,
						 const char *restrict *const argv)
{
	assert(argv);

	if (!pattern)
		return false;

	const tclie_token_t token = {
		.type = TCLIE_TOKEN_UNKNOWN, .str = pattern, .len = strlen(pattern)};
	int arg_index = 0;
	return tclie_pattern_match_token(&token, argc, argv, &arg_index) &&
		   arg_index == argc;
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

static void tclie_print_str(tclie_t *const tclie, const char *const head_str,
							const char *const color, size_t pad,
							const char *const desc_str, const bool flush)
{
	assert(tclie);

	pad += 2;

	if (color)
		tclie_out(tclie, color);
	if (head_str)
		tclie_out(tclie, head_str);
	if (desc_str) {
		size_t len = 0;
		if (head_str) {
			tclie_out(tclie, ": ");
			len = 2 + strlen(head_str);
		}
		while (len++ < pad)
			tclie_out(tclie, " ");
	}
	if (color)
		tclie_out(tclie, TCLI_FORMAT_RESET);
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

	tclie_print_str(tclie, cmd->name, TCLI_COLOR_MAGENTA, pad, cmd->desc,
					flush && !cmd->pattern);

	if (cmd->pattern)
		tclie_print_str(tclie, NULL, TCLI_COLOR_BRIGHT_BLUE, pad, cmd->pattern,
						flush);
}

#if TCLI_COMPLETE
static void tclie_complete(const tclie_t *const tclie,
						   const tclie_cmd_t *const cmds,
						   const size_t cmd_count, const char *const match,
						   const size_t match_len,
						   const char **const completions,
						   const size_t max_count, size_t *const count)
{
	assert(tclie);
	assert(cmds);
	assert(match);
	assert(match_len > 0);
	assert(completions);
	assert(count);

	for (size_t i = 0; i < cmd_count && *count < max_count; i++) {
		const tclie_cmd_t *const cmd = &cmds[i];

		if (!tclie_valid_cmd(tclie, cmd))
			continue;

		if (strncmp(match, cmd->name, match_len) != 0)
			continue;

		const size_t cmd_len = strlen(cmd->name);

		if (cmd_len < match_len)
			continue;

		completions[(*count)++] = cmd->name;
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

	if (max_count == 0 || match != argv[0])
		return 0;

	const size_t match_len = strlen(match);

	if (match_len == 0)
		return 0;

	const tclie_t *const tclie = arg;
	size_t count = 0;

	tclie_complete(tclie, tclie_internal_cmds,
				   TCLIE_ARRAY_SIZE(tclie_internal_cmds), match, match_len,
				   completions, max_count, &count);
	tclie_complete(tclie, tclie->cmd.cmds, tclie->cmd.count, match, match_len,
				   completions, max_count, &count);

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
			if (!tclie_pattern_match(cmd->pattern, argc, argv))
				continue;
		} else
#endif
			if (strcmp(argv[0], cmd->name) != 0)
			continue;

		if (cmd->desc && argc >= 2) {
			assert(argv[1]);
			if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
				tclie_print_cmd(tclie, cmd, 0, true);
				*res = 0;
				return true;
			}
		}

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
		tclie_out_flush(tclie, "Failed!\r\n");
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
	tclie_out_flush(tclie, "Success!\r\n");
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

	tclie_print_str(tclie, "Unknown command", NULL, 0, argv[0], true);
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

	tclie_t *const tclie = arg;

	size_t pad = 0;

	for (size_t i = 0; i < TCLIE_ARRAY_SIZE(tclie_internal_cmds); i++) {
		if (!tclie_valid_cmd(tclie, &tclie_internal_cmds[i]))
			continue;

		assert(tclie_internal_cmds[i].name);
		const size_t len = strlen(tclie_internal_cmds[i].name);
		if (len > pad)
			pad = len;
	}

	for (size_t i = 0; i < tclie->cmd.count; i++) {
		if (!tclie_valid_cmd(tclie, &tclie->cmd.cmds[i]))
			continue;

		assert(tclie->cmd.cmds[i].name);
		const size_t len = strlen(tclie->cmd.cmds[i].name);
		if (len > pad)
			pad = len;
	}

	for (size_t i = 0; i < TCLIE_ARRAY_SIZE(tclie_internal_cmds); i++) {
		if (tclie_valid_cmd(tclie, &tclie_internal_cmds[i]))
			tclie_print_cmd(tclie, &tclie_internal_cmds[i], pad, false);
	}

	for (size_t i = 0; i < tclie->cmd.count; i++) {
		if (tclie_valid_cmd(tclie, &tclie->cmd.cmds[i]))
			tclie_print_cmd(tclie, &tclie->cmd.cmds[i], pad, false);
	}

	tclie_flush(tclie);

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
