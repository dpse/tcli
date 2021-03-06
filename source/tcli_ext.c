#include "tcli_ext.h"
#include <assert.h>
#include <string.h>

#define TCLIE_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

extern void tcli_clear_screen(tcli_t *tcli);

extern void tcli_out(tcli_t *tcli, const char *str);
extern void tcli_flush(tcli_t *tcli);

static int tclie_cmd_help(void *arg, int argc, const char *const *argv);
static int tclie_cmd_clear(void *arg, int argc, const char *const *argv);
#if TCLIE_ENABLE_USERS
static int tclie_cmd_login(void *arg, int argc, const char *const *argv);
static int tclie_cmd_logout(void *arg, int argc, const char *const *argv);
#endif

static const tclie_cmd_t tclie_internal_cmds[] = {
    {"help", tclie_cmd_help, 0, 0,
#if TCLIE_ENABLE_USERS
     0,
#endif
     "Print available commands."},
    {"clear", tclie_cmd_clear, 0, 0,
#if TCLIE_ENABLE_USERS
     0,
#endif
     "Clear screen."},
#if TCLIE_ENABLE_USERS
#if TCLIE_ENABLE_USERNAMES
    {"login", tclie_cmd_login, 0, 0, 1, "Login as user."},
#else
    {"login", tclie_cmd_login, 0, 0, 0, "Login using password."},
#endif
    {"logout", tclie_cmd_logout, 1, 0, 0, "Logout."},
#endif
};

static bool tclie_valid_cmd(const tclie_t *const tclie,
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

static inline void tclie_out(tclie_t *const tclie, const char *const str)
{
    assert(tclie && str);
    tcli_out(&tclie->tcli, str);
}

static inline void tclie_flush(tclie_t *const tclie)
{
    assert(tclie);
    tcli_flush(&tclie->tcli);
}

static inline void tclie_out_flush(tclie_t *const tclie, const char *const str)
{
    assert(tclie);
    tclie_out(tclie, str);
    tclie_flush(tclie);
}

static void tclie_print_str(tclie_t *const tclie, const char *const head_str,
			    const char *const color, const size_t pad,
			    const char *const desc_str, const bool flush)
{
    assert(tclie);
    assert(head_str);

    if (color)
	tclie_out(tclie, color);
    tclie_out(tclie, head_str);
    if (desc_str) {
	tclie_out(tclie, ": ");
	size_t len = strlen(head_str);
	while (len++ < pad)
	    tclie_out(tclie, " ");
    }
    if (color)
	tclie_out(tclie, TCLI_COLOR_DEFAULT);
    if (desc_str)
	tclie_out(tclie, desc_str);
    tclie_out(tclie, "\r\n");
    if (flush)
	tclie_flush(tclie);
}

static inline void tclie_print_cmd(tclie_t *const tclie,
				   const tclie_cmd_t *const cmd,
				   const size_t pad, const bool flush)
{
    assert(tclie);
    assert(cmd);
    assert(cmd->name);

    tclie_print_str(tclie, cmd->name, TCLI_COLOR_MAGENTA, pad, cmd->desc,
		    flush);
}

static void tclie_complete(const tclie_t *const tclie,
			   const tclie_cmd_t *const cmds,
			   const size_t cmd_count, const char *const match,
			   const size_t match_len, const char **const compl,
			   const size_t max_count, size_t *const count)
{
    assert(tclie);
    assert(cmds);
    assert(match);
    assert(match_len > 0);
    assert(compl );
    assert(count);

    for (size_t i = 0; i < cmd_count && * count < max_count; i++) {
	const tclie_cmd_t *const cmd = &cmds[i];

	if (!tclie_valid_cmd(tclie, cmd))
	    continue;

	if (strncmp(match, cmd->name, match_len) != 0)
	    continue;

	const size_t cmd_len = strlen(cmd->name);

	if (cmd_len < match_len)
	    continue;

	if (cmd_len == match_len)
	    return;

	compl [(*count)++] = cmd->name;
    }
}

static void tcli_complete(void *const arg, const int argc,
			  const char *const *const argv,
			  const char **const compl, const size_t max_count,
			  size_t *const count)
{
    assert(arg);
    assert(argc > 0);
    assert(argv);
    assert(compl );
    assert(count);

    if (max_count == 0 || argc > 1)
	return;

    const char *const match = argv[argc - 1];
    assert(match);

    const size_t match_len = strlen(match);

    if (match_len == 0)
	return;

    const tclie_t *const tclie = arg;
    *count = 0;

    tclie_complete(tclie, tclie_internal_cmds,
		   TCLIE_ARRAY_SIZE(tclie_internal_cmds), match, match_len,
		   compl, max_count, count);
    tclie_complete(tclie, tclie->cmd.cmds, tclie->cmd.count, match, match_len,
		   compl, max_count, count);
}

static bool tclie_exec(tclie_t *const tclie, const tclie_cmd_t *const cmds,
		       const size_t cmd_count, void *const arg, const int argc,
		       const char *const *const argv, int *const res)
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

	if ((cmd->min_args >= 0 && argc < cmd->min_args + 1) ||
	    (cmd->max_args >= 0 && argc > cmd->max_args + 1)) {
	    tclie_print_str(tclie, "Invalid number of arguments", NULL, 0,
			    argv[0], true);
	    *res = -1;
	    return true;
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

static int tcli_exec(void *const arg, const int argc,
		     const char *const *const argv)
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
	tcli_log_str(&tclie->tcli, true, "Aborted!");
	tclie_login_proceed(&tclie->user.login, TCLIE_LOGIN_IDLE);
    }
#endif

    if (tclie->sigint)
	tclie->sigint(tclie->arg);
}

bool tclie_set_arg(tclie_t *const tclie, void *const arg)
{
    if (!tclie)
	return false;

    tclie->arg = arg;
    return true;
}

bool tclie_set_pre_cmd(tclie_t *const tclie, tclie_pre_cmd_fn_t pre_cmd)
{
    if (!tclie)
	return false;

    tclie->pre_cmd = pre_cmd;
    return true;
}

bool tclie_set_post_cmd(tclie_t *const tclie, tclie_post_cmd_fn_t post_cmd)
{
    if (!tclie)
	return false;

    tclie->post_cmd = post_cmd;
    return true;
}

bool tclie_set_sigint(tclie_t *const tclie, tclie_sigint_fn_t sigint)
{
    if (!tclie)
	return false;

    tclie->sigint = sigint;
    return true;
}

bool tclie_init(tclie_t *tclie, tcli_out_fn_t out, void *arg)
{
    if (!tclie)
	return false;

    memset(tclie, 0, sizeof(tclie_t));

    if (!tclie_set_arg(tclie, arg))
	return false;
    if (!tclie_set_pre_cmd(tclie, NULL))
	return false;
    if (!tclie_set_post_cmd(tclie, NULL))
	return false;
    if (!tclie_set_sigint(tclie, NULL))
	return false;

    if (!tcli_init(&tclie->tcli, out, tclie))
	return false;
    if (!tcli_set_exec(&tclie->tcli, tcli_exec))
	return false;
    if (!tcli_set_complete(&tclie->tcli, tcli_complete))
	return false;
    if (!tcli_set_sigint(&tclie->tcli, tcli_sigint))
	return false;

    return true;
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
bool tclie_set_user_level(tclie_t *const tclie, const unsigned user_level)
{
    if (!tclie)
	return false;

    tclie->user.level = user_level;
    return true;
}

bool tclie_get_user_level(const tclie_t *const tclie, unsigned *const user_level)
{
    if (!tclie || !user_level)
	return false;

    *user_level = tclie->user.level;
    return true;
}
#endif

static int tclie_cmd_help(void *arg, const int argc, const char *const *argv)
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

static int tclie_cmd_clear(void *arg, const int argc, const char *const *argv)
{
    assert(arg);
    assert(argc >= 1);
    assert(argv);
    assert(argv[0]);

    tclie_t *const tclie = arg;
    tcli_clear_screen(&tclie->tcli);
    return 0;
}

#if TCLIE_ENABLE_USERS
static int tclie_cmd_login(void *arg, const int argc, const char *const *argv)
{
    assert(arg);
    assert(argc >= 1);
    assert(argv);
    assert(argv[0]);

    tclie_t *const tclie = arg;
    return tclie_login_begin(tclie, argc == 2 ? argv[1] : NULL);
}

static int tclie_cmd_logout(void *arg, const int argc, const char *const *argv)
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
