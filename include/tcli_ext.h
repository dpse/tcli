#ifndef TINYSH_EXT_H
#define TINYSH_EXT_H

#include "tcli.h"

#ifndef TCLIE_ENABLE_USERS
#define TCLIE_ENABLE_USERS 1
#endif

#ifndef TCLIE_ENABLE_USERNAMES
#define TCLIE_ENABLE_USERNAMES 1
#endif

#ifndef TCLIE_LOGIN_ATTEMPTS
#define TCLIE_LOGIN_ATTEMPTS 3
#endif

typedef tcli_out_fn_t tclie_out_fn_t;
typedef tcli_sigint_fn_t tclie_sigint_fn_t;

typedef int (*tclie_cmd_fn_t)(void *arg, int argc, const char *const *argv);

typedef const struct tclie_cmd {
	char *name;
	tclie_cmd_fn_t fn;
#if TCLIE_ENABLE_USERS
	unsigned min_user_level;
#endif
	int min_args;
	int max_args;
	char *desc;
} tclie_cmd_t;

typedef void (*tclie_pre_cmd_fn_t)(void *arg, int argc,
								   const char *const *argv);
typedef void (*tclie_post_cmd_fn_t)(void *arg, int argc,
									const char *const *argv, int res);

typedef struct tclie_cmds {
	tclie_cmd_t *cmds;
	size_t count;
} tclie_cmds_t;

#if TCLIE_ENABLE_USERS
typedef const struct tclie_user {
#if TCLIE_ENABLE_USERNAMES
	char *name;
#endif
	char *password;
	unsigned level;
} tclie_user_t;

typedef enum tclie_login_state {
	TCLIE_LOGIN_IDLE = 0,
#if TCLIE_ENABLE_USERNAMES
	TCLIE_LOGIN_USERNAME,
#endif
	TCLIE_LOGIN_PASSWORD
} tclie_login_state_t;

typedef struct tclie_login {
	tclie_login_state_t state;
#if TCLIE_ENABLE_USERNAMES
	size_t target_user;
#endif
	unsigned attempt;
} tclie_login_t;

typedef struct tclie_users {
	tclie_user_t *users;
	size_t count;
	tclie_login_t login;
	unsigned level;
} tclie_users_t;
#endif

typedef struct tclie {
	tcli_t tcli;
	tclie_cmds_t cmd;
#if TCLIE_ENABLE_USERS
	tclie_users_t user;
#endif
	tclie_out_fn_t out;
	tclie_pre_cmd_fn_t pre_cmd;
	tclie_post_cmd_fn_t post_cmd;
	tclie_sigint_fn_t sigint;
	void *arg;
} tclie_t;

bool tclie_init(tclie_t *tclie, tclie_out_fn_t out, void *arg);
#if TCLIE_ENABLE_USERS
bool tclie_reg_users(tclie_t *tclie, const tclie_user_t *users, size_t count);
#endif
bool tclie_reg_cmds(tclie_t *tclie, const tclie_cmd_t *cmds, size_t count);

bool tclie_input_char(tclie_t *tclie, char c);
bool tclie_input_str(tclie_t *tclie, const char *str);
bool tclie_input(tclie_t *tclie, const void *buf, size_t len);

bool tclie_set_out(tclie_t *tclie, tclie_out_fn_t out);
bool tclie_set_arg(tclie_t *tclie, void *arg);
bool tclie_set_echo(tclie_t *tclie, tcli_echo_mode_t mode);
bool tclie_set_sigint(tclie_t *tclie, tclie_sigint_fn_t sigint);
bool tclie_set_pre_cmd(tclie_t *tclie, tclie_pre_cmd_fn_t pre_cmd);
bool tclie_set_post_cmd(tclie_t *tclie, tclie_post_cmd_fn_t post_cmd);
bool tclie_set_prompt(tclie_t *tclie, const char *prompt);
bool tclie_set_error_prompt(tclie_t *tclie, const char *error_prompt);
#if TCLI_HISTORY_BUF_LEN > 0
bool tclie_set_hist(tclie_t *tclie, tcli_history_mode_t mode);
bool tclie_set_search_prompt(tclie_t *tclie, const char *search_prompt);
#endif

#if TCLIE_ENABLE_USERS
bool tclie_set_user_level(tclie_t *tclie, unsigned user_level);
bool tclie_get_user_level(const tclie_t *tclie, unsigned *user_level);
#endif

bool tclie_log_str(tclie_t *tclie, bool newline, const char *str);
int tclie_log_vprintf(tclie_t *tclie, bool newline, char *buf, size_t len,
					  const char *format, va_list arg);
int tclie_log_printf(tclie_t *tclie, bool newline, char *buf, size_t len,
					 const char *format, ...);

void tclie_flush(tclie_t *tclie);
void tclie_out(tclie_t *tclie, const char *str);

void tclie_clear_screen(tclie_t *tclie);

#endif
