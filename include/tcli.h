#ifndef TINYSH_H
#define TINYSH_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TCLI_COLOR_RED "\033[31m"
#define TCLI_COLOR_GREEN "\033[32m"
#define TCLI_COLOR_YELLOW "\033[33m"
#define TCLI_COLOR_BLUE "\033[34m"
#define TCLI_COLOR_PURPLE "\033[35m"
#define TCLI_COLOR_MAGENTA "\033[36m"
#define TCLI_COLOR_WHITE "\033[37m"
#define TCLI_COLOR_DEFAULT "\033[0m"

#ifndef TCLI_CMDLINE_MAX_LEN
#define TCLI_CMDLINE_MAX_LEN 64
#endif

#ifndef TCLI_MAX_TOKENS
#define TCLI_MAX_TOKENS 8
#endif

#ifndef TCLI_HISTORY_BUF_LEN
#define TCLI_HISTORY_BUF_LEN 512
#endif

#ifndef TCLI_OUTPUT_BUF_LEN
#define TCLI_OUTPUT_BUF_LEN 256
#endif

#ifndef TCLI_DEFAULT_PROMPT
#define TCLI_DEFAULT_PROMPT (TCLI_COLOR_GREEN "> " TCLI_COLOR_DEFAULT)
#endif

#ifndef TCLI_DEFAULT_SEARCH_PROMPT
#define TCLI_DEFAULT_SEARCH_PROMPT (TCLI_COLOR_GREEN "? " TCLI_COLOR_DEFAULT)
#endif

#ifndef TCLI_DEFAULT_ERROR_PROMPT
#define TCLI_DEFAULT_ERROR_PROMPT (TCLI_COLOR_RED "> " TCLI_COLOR_DEFAULT)
#endif

typedef void (*tcli_out_fn_t)(void *arg, const char *str);
typedef int (*tcli_exec_fn_t)(void *arg, int argc, const char *const *argv);
typedef void (*tcli_compl_fn_t)(void *arg, int argc, const char *const *argv,
								const char * * compl, size_t max_count,
								size_t *count);
typedef void (*tcli_sigint_fn_t)(void *arg);

typedef struct tcli_cmdline {
	char buf[TCLI_CMDLINE_MAX_LEN + 1];
	size_t len;
	size_t cursor;
} tcli_cmdline_t;

typedef struct tcli_esc {
	unsigned char code;
	bool esc : 1;
} tcli_esc_t;

typedef enum tcli_echo_mode {
	TCLI_ECHO_ON = 0,
	TCLI_ECHO_OFF,
	TCLI_ECHO_OFF_ONCE
} tcli_echo_mode_t;

typedef struct tcli_echo {
	tcli_echo_mode_t mode : 2;
} tcli_echo_t;

#if TCLI_HISTORY_BUF_LEN > 0
typedef enum tcli_history_mode {
	TCLI_HIST_ON = 0,
	TCLI_HIST_OFF,
	TCLI_HIST_OFF_ONCE
} tcli_history_mode_t;

typedef struct tcli_rb {
	size_t head;
	size_t tail;
	size_t count;
	size_t pos;
	char buf[TCLI_HISTORY_BUF_LEN];
} tcli_rb_t;

typedef struct tcli_hist {
	size_t offset;
	tcli_rb_t rb;
	tcli_history_mode_t mode : 2;
	bool has_line : 1;
	bool search : 1;
	const char *search_prompt;
} tcli_hist_t;
#endif

#if TCLI_OUTPUT_BUF_LEN > 0
typedef struct tcli_out_buf {
	size_t len;
	char buf[TCLI_OUTPUT_BUF_LEN];
} tcli_out_buf_t;
#endif

typedef struct tcli_complete {
	tcli_compl_fn_t complete;
	bool active : 1;
} tcli_complete_t;

typedef struct tcli {
	tcli_cmdline_t cmdline;
	tcli_out_fn_t out;
	tcli_exec_fn_t exec;
	tcli_complete_t complete;
	tcli_sigint_fn_t sigint;
	tcli_esc_t esc;
	tcli_echo_t echo;
#if TCLI_HISTORY_BUF_LEN > 0
	tcli_hist_t hist;
#endif
#if TCLI_OUTPUT_BUF_LEN > 0
	tcli_out_buf_t out_buf;
#endif
	void *arg;
	int res;
	const char *prompt;
	const char *error_prompt;
	char last_endl;
	volatile bool executing : 1;
} tcli_t;

void tcli_init(tcli_t *tcli, tcli_out_fn_t out, void *arg);

void tcli_input_char(tcli_t *tcli, char c);
void tcli_input_str(tcli_t *tcli, const char *str);
void tcli_input(tcli_t *tcli, const void *buf, size_t len);

void tcli_set_out(tcli_t *tcli, tcli_out_fn_t out);
void tcli_set_exec(tcli_t *tcli, tcli_exec_fn_t exec);
void tcli_set_arg(tcli_t *tcli, void *arg);
void tcli_set_echo(tcli_t *tcli, tcli_echo_mode_t mode);
void tcli_set_complete(tcli_t *tcli, tcli_compl_fn_t complete);
void tcli_set_sigint(tcli_t *tcli, tcli_sigint_fn_t sigint);
void tcli_set_prompt(tcli_t *tcli, const char *prompt);
void tcli_set_error_prompt(tcli_t *tcli, const char *error_prompt);
#if TCLI_HISTORY_BUF_LEN > 0
void tcli_set_hist(tcli_t *tcli, tcli_history_mode_t mode);
void tcli_set_search_prompt(tcli_t *tcli, const char *search_prompt);
#endif

void tcli_log_str(tcli_t *tcli, const char *str);
int tcli_log_vprintf(tcli_t *tcli, char *buf, size_t len, const char *format,
					 va_list arg);
int tcli_log_printf(tcli_t *tcli, char *buf, size_t len, const char *format,
					...);

void tcli_flush(tcli_t *tcli);
void tcli_out(tcli_t *tcli, const char *str);

void tcli_clear_screen(tcli_t *tcli);

#endif
