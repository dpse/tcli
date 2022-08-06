#ifndef TCLI_H
#define TCLI_H

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
/**
 * The maximum number of characters that the command line can hold (not
 * including null-terminator).
 */
#define TCLI_CMDLINE_MAX_LEN 64
#endif

#ifndef TCLI_MAX_TOKENS
/**
 * The maximum number of tokens that can be processed on command execution.
 */
#define TCLI_MAX_TOKENS 8
#endif

#ifndef TCLI_HISTORY_BUF_LEN
/**
 * The size of the ring buffer used to save command history.
 * Set to zero to disable history.
 */
#define TCLI_HISTORY_BUF_LEN 512
#endif

#ifndef TCLI_OUTPUT_BUF_LEN
/**
 * The size of the output buffer.
 * Set to zero to disable output buffering.
 */
#define TCLI_OUTPUT_BUF_LEN 256
#endif

#ifndef TCLI_DEFAULT_PROMPT
/**
 * The default prompt.
 */
#define TCLI_DEFAULT_PROMPT (TCLI_COLOR_GREEN "> " TCLI_COLOR_DEFAULT)
#endif

#ifndef TCLI_DEFAULT_SEARCH_PROMPT
/**
 * The default search prompt used for backwards search.
 */
#define TCLI_DEFAULT_SEARCH_PROMPT (TCLI_COLOR_GREEN "? " TCLI_COLOR_DEFAULT)
#endif

#ifndef TCLI_DEFAULT_ERROR_PROMPT
/**
 * The default error prompt (displayed when the previous command failed).
 */
#define TCLI_DEFAULT_ERROR_PROMPT (TCLI_COLOR_RED "> " TCLI_COLOR_DEFAULT)
#endif

typedef void (*tcli_out_fn_t)(void *arg, const char *str);
typedef int (*tcli_exec_fn_t)(void *arg, int argc, const char **argv);
typedef void (*tcli_compl_fn_t)(void *arg, int argc, const char **argv,
								const char ** compl, size_t max_count,
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

/**
 * Initializes the instance.
 * @param tcli Pointer to instance.
 * @param out Output callback function.
 * @param arg User data to be passed to callback functions.
 */
void tcli_init(tcli_t *tcli, tcli_out_fn_t out, void *arg);

/**
 * Pass input to be processed.
 * @param tcli Instance pointer.
 * @param c Character to process.
 */
void tcli_input_char(tcli_t *tcli, char c);

/**
 * Pass string input to be processed.
 * @param tcli Instance pointer.
 * @param str Null-terminated string to process.
 */
void tcli_input_str(tcli_t *tcli, const char *str);

/**
 * Pass data input to be processed.
 * @param tcli Instance pointer.
 * @param buf Pointer to data buffer.
 * @param len Data length.
 */
void tcli_input(tcli_t *tcli, const void *buf, size_t len);

/**
 * Set callback function for output.
 * @param tcli Instance pointer.
 * @param out Output callback function.
 */
void tcli_set_out(tcli_t *tcli, tcli_out_fn_t out);

/**
 * Set callback function for command execution.
 * @param tcli Instance pointer.
 * @param exec Callback function.
 */
void tcli_set_exec(tcli_t *tcli, tcli_exec_fn_t exec);

/**
 * Set user data for callback functions.
 * @param tcli Instance pointer.
 * @param arg Pointer to user data.
 */
void tcli_set_arg(tcli_t *tcli, void *arg);

/**
 * Set echo mode for output.
 * @param tcli Instance pointer.
 * @param mode Echo mode.
 */
void tcli_set_echo(tcli_t *tcli, tcli_echo_mode_t mode);

/**
 * Set callback function for tab-completion.
 * @param tcli Instance pointer.
 * @param complete Callback function.
 */
void tcli_set_complete(tcli_t *tcli, tcli_compl_fn_t complete);

/**
 * Set callback function for SIGINT (ctrl+c).
 * @param tcli Instance pointer.
 * @param sigint Callback function.
 */
void tcli_set_sigint(tcli_t *tcli, tcli_sigint_fn_t sigint);

/**
 * Set default prompt string.
 * @param tcli Instance pointer.
 * @param prompt Prompt string.
 */
void tcli_set_prompt(tcli_t *tcli, const char *prompt);

/**
 * Set error prompt string (used when previous command failed).
 * @param tcli Instance pointer.
 * @param error_prompt Prompt string.
 */
void tcli_set_error_prompt(tcli_t *tcli, const char *error_prompt);

#if TCLI_HISTORY_BUF_LEN > 0

/**
 * Set history mode for recording entered lines.
 * @param tcli Instance pointer.
 * @param mode History mode.
 */
void tcli_set_hist(tcli_t *tcli, tcli_history_mode_t mode);

/**
 * Set search prompt (used when backwards-searching).
 * @param tcli Instance pointer.
 * @param search_prompt Prompt string.
 */
void tcli_set_search_prompt(tcli_t *tcli, const char *search_prompt);

#endif

/**
 * Logs a string without disturbing the current prompt.
 * @param tcli Instance pointer.
 * @param str String.
 */
void tcli_log_str(tcli_t *tcli, const char *str);

/**
 * Logs formatted data from variable argument list without disturbing the
 * current prompt.
 * @param tcli Instance pointer.
 * @param buf Buffer to hold formatted data.
 * @param len Buffer length.
 * @param format Format string.
 * @param arg Variable arguments list.
 * @return On success, the total number of characters written, else -1.
 */
int tcli_log_vprintf(tcli_t *tcli, char *buf, size_t len, const char *format,
					 va_list arg);

/**
 * Logs formatted string without disturbing the current prompt.
 * @param tcli Instance pointer.
 * @param buf Buffer to hold formatted data.
 * @param len Buffer length.
 * @param format Format string.
 * @param ... Arguments depending on format string.
 * @return On success, the total number of characters written, else -1.
 */
int tcli_log_printf(tcli_t *tcli, char *buf, size_t len, const char *format,
					...);

/**
 * Flushes output buffer (if used).
 * @param tcli Instance pointer.
 */
void tcli_flush(tcli_t *tcli);

/**
 * Outputs a string through the instance output callback function. May be
 * buffered.
 * @param tcli Instance pointer.
 * @param str String to output.
 */
void tcli_out(tcli_t *tcli, const char *str);

/**
 * Outputs data from variable argument list without disturbing the
 * current prompt. May be buffered.
 * @param tcli Instance pointer.
 * @param buf Buffer to hold formatted data.
 * @param len Buffer length.
 * @param format Format string.
 * @param arg Variable arguments list.
 * @return On success, the total number of characters written, else -1.
 */
int tcli_out_vprintf(tcli_t *tcli, char *buf, size_t len, const char *format,
					 va_list arg);

/**
 * Outputs formatted string without disturbing the current prompt. May be
 * buffered.
 * @param tcli Instance pointer.
 * @param buf Buffer to hold formatted data.
 * @param len Buffer length.
 * @param format Format string.
 * @param ... Arguments depending on format string.
 * @return On success, the total number of characters written, else -1.
 */
int tcli_out_printf(tcli_t *tcli, char *buf, size_t len, const char *format,
					...);

/**
 * Clears the current screen output.
 * @param tcli Instance pointer.
 */
void tcli_clear_screen(tcli_t *tcli);

#endif
