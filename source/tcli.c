#include "tcli.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static_assert(TCLI_CMDLINE_MAX_LEN > 0,
			  "Command line length must be larger than zero.");
static_assert(TCLI_MAX_TOKENS > 0,
			  "Maximum number of tokens must be at least one.");
static_assert(TCLI_HISTORY_BUF_LEN >= 0,
			  "History buffer length must be at least zero.");
static_assert(TCLI_OUTPUT_BUF_LEN >= 0,
			  "Output buffer length must be at least zero.");

#define TCLI_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define TCLI_ASSERT(tcli)                                                      \
	assert(tcli);                                                              \
	assert((tcli)->cmdline.len <= TCLI_CMDLINE_MAX_LEN);                       \
	assert((tcli)->cmdline.cursor <= (tcli)->cmdline.len)

#if TCLI_HISTORY_BUF_LEN > 0
#define TCLI_ASSERT_RB(rb)                                                     \
	assert(rb);                                                                \
	assert((rb)->head < TCLI_ARRAY_SIZE((rb)->buf));                           \
	assert((rb)->tail < TCLI_ARRAY_SIZE((rb)->buf));                           \
	assert((rb)->count <= TCLI_ARRAY_SIZE((rb)->buf));                         \
	assert((rb)->pos < TCLI_ARRAY_SIZE((rb)->buf))
#endif

#if TCLI_OUTPUT_BUF_LEN > 0
#define TCLI_ASSERT_OUT_BUF(out_buf)                                           \
	assert(out_buf);                                                           \
	assert((out_buf)->len <= TCLI_ARRAY_SIZE((out_buf)->buf))
#endif

enum {
	TCLI_NUL = 0x00,
	TCLI_SOH = 0x01,
	TCLI_STX = 0x02,
	TCLI_ETX = 0x03,
	TCLI_EOT = 0x04,
	TCLI_ENQ = 0x05,
	TCLI_ACK = 0x06,
	TCLI_BEL = 0x07,
	TCLI_BS = 0x08,
	TCLI_HT = 0x09,
	TCLI_LF = 0x0A,
	TCLI_VT = 0x0B,
	TCLI_FF = 0x0C,
	TCLI_CR = 0x0D,
	TCLI_SO = 0x0E,
	TCLI_SI = 0x0F,
	TCLI_DLE = 0x10,
	TCLI_DC1 = 0x11,
	TCLI_DC2 = 0x12,
	TCLI_DC3 = 0x13,
	TCLI_DC4 = 0x14,
	TCLI_NAK = 0x15,
	TCLI_SYN = 0x16,
	TCLI_ETB = 0x17,
	TCLI_CAN = 0x18,
	TCLI_EM = 0x19,
	TCLI_SUB = 0x1A,
	TCLI_ESC = 0x1B,
	TCLI_FS = 0x1C,
	TCLI_GS = 0x1D,
	TCLI_RS = 0x1E,
	TCLI_US = 0x1F,
	TCLI_DEL = 0x7F
};

enum {
	TCLI_OP_NONE = 0,
	TCLI_OP_BACKSPACE_MAX,
	TCLI_OP_DELETE_MAX,
	TCLI_OP_BACKSPACE_ONE,
	TCLI_OP_DELETE_ONE,
	TCLI_OP_CURSOR_FORWARD_MAX,
	TCLI_OP_CURSOR_BACKWARD_MAX,
	TCLI_OP_CURSOR_FORWARD_ONE,
	TCLI_OP_CURSOR_BACKWARD_ONE,
#if TCLI_HISTORY_BUF_LEN > 0
	TCLI_OP_HIST_MODE_TOGGLE,
	TCLI_OP_HIST_MODE_OFF,
	TCLI_OP_HIST_PREV,
	TCLI_OP_HIST_NEXT,
	TCLI_OP_HIST_RESTORE,
#endif
	TCLI_OP_COMPLETE,
	TCLI_OP_SIGINT,
	TCLI_OP_CURSOR_FORWARD_WORD,
	TCLI_OP_CURSOR_BACKWARD_WORD,
	TCLI_OP_BACKSPACE_WORD,
	TCLI_OP_DELETE_WORD,
	TCLI_OP_CLEAR
};

static const struct {
	char match;
	unsigned char op;
} ctrl_char_table[] = {{TCLI_ACK, TCLI_OP_CURSOR_FORWARD_ONE},
					   {TCLI_STX, TCLI_OP_CURSOR_BACKWARD_ONE},
					   {TCLI_DEL, TCLI_OP_BACKSPACE_ONE},
					   {TCLI_BS, TCLI_OP_BACKSPACE_ONE},
					   {TCLI_EOT, TCLI_OP_DELETE_ONE},
					   {TCLI_NAK, TCLI_OP_BACKSPACE_MAX},
					   {TCLI_VT, TCLI_OP_DELETE_MAX},
					   {TCLI_ENQ, TCLI_OP_CURSOR_FORWARD_MAX},
					   {TCLI_SOH, TCLI_OP_CURSOR_BACKWARD_MAX},
					   {TCLI_ETB, TCLI_OP_BACKSPACE_WORD},
#if TCLI_HISTORY_BUF_LEN > 0
					   {TCLI_DLE, TCLI_OP_HIST_PREV},
					   {TCLI_SO, TCLI_OP_HIST_NEXT},
					   {TCLI_DC2, TCLI_OP_HIST_MODE_TOGGLE},
					   {TCLI_ESC, TCLI_OP_HIST_MODE_OFF},
#endif
					   {TCLI_HT, TCLI_OP_COMPLETE},
					   {TCLI_ETX, TCLI_OP_SIGINT},
					   {TCLI_FF, TCLI_OP_CLEAR}};

enum {
	TCLI_ESC_NONE = 0,
	TCLI_ESC_BRACKET,
	TCLI_ESC_HOME,
	TCLI_ESC_INSERT,
	TCLI_ESC_DELETE,
	TCLI_ESC_END,
	TCLI_ESC_PGUP,
	TCLI_ESC_PGDN
};

static const struct {
	unsigned char old_esc;
	char match;
	unsigned char new_esc;
} esc_code_table[] = {{TCLI_ESC_NONE, '[', TCLI_ESC_BRACKET},
					  {TCLI_ESC_BRACKET, '1', TCLI_ESC_HOME},
					  {TCLI_ESC_BRACKET, '2', TCLI_ESC_INSERT},
					  {TCLI_ESC_BRACKET, '3', TCLI_ESC_DELETE},
					  {TCLI_ESC_BRACKET, '4', TCLI_ESC_END},
					  {TCLI_ESC_BRACKET, '5', TCLI_ESC_PGUP},
					  {TCLI_ESC_BRACKET, '6', TCLI_ESC_PGDN},
					  {TCLI_ESC_BRACKET, '7', TCLI_ESC_HOME},
					  {TCLI_ESC_BRACKET, '8', TCLI_ESC_END}};

static const struct {
	unsigned char esc;
	char match;
	unsigned char op;
} esc_table[] = {
#if TCLI_HISTORY_BUF_LEN > 0
	{TCLI_ESC_BRACKET, 'A', TCLI_OP_HIST_PREV},
	{TCLI_ESC_BRACKET, 'B', TCLI_OP_HIST_NEXT},
	{TCLI_ESC_NONE, 'r', TCLI_OP_HIST_RESTORE},
#endif
	{TCLI_ESC_BRACKET, 'C', TCLI_OP_CURSOR_FORWARD_ONE},
	{TCLI_ESC_BRACKET, 'D', TCLI_OP_CURSOR_BACKWARD_ONE},
	{TCLI_ESC_DELETE, '~', TCLI_OP_DELETE_ONE},
	{TCLI_ESC_HOME, '~', TCLI_OP_CURSOR_BACKWARD_MAX},
	{TCLI_ESC_END, '~', TCLI_OP_CURSOR_FORWARD_MAX},
	{TCLI_ESC_NONE, 'b', TCLI_OP_CURSOR_BACKWARD_WORD},
	{TCLI_ESC_NONE, 'f', TCLI_OP_CURSOR_FORWARD_WORD},
	{TCLI_ESC_NONE, 'd', TCLI_OP_DELETE_WORD}};

#if TCLI_HISTORY_BUF_LEN > 0
typedef enum tcli_hist_mode {
	TCLI_HIST_PREV = 0,
	TCLI_HIST_NEXT,
	TCLI_HIST_SAME
} tcli_hist_it_t;

static inline void tcli_rb_scan_backwards(tcli_rb_t *const rb)
{
	TCLI_ASSERT_RB(rb);

	if (rb->pos == 0)
		rb->pos = TCLI_ARRAY_SIZE(rb->buf);

	rb->pos--;
}

static inline void tcli_rb_scan_forwards(tcli_rb_t *const rb)
{
	TCLI_ASSERT_RB(rb);

	rb->pos++;

	if (rb->pos >= TCLI_ARRAY_SIZE(rb->buf))
		rb->pos = 0;
}

static void tcli_rb_pop_first(tcli_rb_t *const rb)
{
	TCLI_ASSERT_RB(rb);

	bool end_found = false;
	size_t prev_head = rb->head;
	while (rb->count != 0) {

		if (rb->head == 0)
			rb->head = TCLI_ARRAY_SIZE(rb->buf);

		const char c = rb->buf[--rb->head];

		if (c == '\0') {
			if (!end_found)
				end_found = true;
			else {
				rb->head = prev_head;
				break;
			}
		}

		rb->count--;
		prev_head = rb->head;
	}

	rb->pos = rb->head;
}

static void tcli_rb_pop(tcli_rb_t *const rb)
{
	TCLI_ASSERT_RB(rb);

	while (rb->count != 0) {
		const char c = rb->buf[rb->tail++];

		if (rb->tail >= TCLI_ARRAY_SIZE(rb->buf))
			rb->tail = 0;

		rb->count--;

		if (c == '\0')
			break;
	}
}

static bool tcli_rb_peekcmp(tcli_rb_t *restrict const rb,
							const char *restrict str, size_t len)
{
	TCLI_ASSERT_RB(rb);
	assert(str);

	if (rb->count == 0 || rb->pos == rb->tail)
		return false;

	const size_t pos = rb->pos;

	tcli_rb_scan_backwards(rb);
	assert(rb->buf[rb->pos] == '\0');
	tcli_rb_scan_backwards(rb);

	size_t l = 0;
	while (rb->buf[rb->pos] != '\0') {
		l++;

		if (rb->pos == rb->tail)
			break;

		tcli_rb_scan_backwards(rb);
	}

	assert(l != 0);

	if (rb->pos != rb->tail)
		tcli_rb_scan_forwards(rb);

	bool match = l == len;
	if (match) {
		for (size_t i = 0; i < l; i++) {
			if (*str++ != rb->buf[rb->pos]) {
				match = false;
				break;
			}
			tcli_rb_scan_forwards(rb);
		}
	}

	rb->pos = pos;
	return match;
}

static bool tcli_rb_push(tcli_rb_t *restrict const rb, const char *restrict str,
						 size_t len, const bool move_pos)
{
	TCLI_ASSERT_RB(rb);
	assert(str);

	while (len > 0 && str[len - 1] == ' ')
		len--;

	if (len == 0 || len + 1 > TCLI_ARRAY_SIZE(rb->buf))
		return false;

	if (tcli_rb_peekcmp(rb, str, len))
		return true;

	while (rb->count + len + 1 > TCLI_ARRAY_SIZE(rb->buf))
		tcli_rb_pop(rb);

	const size_t end_len = TCLI_ARRAY_SIZE(rb->buf) - rb->head;

	if (len + 1 > end_len) {
		memcpy(&rb->buf[rb->head], str, end_len);
		memcpy(rb->buf, str + end_len, len - end_len);
		rb->head = len - end_len;
	} else {
		memcpy(&rb->buf[rb->head], str, len);
		rb->head += len;
	}

	// Reset scan position
	rb->buf[rb->head++] = '\0';
	rb->count += len + 1;

	if (move_pos)
		rb->pos = rb->head;

	return true;
}

static bool tcli_rb_previous(tcli_rb_t *restrict const rb, char *str,
							 size_t *restrict const len,
							 const char *const match_str,
							 const size_t match_len)
{
	TCLI_ASSERT_RB(rb);
	assert(str);
	assert(len);

SCAN:

	if (rb->count == 0 || rb->pos == rb->tail)
		return false;

	tcli_rb_scan_backwards(rb);
	assert(rb->buf[rb->pos] == '\0');
	tcli_rb_scan_backwards(rb);

	size_t l = 0;
	while (rb->buf[rb->pos] != '\0') {
		l++;

		if (rb->pos == rb->tail)
			break;

		tcli_rb_scan_backwards(rb);
	}

	assert(l != 0);

	if (rb->pos != rb->tail)
		tcli_rb_scan_forwards(rb);

	const size_t pos = rb->pos;
	if (match_str) {
		if (match_len == 0 || *match_str == '\0')
			return false;

		// Check if we match
		size_t matched = 0;
		const char *c = match_str;
		while (*c != '\0') {
			if (rb->buf[rb->pos] == '\0' || *c++ != rb->buf[rb->pos]) {
				rb->pos = pos;
				goto SCAN;
			}
			if (++matched == match_len)
				break;
			tcli_rb_scan_forwards(rb);
		}
		rb->pos = pos;
	}

	for (size_t i = 0; i < l; i++) {
		*str++ = rb->buf[rb->pos];
		tcli_rb_scan_forwards(rb);
	}
	rb->pos = pos;

	*str++ = '\0';
	*len = l;
	return true;
}

static bool tcli_rb_current(tcli_rb_t *restrict const rb, char *restrict str,
							size_t *restrict const len)
{
	TCLI_ASSERT_RB(rb);
	assert(str);
	assert(len);

	if (rb->count == 0 || rb->pos == rb->head)
		return false;

	const size_t pos = rb->pos;
	size_t l = 0;
	while (rb->buf[rb->pos] != '\0') {
		*str++ = rb->buf[rb->pos];
		l++;
		tcli_rb_scan_forwards(rb);
	}
	rb->pos = pos;

	assert(l != 0);

	*str++ = '\0';
	*len = l;
	return true;
}

static bool tcli_rb_next(tcli_rb_t *restrict const rb, char *restrict str,
						 size_t *restrict const len)
{
	TCLI_ASSERT_RB(rb);
	assert(str);
	assert(len);

	if (rb->count == 0 || rb->pos == rb->head)
		return false;

	while (rb->buf[rb->pos] != '\0')
		tcli_rb_scan_forwards(rb);

	assert(rb->buf[rb->pos] == '\0');
	tcli_rb_scan_forwards(rb);

	return tcli_rb_current(rb, str, len);
}
#endif

static int tcli_itoa(int n, char *const str)
{
	assert(str);

	n = n < -999 ? -999 : (n > 999 ? 999 : n);
	char tmp[4];
	int i = 0;

	if (n < 0)
		tmp[i++] = '-';

	while (n != 0) {
		tmp[i++] = (char)('0' + (n % 10));
		n /= 10;
	}

	int j = 0;
	while (j < i) {
		str[j] = tmp[i - j - 1];
		j++;
	}

	str[j] = '\0';
	return j;
}

static size_t tcli_tokenize(char *restrict str,
							const char *restrict *const tokens,
							const size_t max_tokens)
{
	assert(str);
	assert(tokens);

	size_t found_tokens = 0;

	while (found_tokens < max_tokens) {
		while (*str == ' ')
			str++;

		const char *start = str;

		if (*start == '\0')
			break;

		if (*start == '"' || *start == '\'') {
			str++;
			bool esc = false;
			while (*str != '\0' && (*str != *start || esc)) {
				esc = *str == '\\';
				str++;
			}
			start++;

			if (*start == '\0')
				break;
		} else {
			while (*str != '\0' && *str != ' ')
				str++;
		}

		char *const stop = str;

		tokens[found_tokens++] = start;

		if (*stop == '\0')
			break;

		*stop = '\0';
		str++;
	}

	return found_tokens;
}

static bool tcli_is_word_char(const char c)
{
	if (c >= '0' && c <= '9')
		return true;

	if (c >= 'a' && c <= 'z')
		return true;

	if (c >= 'A' && c <= 'Z')
		return true;

	return false;
}

void tcli_flush(tcli_t *const tcli)
{
#if TCLI_OUTPUT_BUF_LEN > 0
	if (!tcli)
		return;

	TCLI_ASSERT(tcli);
	TCLI_ASSERT_OUT_BUF(&tcli->out_buf);

	if (tcli->out_buf.len == 0)
		return;
	assert(tcli->out_buf.len < TCLI_ARRAY_SIZE(tcli->out_buf.buf));
	tcli->out_buf.buf[tcli->out_buf.len] = '\0';
	if (tcli->out)
		tcli->out(tcli->arg, tcli->out_buf.buf);
	tcli->out_buf.len = 0;
#endif
}

void tcli_out(tcli_t *const tcli, const char *str)
{
	if (!tcli || !str)
		return;

	TCLI_ASSERT(tcli);
	assert(str);

	if (!tcli->out)
		return;

#if TCLI_OUTPUT_BUF_LEN == 0
	tcli->out(tcli->arg, str);
#else
	TCLI_ASSERT_OUT_BUF(&tcli->out_buf);

	while (true) {
		while (tcli->out_buf.len + 1 < TCLI_ARRAY_SIZE(tcli->out_buf.buf)) {
			const char c = *str++;
			if (c == '\0')
				return;
			tcli->out_buf.buf[tcli->out_buf.len++] = c;
		}
		tcli_flush(tcli);
	}
#endif
}

int tcli_out_vprintf(tcli_t *restrict const tcli, char *restrict const buf,
					 size_t len, const char *restrict const format, va_list arg)
{
	if (!tcli || !buf || !format)
		return -1;

	if (len == 0)
		return 0;

	const int count = vsnprintf(buf, len, format, arg);
	tcli_out(tcli, buf);
	return count;
}

int tcli_out_printf(tcli_t *restrict const tcli, char *restrict const buf,
					size_t len, const char *restrict const format, ...)
{
	if (!tcli || !buf || !format)
		return -1;

	if (len == 0)
		return 0;

	va_list arg;
	va_start(arg, format);
	const int count = tcli_out_vprintf(tcli, buf, len, format, arg);
	va_end(arg);
	return count;
}

static void tcli_term_move_cursor(tcli_t *const tcli, int offset)
{
	TCLI_ASSERT(tcli);

	if (offset == 0)
		return;

	const char code = offset > 0 ? 'C' : 'D';

	if (offset < 0)
		offset = -offset;

	char str[7];
	char *c = str;
	*c++ = '\033';
	*c++ = '[';
	if (offset > 1)
		c += tcli_itoa(offset, c);
	*c++ = code;
	*c = '\0';

	assert(c - str <= sizeof(str));
	tcli_out(tcli, str);
}

static inline void tcli_term_clear(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\033[2J");
}

static inline void tcli_term_cursor_home(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\033[f");
}

static inline void tcli_term_return(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\r");
}

static inline void tcli_term_newline(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\r\n");
}

static inline void tcli_term_cut(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\033[K"); // Erase to end of line
}

static inline void tcli_term_return_cut(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_term_return(tcli);
	tcli_term_cut(tcli);
}

static inline void tcli_term_erase_all(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\033[2K"); // Erase to end of line
}

static inline void tcli_term_erase_line(tcli_t *const tcli)
{
	tcli_term_move_cursor(tcli, -(int)tcli->cmdline.cursor);
	tcli_term_cut(tcli);
}

static inline void tcli_term_save_cursor(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\033[s");
}

static inline void tcli_term_restore_cursor(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\033[u");
}

static inline void tcli_term_cursor_up(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\033[A");
}

static inline void tcli_term_cursor_down(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_out(tcli, "\033[B");
}

static void tcli_echo_out(tcli_t *const tcli, const size_t cursor)
{
	TCLI_ASSERT(tcli);

	if (tcli->echo.mode == TCLI_ECHO_ON) {
		tcli_out(tcli, tcli->cmdline.buf + cursor);
		return;
	}

	for (size_t i = cursor; i < tcli->cmdline.len; i++)
		tcli_out(tcli, "*");
}

static void tcli_term_print_from_cursor(tcli_t *const tcli,
										const bool save_cursor)
{
	TCLI_ASSERT(tcli);
	if (save_cursor)
		tcli_term_save_cursor(tcli);
	tcli_echo_out(tcli, tcli->cmdline.cursor);
	if (save_cursor)
		tcli_term_restore_cursor(tcli);
}

static inline void tcli_term_reprint_from_cursor(tcli_t *const tcli,
												 const bool save_cursor)
{
	TCLI_ASSERT(tcli);
	tcli_term_cut(tcli);
	tcli_term_print_from_cursor(tcli, save_cursor);
}

static void tcli_term_reprint_all(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);
	tcli_term_return_cut(tcli);

#if TCLI_HISTORY_BUF_LEN > 0
	if (tcli->hist.search)
		tcli_out(tcli, tcli->hist.search_prompt);
	else
#endif
	if (tcli->res != 0)
		tcli_out(tcli, tcli->error_prompt);
	else
		tcli_out(tcli, tcli->prompt);

	tcli_echo_out(tcli, 0);
	tcli_term_move_cursor(tcli,
						  (int)tcli->cmdline.cursor - (int)tcli->cmdline.len);
}

static size_t tcli_max_forward_len(const tcli_t *const tcli, const size_t len)
{
	TCLI_ASSERT(tcli);

	if (len == 0 || tcli->cmdline.cursor == tcli->cmdline.len)
		return 0;

	if (len > tcli->cmdline.len - tcli->cmdline.cursor)
		return tcli->cmdline.len - tcli->cmdline.cursor;

	return len;
}

static size_t tcli_max_backward_len(const tcli_t *const tcli, const size_t len)
{
	TCLI_ASSERT(tcli);

	if (len == 0 || tcli->cmdline.cursor == 0)
		return 0;

	if (len > tcli->cmdline.cursor)
		return tcli->cmdline.cursor;

	return len;
}

static void tcli_cursor_forward(tcli_t *const tcli, size_t len)
{
	TCLI_ASSERT(tcli);

	if ((len = tcli_max_forward_len(tcli, len)) == 0)
		return;

	tcli->cmdline.cursor += len;
	tcli_term_move_cursor(tcli, (int)len);
	tcli_flush(tcli);
}

static void tcli_cursor_backward(tcli_t *const tcli, size_t len)
{
	TCLI_ASSERT(tcli);

	if ((len = tcli_max_backward_len(tcli, len)) == 0)
		return;

	tcli->cmdline.cursor -= len;
	tcli_term_move_cursor(tcli, -(int)len);
	tcli_flush(tcli);
}

static size_t tcli_offset_next_word(const tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	const tcli_cmdline_t *const cmdline = &tcli->cmdline;
	size_t pos = cmdline->cursor;

	if (pos == cmdline->len)
		return 0;

	if (pos < cmdline->len && !tcli_is_word_char(cmdline->buf[pos]))
		pos++;

	while (pos < cmdline->len && cmdline->buf[pos] == ' ')
		pos++;

	while (pos < cmdline->len && tcli_is_word_char(cmdline->buf[pos]))
		pos++;

	return pos - cmdline->cursor;
}

static size_t tcli_offset_prev_word(const tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	const tcli_cmdline_t *const cmdline = &tcli->cmdline;
	size_t pos = cmdline->cursor;

	if (pos == 0)
		return 0;

	pos--;

	if (pos > 0 && !tcli_is_word_char(cmdline->buf[pos]))
		pos--;

	while (pos > 0 && cmdline->buf[pos] == ' ')
		pos--;

	while (pos > 0 && tcli_is_word_char(cmdline->buf[pos]))
		pos--;

	size_t offset = cmdline->cursor - pos;

	if (pos != 0 && offset != 0)
		offset--;

	return offset;
}

void tcli_clear_screen(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	if (!tcli)
		return;

	tcli_term_clear(tcli);
	tcli_term_cursor_home(tcli);
	tcli_term_reprint_all(tcli);
	tcli_flush(tcli);
}

static void tcli_insert(tcli_t *restrict const tcli,
						const char *restrict const str, size_t len)
{
	TCLI_ASSERT(tcli);
	assert(str);

	if (len == 0 || tcli->cmdline.len == TCLI_CMDLINE_MAX_LEN)
		return;

	if (len > TCLI_CMDLINE_MAX_LEN - tcli->cmdline.len)
		len = TCLI_CMDLINE_MAX_LEN - tcli->cmdline.len;

	// Shift all characters from cursor to len + 1
	memmove(tcli->cmdline.buf + tcli->cmdline.cursor + len,
			tcli->cmdline.buf + tcli->cmdline.cursor,
			tcli->cmdline.len - tcli->cmdline.cursor + 1);
	memcpy(tcli->cmdline.buf + tcli->cmdline.cursor, str, len);

	tcli->cmdline.len += len;
	tcli_term_print_from_cursor(tcli, false);
	tcli->cmdline.cursor += len;
	tcli_term_move_cursor(
		tcli,
		(int)tcli->cmdline.cursor -
			(int)tcli->cmdline.len); // Move cursor back len steps
	tcli_flush(tcli);
}

static void tcli_backspace(tcli_t *const tcli, size_t len)
{
	TCLI_ASSERT(tcli);

	if ((len = tcli_max_backward_len(tcli, len)) == 0)
		return;

	memmove(tcli->cmdline.buf + tcli->cmdline.cursor - len,
			tcli->cmdline.buf + tcli->cmdline.cursor,
			tcli->cmdline.len - tcli->cmdline.cursor + 1);

	tcli->cmdline.len -= len;
	tcli->cmdline.cursor -= len;
	tcli_term_move_cursor(tcli, -(int)len); // Move cursor back len steps
	tcli_term_reprint_from_cursor(tcli, true);
	tcli_flush(tcli);
}

static void tcli_delete(tcli_t *const tcli, size_t len)
{
	TCLI_ASSERT(tcli);

	if ((len = tcli_max_forward_len(tcli, len)) == 0)
		return;

	// Same as delete but offset
	memmove(tcli->cmdline.buf + tcli->cmdline.cursor,
			tcli->cmdline.buf + tcli->cmdline.cursor + len,
			tcli->cmdline.len - tcli->cmdline.cursor + 1);

	tcli->cmdline.len -= len;
	tcli_term_reprint_from_cursor(tcli, true);
	tcli_flush(tcli);
}

static inline void tcli_reset(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	tcli->cmdline.len = tcli->cmdline.cursor = 0;
	tcli->cmdline.buf[0] = '\0';
}

#if TCLI_HISTORY_BUF_LEN > 0
static inline void tcli_reset_hist(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	if (tcli->hist.has_line)
		tcli_rb_pop_first(&tcli->hist.rb);

	tcli->hist.rb.pos = tcli->hist.rb.head;
	tcli->hist.has_line = false;
	tcli->hist.offset = 0;
	tcli->hist.search = false;
}

static inline void tcli_reset_hist_mode(tcli_t *const tcli)
{
	if (tcli->hist.mode == TCLI_HIST_OFF_ONCE)
		tcli->hist.mode = TCLI_HIST_ON;
}
#endif

static inline void tcli_reset_echo_mode(tcli_t *const tcli)
{
	if (tcli->echo.mode == TCLI_ECHO_OFF_ONCE)
		tcli->echo.mode = TCLI_ECHO_ON;
}

#if TCLI_HISTORY_BUF_LEN > 0
static void tcli_clear(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	tcli_term_move_cursor(tcli, -(int)tcli->cmdline.cursor);
	tcli_term_cut(tcli);
	tcli_reset(tcli);
	tcli_flush(tcli);
}
#endif

static void tcli_clear_all(tcli_t *const tcli, const bool reset_modes)
{
	TCLI_ASSERT(tcli);

	tcli_term_return_cut(tcli);
	tcli_reset(tcli);
#if TCLI_HISTORY_BUF_LEN > 0
	tcli_reset_hist(tcli);
#endif
	if (reset_modes) {
#if TCLI_HISTORY_BUF_LEN > 0
		tcli_reset_hist_mode(tcli);
#endif
		tcli_reset_echo_mode(tcli);
	}
	tcli_term_reprint_all(tcli);
	tcli_flush(tcli);
}

static bool tcli_unescape(tcli_t *restrict const tcli, const char c,
						  unsigned char *restrict const op)
{
	TCLI_ASSERT(tcli);
	assert(op);

	if (c == TCLI_ESC)
		return (tcli->esc.esc = true);
	else if (!tcli->esc.esc)
		return false;

	for (size_t i = 0; i < TCLI_ARRAY_SIZE(esc_code_table); i++) {
		if (c != esc_code_table[i].match ||
			tcli->esc.code != esc_code_table[i].old_esc)
			continue;

		tcli->esc.code = esc_code_table[i].new_esc;
		return true;
	}

	for (size_t i = 0; i < TCLI_ARRAY_SIZE(esc_table); i++) {
		if (c != esc_table[i].match || tcli->esc.code != esc_table[i].esc)
			continue;

		*op = esc_table[i].op;
		break;
	}

	tcli->esc.code = TCLI_ESC_NONE;
	return (tcli->esc.esc = false);
}

static void tcli_exec(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	if (!tcli->exec)
		return;

	const char *tokens[TCLI_MAX_TOKENS] = {NULL};
	size_t count =
		tcli_tokenize(tcli->cmdline.buf, tokens, TCLI_ARRAY_SIZE(tokens));

	if (count != 0) {
		tcli->executing = true;
		tcli->res = tcli->exec(tcli->arg, (int)count, tokens);
		tcli->executing = false;
	}
}

static size_t tcli_str_match(const char *restrict a, const char *restrict b,
							 const size_t max_len)
{
	assert(a);
	assert(b);
	assert(a != b);

	size_t len = 0;
	while (len < max_len && a[len] != '\0' && b[len] != '\0' &&
		   a[len] == b[len])
		len++;

	return len;
}

static void tcli_complete(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	if (!tcli->complete.complete || tcli->echo.mode != TCLI_ECHO_ON ||
		tcli->cmdline.len == TCLI_CMDLINE_MAX_LEN)
		return;

	// Limit to current cursor
	const char old_cursor_char = tcli->cmdline.buf[tcli->cmdline.cursor];
	tcli->cmdline.buf[tcli->cmdline.cursor] = '\0';

	// Split tokens
	const char *tokens[TCLI_MAX_TOKENS] = {NULL};
	size_t count =
		tcli_tokenize(tcli->cmdline.buf, tokens, TCLI_ARRAY_SIZE(tokens));

	if (count == 0)
		return;

	// Get completions
	const char *compl_tokens[TCLI_MAX_TOKENS] = {NULL};
	size_t compl_count = 0;
	tcli->complete.complete(tcli->arg, (int)count, tokens, compl_tokens,
							TCLI_ARRAY_SIZE(compl_tokens), &compl_count);

	// Restore cursor
	tcli->cmdline.buf[tcli->cmdline.cursor] = old_cursor_char;

	// Restore splits
	for (size_t i = 0; i < tcli->cmdline.cursor; i++) {
		if (tcli->cmdline.buf[i] == '\0')
			tcli->cmdline.buf[i] = ' ';
	}

	if (compl_count == 0)
		return;

	size_t match_len = SIZE_MAX;
	const char *match = compl_tokens[0];
	assert(match);
	assert(*match != '\0');

	if (compl_count != 1) {
		// Multiple matches
		for (size_t i = 1; i < compl_count; i++) {
			assert(compl_tokens[i]);
			assert(*(compl_tokens[i]) != '\0');
			const size_t m = tcli_str_match(match, compl_tokens[i], match_len);
			if (m >= match_len)
				continue;
			match_len = m;
			if (m == 0)
				break;
		}
	}

	if (match_len != 0) {
		// Back up cursor
		int move = 0;
		while (tcli->cmdline.cursor > 0 &&
			   tcli->cmdline.buf[tcli->cmdline.cursor] != ' ') {
			if (tcli->cmdline.buf[tcli->cmdline.cursor - 1] == ' ')
				break;
			tcli->cmdline.cursor--;
			move--;
		}

		size_t cursor = tcli->cmdline.cursor;
		const char *c = match;
		while (cursor < TCLI_CMDLINE_MAX_LEN && *c != '\0' && match_len > 0) {
			tcli->cmdline.buf[cursor++] = *c++;
			match_len--;
		}

		if (compl_count == 1 && cursor < TCLI_CMDLINE_MAX_LEN)
			tcli->cmdline.buf[cursor++] = ' ';

		tcli->cmdline.len = cursor;
		tcli->cmdline.buf[tcli->cmdline.len] = '\0';
		tcli_term_move_cursor(tcli, move);
		tcli_term_reprint_from_cursor(tcli, false);
		tcli->cmdline.cursor = cursor;

		if (compl_count == 1) {
			tcli_flush(tcli);
			return;
		}
	}

	// Multiple completions => print below
	tcli->complete.active = true;
	tcli_term_save_cursor(tcli);
	tcli_term_newline(tcli);

	for (size_t i = 0; i < compl_count; i++) {
		assert(compl_tokens[i]);
		assert(*(compl_tokens[i]) != '\0');
		tcli_out(tcli, compl_tokens[i]);
		if (i + 1 < compl_count)
			tcli_out(tcli, " ");
	}

	tcli_term_cursor_up(tcli);
	tcli_term_restore_cursor(tcli);
	tcli_term_cursor_down(tcli);
	tcli_term_cursor_up(tcli);
	tcli_flush(tcli);
}

static void tcli_exit_compl(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	if (!tcli->complete.active)
		return;

	tcli->complete.active = false;
	tcli_term_cursor_down(tcli);
	tcli_term_erase_all(tcli);
	tcli_term_cursor_up(tcli);
	tcli_flush(tcli);
}

static bool tcli_newline(tcli_t *const tcli, const char c)
{
	TCLI_ASSERT(tcli);

	if (c != TCLI_CR && c != TCLI_LF) {
		tcli->last_endl = 0;
		return false;
	}

	tcli->last_endl = c;

	if (tcli->last_endl == (c == TCLI_CR ? TCLI_LF : TCLI_CR))
		return true;

#if TCLI_HISTORY_BUF_LEN > 0
	tcli_reset_hist(tcli);

	if (tcli->echo.mode == TCLI_ECHO_ON && tcli->hist.mode == TCLI_HIST_ON)
		tcli_rb_push(&tcli->hist.rb, tcli->cmdline.buf, tcli->cmdline.len,
					 true);
#endif

	tcli_term_newline(tcli);
	tcli_flush(tcli);
#if TCLI_HISTORY_BUF_LEN > 0
	tcli_reset_hist_mode(tcli);
#endif
	tcli_reset_echo_mode(tcli);
	tcli_exec(tcli);
	tcli_clear_all(tcli, false);
	return true;
}

static void tcli_insert_char(tcli_t *const tcli, const char c)
{
	TCLI_ASSERT(tcli);

	if (c <= 31 || c >= 127)
		return;

	if (tcli->cmdline.len == 0 && c == ' ')
		return;

	tcli_insert(tcli, &c, 1);
}

static void tcli_sigint(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	if (tcli->sigint)
		tcli->sigint(tcli->arg);

	tcli_clear_all(tcli, true);
}

#if TCLI_HISTORY_BUF_LEN > 0
static void tcli_hist_remove_line(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	if (tcli->hist.has_line && tcli->hist.offset == 0) {
		tcli_rb_pop_first(&tcli->hist.rb);
		tcli->hist.has_line = false;
	}
}

static void tcli_hist(tcli_t *const tcli, const tcli_hist_it_t mode)
{
	TCLI_ASSERT(tcli);
	assert(mode == TCLI_HIST_PREV || mode == TCLI_HIST_NEXT ||
		   mode == TCLI_HIST_SAME);

	if (tcli->echo.mode != TCLI_ECHO_ON)
		return;

	size_t len = 0;
	if (mode == TCLI_HIST_PREV) {
		if (tcli->hist.offset == 0)
			tcli->hist.has_line = tcli_rb_push(
				&tcli->hist.rb, tcli->cmdline.buf, tcli->cmdline.len, false);
		if (!tcli_rb_previous(&tcli->hist.rb, tcli->cmdline.buf, &len, NULL,
							  0)) {
			tcli_hist_remove_line(tcli);
			return;
		}
		tcli->hist.offset++;
	} else if (mode == TCLI_HIST_NEXT) {
		if (!tcli_rb_next(&tcli->hist.rb, tcli->cmdline.buf, &len)) {
			tcli_clear(tcli);
			tcli_reset_hist(tcli);
			return;
		}
		assert(tcli->hist.offset != 0);
		tcli->hist.offset--;
		tcli_hist_remove_line(tcli);
	} else {
		if (tcli->hist.offset == 0)
			return;
		if (!tcli_rb_current(&tcli->hist.rb, tcli->cmdline.buf, &len)) {
			tcli_clear(tcli);
			tcli_reset_hist(tcli);
			return;
		}
	}

	tcli_term_erase_line(tcli);
	tcli->cmdline.len = len;
	tcli->cmdline.cursor = len;
	tcli_echo_out(tcli, 0);
	tcli_flush(tcli);
}

static void tcli_hist_set_search_mode(tcli_t *const tcli, const bool search)
{
	TCLI_ASSERT(tcli);

	if (tcli->hist.search == search)
		return;

	if (tcli->echo.mode != TCLI_ECHO_ON && search)
		return;

	if (!search)
		tcli_reset_hist(tcli);

	tcli->hist.search = search;

	tcli_term_reprint_all(tcli);
	tcli_flush(tcli);
}

static void tcli_hist_search(tcli_t *const tcli)
{
	TCLI_ASSERT(tcli);

	if (!tcli->hist.search)
		return;

	if (tcli->echo.mode != TCLI_ECHO_ON) {
		tcli_hist_set_search_mode(tcli, false);
		return;
	}

	if (tcli->cmdline.len == 0)
		return;

	tcli_reset_hist(tcli);
	tcli->hist.search = true;

	if (tcli_rb_previous(&tcli->hist.rb, tcli->cmdline.buf, &tcli->cmdline.len,
						 tcli->cmdline.buf, tcli->cmdline.cursor)) {
		tcli_term_reprint_from_cursor(tcli, true);
		tcli_flush(tcli);
		return;
	}

	tcli_delete(tcli, TCLI_CMDLINE_MAX_LEN);
}
#endif

static void tcli_convert_op(const char c, unsigned char *const op)
{
	assert(op);

	for (size_t i = 0; i < TCLI_ARRAY_SIZE(ctrl_char_table); i++) {
		if (c == ctrl_char_table[i].match) {
			*op = ctrl_char_table[i].op;
			return;
		}
	}
}

void tcli_input_char(tcli_t *const tcli, char c)
{
	if (!tcli)
		return;

	TCLI_ASSERT(tcli);

	if (c == '\0')
		return;

	unsigned char op = TCLI_OP_NONE;

	tcli_exit_compl(tcli);

	if (tcli_unescape(tcli, c, &op) || tcli_newline(tcli, c))
		return;

	if (op == TCLI_OP_NONE)
		tcli_convert_op(c, &op);

	switch (op) {
	case TCLI_OP_NONE:
		tcli_insert_char(tcli, c);
		break;
	case TCLI_OP_BACKSPACE_ONE:
		tcli_backspace(tcli, 1);
		break;
	case TCLI_OP_DELETE_ONE:
		tcli_delete(tcli, 1);
		break;
	case TCLI_OP_BACKSPACE_MAX:
		tcli_backspace(tcli, TCLI_CMDLINE_MAX_LEN);
		break;
	case TCLI_OP_DELETE_MAX:
		tcli_delete(tcli, TCLI_CMDLINE_MAX_LEN);
		break;
	case TCLI_OP_BACKSPACE_WORD:
		tcli_backspace(tcli, tcli_offset_prev_word(tcli));
		break;
	case TCLI_OP_DELETE_WORD:
		tcli_delete(tcli, tcli_offset_next_word(tcli));
		break;
	case TCLI_OP_CURSOR_FORWARD_MAX:
		tcli_cursor_forward(tcli, TCLI_CMDLINE_MAX_LEN);
		break;
	case TCLI_OP_CURSOR_BACKWARD_MAX:
		tcli_cursor_backward(tcli, TCLI_CMDLINE_MAX_LEN);
		break;
	case TCLI_OP_CURSOR_FORWARD_ONE:
		tcli_cursor_forward(tcli, 1);
		break;
	case TCLI_OP_CURSOR_BACKWARD_ONE:
		tcli_cursor_backward(tcli, 1);
		break;
	case TCLI_OP_CURSOR_FORWARD_WORD:
		tcli_cursor_forward(tcli, tcli_offset_next_word(tcli));
		break;
	case TCLI_OP_CURSOR_BACKWARD_WORD:
		tcli_cursor_backward(tcli, tcli_offset_prev_word(tcli));
		break;
#if TCLI_HISTORY_BUF_LEN > 0
	case TCLI_OP_HIST_PREV:
		tcli_hist(tcli, TCLI_HIST_PREV);
		break;
	case TCLI_OP_HIST_NEXT:
		tcli_hist(tcli, TCLI_HIST_NEXT);
		break;
	case TCLI_OP_HIST_RESTORE:
		tcli_hist(tcli, TCLI_HIST_SAME);
		break;
	case TCLI_OP_HIST_MODE_TOGGLE:
		tcli_hist_set_search_mode(tcli, !tcli->hist.search);
		break;
	case TCLI_OP_HIST_MODE_OFF:
		tcli_hist_set_search_mode(tcli, false);
		break;
#endif
	case TCLI_OP_COMPLETE:
		tcli_complete(tcli);
		break;
	case TCLI_OP_CLEAR:
		tcli_clear_screen(tcli);
		break;
	case TCLI_OP_SIGINT:
		tcli_sigint(tcli);
		break;
	default:
		break;
	}

#if TCLI_HISTORY_BUF_LEN > 0
	tcli_hist_search(tcli);
#endif
}

void tcli_input_str(tcli_t *restrict const tcli, const char *restrict str)
{
	if (!tcli || !str)
		return;

	while (*str != '\0')
		tcli_input_char(tcli, *str++);
}

void tcli_input(tcli_t *restrict const tcli, const void *restrict const buf,
				size_t len)
{
	if (!tcli || !buf)
		return;

	const char *str = buf;
	while (len != 0) {
		tcli_input_char(tcli, *str++);
		len--;
	}
}

void tcli_set_echo(tcli_t *restrict const tcli, const tcli_echo_mode_t mode)
{
	if (!tcli || mode < TCLI_ECHO_ON || mode > TCLI_ECHO_OFF_ONCE)
		return;

	tcli->echo.mode = mode;
}

#if TCLI_HISTORY_BUF_LEN > 0
void tcli_set_hist(tcli_t *restrict const tcli, const tcli_history_mode_t mode)
{
	if (!tcli || mode < TCLI_HIST_ON || mode > TCLI_HIST_OFF_ONCE)
		return;

	tcli->hist.mode = mode;
}
#endif

void tcli_set_out(tcli_t *const tcli, tcli_out_fn_t out)
{
	if (!tcli)
		return;

	tcli->out = out;
}

void tcli_set_exec(tcli_t *const tcli, tcli_exec_fn_t exec)
{
	if (!tcli)
		return;

	tcli->exec = exec;
}

void tcli_set_complete(tcli_t *const tcli, tcli_compl_fn_t complete)
{
	if (!tcli)
		return;

	tcli->complete.complete = complete;
}

void tcli_set_sigint(tcli_t *const tcli, tcli_sigint_fn_t sigint)
{
	if (!tcli)
		return;

	tcli->sigint = sigint;
}

void tcli_set_arg(tcli_t *const tcli, void *const arg)
{
	if (!tcli)
		return;

	tcli->arg = arg;
}

void tcli_set_prompt(tcli_t *restrict const tcli,
					 const char *restrict const prompt)
{
	if (!tcli)
		return;

	tcli->prompt = prompt ? prompt : TCLI_DEFAULT_PROMPT;
	tcli_term_reprint_all(tcli);
	tcli_flush(tcli);
}

void tcli_set_error_prompt(tcli_t *restrict const tcli,
						   const char *restrict const error_prompt)
{
	if (!tcli)
		return;

	tcli->error_prompt =
		error_prompt ? error_prompt : TCLI_DEFAULT_ERROR_PROMPT;
	tcli_term_reprint_all(tcli);
	tcli_flush(tcli);
}

#if TCLI_HISTORY_BUF_LEN > 0
void tcli_set_search_prompt(tcli_t *restrict const tcli,
							const char *restrict const search_prompt)
{
	if (!tcli)
		return;

	tcli->hist.search_prompt =
		search_prompt ? search_prompt : TCLI_DEFAULT_SEARCH_PROMPT;
	tcli_term_reprint_all(tcli);
	tcli_flush(tcli);
}
#endif

void tcli_init(tcli_t *restrict const tcli, tcli_out_fn_t out, void *const arg)
{
	if (!tcli)
		return;

	memset(tcli, 0, sizeof(tcli_t));

	tcli_set_out(tcli, out);
	tcli_set_exec(tcli, NULL);
	tcli_set_sigint(tcli, NULL);
	tcli_set_arg(tcli, arg);
	tcli_set_prompt(tcli, NULL);
	tcli_set_error_prompt(tcli, NULL);
#if TCLI_HISTORY_BUF_LEN > 0
	tcli_set_search_prompt(tcli, NULL);
#endif
}

void tcli_log(tcli_t *restrict const tcli, const char *restrict str)
{
	if (!tcli || !str)
		return;

	if (tcli->executing) {
		tcli_out(tcli, str);
		tcli_flush(tcli);
		return;
	}

	tcli_term_return_cut(tcli);
	tcli_out(tcli, str);
	tcli_term_reprint_all(tcli);

	if (tcli->complete.active)
		tcli_complete(tcli);

	tcli_flush(tcli);
}

int tcli_log_vprintf(tcli_t *restrict const tcli, char *restrict const buf,
					 size_t len, const char *restrict const format, va_list arg)
{
	if (!tcli || !buf || !format)
		return -1;

	if (len == 0)
		return 0;

	const int count = vsnprintf(buf, len, format, arg);
	tcli_log(tcli, buf);
	return count;
}

int tcli_log_printf(tcli_t *restrict const tcli, char *restrict const buf,
					size_t len, const char *restrict const format, ...)
{
	if (!tcli || !buf || !format)
		return -1;

	if (len == 0)
		return 0;

	va_list arg;
	va_start(arg, format);
	const int count = tcli_log_vprintf(tcli, buf, len, format, arg);
	va_end(arg);
	return count;
}
