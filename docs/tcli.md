+++
title = "The tcli Core"
description = "Lower-level interface"
weight = 15
+++

`tcli` is the lower-level layer and is intended to be used directly when a registered command table is not desired, e.g. when implementing a custom dispatch that interprets each typed line. The wrapper [`tclie`](@/tclie.md) is built entirely on top of `tcli`, and everything described on this page applies to both.

The canonical declarations live in [`include/tcli.h`](https://github.com/dpse/tcli/blob/master/include/tcli.h).

## Lifecycle

A `tcli_t` instance is opaque storage provided by the caller (stack or static). It is initialized once, an executor callback is registered, and characters are then fed in as they arrive.

```c
#include "tcli.h"

void out(void *arg, const char *str)
{
    /* … */
}

int exec(void *arg, int argc, const char **argv)
{
    /* … */
    return 0;
}

tcli_t t;
tcli_init(&t, out, NULL);          /* zeroes state, sets defaults */
tcli_set_exec(&t, exec);           /* called when the user presses Enter */
```

The `tcli_t` instance fields are managed internally and should not be accessed directly. The third argument to `tcli_init` is an opaque user pointer passed unchanged to every callback (`out`, `exec`, completion, SIGINT); it can be changed later with `tcli_set_arg`. The output and executor callbacks can likewise be replaced at runtime with `tcli_set_out` and `tcli_set_exec`.

## Input

Three input variants are provided:

```c
tcli_in_char(&t, c);                       /* one byte */
tcli_in_str(&t, "command\r\n");            /* null-terminated */
tcli_in(&t, buf, len);                     /* arbitrary buffer */
```

All three are equivalent. The library only acts on byte boundaries; no caller-side buffering is required.

## Output

The output callback registered through `tcli_init` (or later via `tcli_set_out`) receives every byte emitted by the library: the prompt, echoed user input, command output produced via `tcli_out` and `tcli_out_printf`, and any ANSI escape sequences. Output may be buffered (see [Logging and Output](@/logging.md)) and can be manually flushed using `tcli_flush`.

```c
tcli_out(&t, "Hello\n");
tcli_out_printf(&t, buf, sizeof(buf), "value = %d\n", x);
tcli_out_vprintf(&t, buf, sizeof(buf), fmt, va);   /* va_list variant */
tcli_flush(&t);
```

The `buf` and `len` arguments to the printf-style functions are for a caller-provided scratch space and are required as TinyCLI does not allocate internally. `tcli_out_printf` and `tcli_out_vprintf` return the would-be length, following the C99 `vsnprintf` convention, so truncation can be detected by comparing the return value against `len`.

## Echo Modes

Each typed character is echoed back to the output callback by default (`TCLI_ECHO_ON`). The two off modes do not silence the echo: each input character is echoed as a `*` instead of the character itself, so the input is masked rather than hidden entirely.

```c
tcli_set_echo(&t, TCLI_ECHO_OFF);          /* persistent: input echoed as `*` */
tcli_set_echo(&t, TCLI_ECHO_OFF_ONCE);     /* mask once, then revert to TCLI_ECHO_ON after the next Enter */
tcli_set_echo(&t, TCLI_ECHO_ON);           /* default: echo verbatim */
```

The `tclie` built-in `login` command sets `TCLI_ECHO_OFF_ONCE` for the password line, so the password is echoed as `*` characters and normal echo resumes automatically once it has been submitted.

## Prompts

The different prompts can be configured:

```c
tcli_set_prompt(&t, "device> ");
tcli_set_error_prompt(&t, "device! ");    /* shown when the previous exec returned non-zero */
tcli_set_search_prompt(&t, "(reverse-i-search) ");
```

The defaults wrap the prompt strings in ANSI color escapes (green, red, and green respectively). To retain the default colors but change the prompt text, see the [Default Prompts](@/configuration.md#default-prompts) section.

## Command History

{{ <kbd key="Up" /> }}/{{ <kbd key="Down" /> }} recalls earlier lines and {{ <kbd key="Ctrl+r" /> }} enters reverse search. The feature is enabled when [`TCLI_HISTORY_BUF_LEN`](@/configuration.md#history) is non-zero at compile time (default 512 bytes).

```c
tcli_set_hist(&t, TCLI_HIST_OFF);          /* do not record any new lines */
tcli_set_hist(&t, TCLI_HIST_OFF_ONCE);     /* skip recording the next line; useful for sensitive input */
tcli_set_hist(&t, TCLI_HIST_ON);
```

The history is stored in a ring buffer. Old lines are evicted as the buffer fills.

## Tab-Completion

When [`TCLI_COMPLETE`](@/configuration.md#tab-completion) is set to `1` (enabled by default), pressing {{ <kbd key="Tab" /> }} invokes the registered completion function. If multiple matches are returned, subsequent {{ <kbd key="Tab" /> }} presses cycle through them.

```c
size_t complete(void *arg, int argc, const char **argv,
                const char *match, const char **completions, size_t max_count)
{
    /* Up to max_count completion strings are returned in completions.
       The caller retains ownership; the strings must remain valid until
       the user has made a selection. */
    if (argc == 1 && match[0] == 'r') {
        completions[0] = "reboot";
        completions[1] = "reset";
        return 2;
    }
    return 0;
}

tcli_set_complete(&t, complete);
```

A completion function is provided automatically by the `tclie` pattern-matching system when patterns are set on registered commands (see [Pattern Matching](@/pattern-matching.md)).

## SIGINT Handling

```c
tcli_set_sigint(&t, my_sigint);
```

The registered handler is invoked when the user presses {{ <kbd key="Ctrl+c" /> }}. Without a handler the default behavior is to abort the current line and reprint the prompt.

> [!NOTE]
> Pressing {{ <kbd key="Ctrl+c" /> }} will not abort any currently executing command! The handler will be invoked once the command has returned.

## Screen Clearing

```c
tcli_clear_screen(&t);
```

Sends the ANSI clear sequence and reprints the prompt. Bound to {{ <kbd key="Ctrl+l" /> }} automatically.
