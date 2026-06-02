+++
title = "Logging and Output"
description = "Printing without disturbing the current prompt; output buffering"
weight = 40
+++

A common situation in embedded systems is that the user is at a prompt, partway through typing a command, when a background task needs to print a message. A direct call to `printf` would write the message on top of the prompt and the partially-typed input, mangling the display. The TinyCLI log functions avoid this by redrawing the prompt and the in-progress input around the emitted log line.

## Log Functions

[`tcli`](@/tcli.md) and [`tclie`](@/tclie.md) both expose the same set of functions, with the corresponding prefix:

```c
tclie_log(&t, "Battery low\r\n");
tclie_log_printf(&t, buf, sizeof(buf), "Temperature: %d C\r\n", temp);
tclie_log_vprintf(&t, buf, sizeof(buf), fmt, va);   /* va_list variant */
```

The `buf` buffer is provided by the caller and is used for formatting (TinyCLI does not allocate). The buffer should be sized for the longest expected formatted line. Output longer than `len` is truncated, and the return value is the would-be length (matching the C99 `vsnprintf` convention). Truncation can therefore be detected by comparing the return value against `len`.

## Prompt-Preserving Redraw

Internally a log call performs the following sequence:

1. A carriage return and erase-line sequence is sent, clearing whatever is currently displayed on the prompt line.
2. The log line is emitted.
3. The prompt and the in-progress input are reprinted, with the cursor restored to its previous position.

The user sees the log line appear above the input line, which is otherwise unchanged. No interaction is required, and no flicker beyond the redraw itself is visible.

The redraw also covers tab-completion and reverse-search overlays when either mode is active.

## `tcli_out` and `tcli_log`

| Function       | Intended use                                                         |
|----------------|-----------------------------------------------------------------|
| `tcli_out`     | Output produced *as part of executing a command*, e.g. `help`, command results, or error messages emitted from a callback. The prompt is not on screen at this point. |
| `tcli_log`     | Output produced *outside* command execution, e.g. sensor readings or alerts emitted from a background context. The prompt may be visible and partially typed. |

Calling `tcli_log` while a command is running is harmless but slightly slower than `tcli_out` (an additional erase-line round trip is performed). Calling `tcli_out` from a background context will overwrite the user's input, and `tcli_log` should be used in that situation instead.

## Output Buffering

When [`TCLI_OUTPUT_BUF_LEN`](@/configuration.md#output-buffering) is non-zero (default 256), `tcli_out` accumulates writes in a buffer and flushes them in chunks. This is relevant when each call to the output callback is expensive, e.g. when each call invokes a UART driver that performs a context switch, or when each call results in a separate packet being sent.

```c
tcli_out(&t, "line 1\r\n");      /* may not appear yet */
tcli_out(&t, "line 2\r\n");
tcli_flush(&t);                  /* both lines are now sent */
```

The library flushes the output buffer automatically when necessary. Explicit `tcli_flush` calls are only needed when buffered output must leave the buffer mid-command, e.g. before a long sleep.

Setting `TCLI_OUTPUT_BUF_LEN = 0` at compile time disables buffering entirely; every byte is then forwarded to the callback immediately.

## Formatted Output from Callbacks

The same `printf`-style helpers are available for use from inside command callbacks:

```c
int cmd_status(void *arg, int argc, const char **argv)
{
    tclie_t *t = arg;
    char buf[64];
    tclie_out_printf(t, buf, sizeof(buf), "Uptime: %lu s\r\n", uptime);
    return 0;
}
```

These go through the buffered path (where applicable) and follow the same `len`-based truncation contract as the log variants.
