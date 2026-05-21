+++
title = "Configuration"
description = "Compile-time #defines and the bundled ANSI macros"
weight = 60
+++

All tuning is performed via compile-time `#define`s; no runtime configuration is provided. A default can be overridden by defining the corresponding macro before including the header, or by passing `-D...` to the compiler.

## Line Buffer and Tokens

| Macro                  | Default | Effect |
|------------------------|---------|--------|
| `TCLI_CMDLINE_MAX_LEN` | `64`    | Maximum number of characters that fit on the command line (excluding the null terminator). The full buffer is embedded in `tcli_t`, so this value directly affects the struct size. |
| `TCLI_MAX_TOKENS`      | `12`    | Maximum number of whitespace-separated tokens produced by the tokenizer. Lines with more tokens are rejected before the executor is invoked. |

## History

| Macro                 | Default | Effect |
|-----------------------|---------|--------|
| `TCLI_HISTORY_BUF_LEN`| `512`   | Size of the ring buffer that stores history lines. Setting it to `0` compiles history out entirely: no {{ kbd(key="Up") }}/{{ kbd(key="Down") }}, no {{ kbd(key="Ctrl+r") }}, smaller `tcli_t`. |

## Output Buffering

| Macro                 | Default | Effect |
|-----------------------|---------|--------|
| `TCLI_OUTPUT_BUF_LEN` | `256`   | Size of the buffer used to coalesce `tcli_out` writes before they reach the output callback. Setting it to `0` disables buffering; every byte is forwarded to the callback immediately. |

## Tab-Completion

| Macro           | Default | Effect |
|-----------------|---------|--------|
| `TCLI_COMPLETE` | `1`     | Setting to `0` compiles out tab-completion entirely (smaller binary, `tcli_compl_fn_t` removed). |

## Default Prompts

Each prompt is a string. The defaults wrap the visible text in ANSI color escapes; the same form can be used in custom prompts to retain coloring.

| Macro | Default | Rendered |
|---|---|---|
| `TCLI_DEFAULT_PROMPT`        | `(TCLI_COLOR_GREEN "> " TCLI_COLOR_DEFAULT)` | <code style="background:#000000;color:#00bb00">&gt;&nbsp;</code> |
| `TCLI_DEFAULT_ERROR_PROMPT`  | `(TCLI_COLOR_RED "> " TCLI_COLOR_DEFAULT)`   | <code style="background:#000000;color:#bb0000">&gt;&nbsp;</code> |
| `TCLI_DEFAULT_SEARCH_PROMPT` | `(TCLI_COLOR_GREEN "? " TCLI_COLOR_DEFAULT)` | <code style="background:#000000;color:#00bb00">?&nbsp;</code> |

These are the starting values. The prompts can also be overridden at runtime via [`tcli_set_prompt`](@/tcli.md#prompts) and the corresponding setters.

## `tclie`-Specific

| Macro                          | Default | Effect |
|--------------------------------|---------|--------|
| `TCLIE_ENABLE_USERS`           | `1`     | Compiles in users and login. Set to `0` for command-only CLIs. |
| `TCLIE_ENABLE_USERNAMES`       | `1`     | Enables usernames in addition to passwords. Set to `0` for password-only login (matched against any user). |
| `TCLIE_LOGIN_ATTEMPTS`         | `3`     | Number of incorrect password attempts before the login is rejected. |
| `TCLIE_PATTERN_MATCH`          | `1`     | Compiles in [pattern matching](@/pattern-matching.md). Set to `0` to reduce footprint when not used. |
| `TCLIE_PATTERN_MATCH_MAX_TOKENS` | `TCLI_MAX_TOKENS` | Maximum number of tokens considered during pattern matching. More tokens require a deeper stack depth. |
| `TCLIE_PATTERN_MATCH_BUF_LEN`  | `64`    | Scratch buffer used for pattern-derived tab-completion candidates. |

## ANSI Color and Format Macros

A set of ANSI escape constants is provided for use in prompts and command output. They are referenced by name; the samples below show how each renders in a terminal.

### Foreground Colors

| Macro | Sample |
|---|---|
| `TCLI_COLOR_BLACK` | <code style="background:#000000;color:#000000">Sample</code> |
| `TCLI_COLOR_RED` | <code style="background:#000000;color:#bb0000">Sample</code> |
| `TCLI_COLOR_GREEN` | <code style="background:#000000;color:#00bb00">Sample</code> |
| `TCLI_COLOR_YELLOW` | <code style="background:#000000;color:#bbbb00">Sample</code> |
| `TCLI_COLOR_BLUE` | <code style="background:#000000;color:#0000bb">Sample</code> |
| `TCLI_COLOR_MAGENTA` | <code style="background:#000000;color:#bb00bb">Sample</code> |
| `TCLI_COLOR_CYAN` | <code style="background:#000000;color:#00bbbb">Sample</code> |
| `TCLI_COLOR_WHITE` | <code style="background:#000000;color:#bbbbbb">Sample</code> |
| `TCLI_COLOR_BRIGHT_BLACK` | <code style="background:#000000;color:#555555">Sample</code> |
| `TCLI_COLOR_BRIGHT_RED` | <code style="background:#000000;color:#ff5555">Sample</code> |
| `TCLI_COLOR_BRIGHT_GREEN` | <code style="background:#000000;color:#55ff55">Sample</code> |
| `TCLI_COLOR_BRIGHT_YELLOW` | <code style="background:#000000;color:#ffff55">Sample</code> |
| `TCLI_COLOR_BRIGHT_BLUE` | <code style="background:#000000;color:#5555ff">Sample</code> |
| `TCLI_COLOR_BRIGHT_MAGENTA` | <code style="background:#000000;color:#ff55ff">Sample</code> |
| `TCLI_COLOR_BRIGHT_CYAN` | <code style="background:#000000;color:#55ffff">Sample</code> |
| `TCLI_COLOR_BRIGHT_WHITE` | <code style="background:#000000;color:#ffffff">Sample</code> |
| `TCLI_COLOR_DEFAULT` | Restores the terminal's default foreground color. |

### Background Colors

| Macro | Sample |
|---|---|
| `TCLI_BG_COLOR_BLACK` | <code style="background:#000000;color:#bbbbbb">Sample</code> |
| `TCLI_BG_COLOR_RED` | <code style="background:#bb0000;color:#ffffff">Sample</code> |
| `TCLI_BG_COLOR_GREEN` | <code style="background:#00bb00;color:#ffffff">Sample</code> |
| `TCLI_BG_COLOR_YELLOW` | <code style="background:#bbbb00;color:#000000">Sample</code> |
| `TCLI_BG_COLOR_BLUE` | <code style="background:#0000bb;color:#ffffff">Sample</code> |
| `TCLI_BG_COLOR_MAGENTA` | <code style="background:#bb00bb;color:#ffffff">Sample</code> |
| `TCLI_BG_COLOR_CYAN` | <code style="background:#00bbbb;color:#000000">Sample</code> |
| `TCLI_BG_COLOR_WHITE` | <code style="background:#bbbbbb;color:#000000">Sample</code> |
| `TCLI_BG_COLOR_DEFAULT` | Restores the terminal's default background color. |

### Text Formatting

| Macro | Sample |
|---|---|
| `TCLI_FORMAT_BOLD` | <code style="background:#000000;color:#bbbbbb;font-weight:700">Sample</code> |
| `TCLI_FORMAT_DIM` | <code style="background:#000000;color:#bbbbbb;opacity:0.55">Sample</code> |
| `TCLI_FORMAT_ITALIC` | <code style="background:#000000;color:#bbbbbb;font-style:italic">Sample</code> |
| `TCLI_FORMAT_UNDERLINE` | <code style="background:#000000;color:#bbbbbb;text-decoration:underline">Sample</code> |
| `TCLI_FORMAT_RESET` | Clears all color and formatting. |

### Combinations

Format and color macros concatenate; any number can be combined.

| Macros | Sample |
|---|---|
| `TCLI_FORMAT_BOLD TCLI_COLOR_RED` | <code style="background:#000000;color:#bb0000;font-weight:700">Sample</code> |
| `TCLI_FORMAT_BOLD TCLI_FORMAT_UNDERLINE TCLI_COLOR_CYAN` | <code style="background:#000000;color:#00bbbb;font-weight:700;text-decoration:underline">Sample</code> |
| `TCLI_FORMAT_ITALIC TCLI_COLOR_GREEN` | <code style="background:#000000;color:#00bb00;font-style:italic">Sample</code> |
| `TCLI_FORMAT_DIM TCLI_COLOR_YELLOW` | <code style="background:#000000;color:#bbbb00;opacity:0.55">Sample</code> |
| `TCLI_BG_COLOR_BLUE TCLI_COLOR_BRIGHT_WHITE` | <code style="background:#0000bb;color:#ffffff">Sample</code> |
| `TCLI_FORMAT_BOLD TCLI_BG_COLOR_WHITE TCLI_COLOR_RED` | <code style="background:#bbbbbb;color:#bb0000;font-weight:700">Sample</code> |

The constants concatenate at compile time and can be composed directly into a single string literal:

```c
#define TCLI_DEFAULT_PROMPT \
    (TCLI_FORMAT_BOLD TCLI_COLOR_CYAN "device> " TCLI_FORMAT_RESET)
```

The format macros used by `tclie` and the `help` command are also overridable:

| Macro | Default | Rendered |
|---|---|---|
| `TCLIE_SUCCESS_FORMAT` | `TCLI_COLOR_GREEN` | <code style="background:#000000;color:#00bb00">Sample</code> |
| `TCLIE_FAILURE_FORMAT` | `TCLI_COLOR_RED` | <code style="background:#000000;color:#bb0000">Sample</code> |
| `TCLIE_COMMAND_FORMAT` | `(TCLI_FORMAT_BOLD TCLI_FORMAT_UNDERLINE TCLI_COLOR_CYAN)` | <code style="background:#000000;color:#00bbbb;font-weight:700;text-decoration:underline">Sample</code> |
| `TCLIE_USAGE_FORMAT`   | `TCLI_COLOR_CYAN` | <code style="background:#000000;color:#00bbbb">Sample</code> |
| `TCLIE_OPTION_FORMAT`  | `(TCLI_FORMAT_ITALIC TCLI_COLOR_CYAN)` | <code style="background:#000000;color:#00bbbb;font-style:italic">Sample</code> |

Setting any of these to an empty string removes the corresponding color or formatting from the help output, e.g. for log capture or terminals that do not render escape sequences.

The tab-completion display has two further format macros:

| Macro | Default | Rendered | Effect |
|---|---|---|---|
| `TCLI_MATCH_FORMAT`     | `TCLI_COLOR_BRIGHT_BLACK`                | <code style="background:#000000;color:#555555">Sample</code> | Format of the common-prefix match hint shown while completing. |
| `TCLI_SELECTION_FORMAT` | `(TCLI_BG_COLOR_WHITE TCLI_COLOR_BLACK)` | <code style="background:#bbbbbb;color:#000000">Sample</code> | Format of the currently-selected candidate when cycling through matches. |

## Version

The library version is available at compile time through macros defined in `tcli.h`: `TCLI_VERSION_MAJOR`, `TCLI_VERSION_MINOR`, `TCLI_VERSION_PATCH`, and `TCLI_VERSION_STR`.
