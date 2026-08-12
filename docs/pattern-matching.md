+++
title = "Pattern Matching"
description = "Argument validation and context-aware tab-completion via patterns"
weight = 30
+++

A pattern describes the expected shape of a command's arguments: required tokens, optional tokens, alternatives, and wildcards. Patterns are used by the library to reject malformed invocations before the callback is invoked, and to drive tab-completion at the current cursor position.

Patterns are opt-in at compile time via [`TCLIE_PATTERN_MATCH`](@/configuration.md#tclie-specific) (enabled by default). Each entry in the command table may carry a pattern in its `pattern` field. Without a pattern, the command name is used for tab-completion.

## Syntax

A pattern is a whitespace-separated list of tokens. The recognized forms are:

| Pattern             | Matches                                  |
|---------------------|------------------------------------------|
| `abc`               | The literal word `abc`.                  |
| `"a b"` or `'a b'`  | The literal `a b`, including the space. |
| `[abc]`             | `abc`, optionally.                       |
| `a\|b\|cd`          | One of `a`, `b`, or `cd`.                |
| `<name>`            | Any single word.                         |
| `[<name>]`          | Any single word, optionally.             |
| `a\|(b c)`          | Either `a` or the two words `b c`.       |
| `...`               | None or all remaining tokens.            |

Patterns operate on whole word-tokens: matching inside a word is not supported. The matcher is recursive, and stack usage scales with pattern complexity. Patterns with many alternations and nested groups should therefore be kept moderate on small devices.

## Examples

A `set` command that takes a key and a value:

```c
{ .name = "set", .fn = cmd_set, .desc = "Set a value",
  .pattern = "set <key> <value>" }
```

The pattern does not need to match the name:

```c
{ .name = "set", .fn = cmd_set, .desc = "Set a value",
  .pattern = "<key> = <value>" }
```

A `power` command with explicit alternatives:

```c
{ .name = "power", .fn = cmd_power, .desc = "Toggle power",
  .pattern = "power on|off" }
```

A `connect` command where the port is optional:

```c
{ .name = "connect", .fn = cmd_connect, .desc = "Connect to host",
  .pattern = "connect <host> [<port>]" }
```

A `log` command that accepts any tail:

```c
{ .name = "log", .fn = cmd_log, .desc = "Print a message",
  .pattern = "log ..." }
```

## Validation and Completion

When the typed arguments do not match the pattern, the callback is not invoked. A usage hint is printed instead and the prompt switches to the error variant. The hint is the pattern itself, formatted with [`TCLIE_USAGE_FORMAT`](@/configuration.md#ansi-color-and-format-macros).

When {{ <kbd key="Tab" /> }} is pressed mid-token, the matcher determines what is expected at the current position and offers it as a completion candidate. For literal alternations the candidates are the alternations themselves (e.g. `on` and `off`). For `<wildcard>` tokens no candidates are offered, and the user types freely.

## Options

The `pattern` field can be combined with an options table. Options are documented separately in the output of `help <command>`.

```c
static const tclie_cmd_opt_t set_opts[] = {
    { .short_opt = 'f', .long_opt = "force",   .desc = "Skip confirmation" },
    { .short_opt = 'v', .long_opt = "verbose", .desc = "Print extra detail" },
};

static const tclie_cmd_t cmds[] = {
    { .name = "set", .fn = cmd_set, .desc = "Set a value",
      .pattern = "set <key> <value>",
      .options = { .option = set_opts, .count = sizeof(set_opts) / sizeof(*set_opts) } },
};
```

When an options table is set, the options are also completed automatically. At an option position, pressing {{ <kbd key="Tab" /> }} offers each option in both its short form (`-f`) and long form (`--force`).

Short options may be combined behind a single `-`: `-fv` is equivalent to `-f -v`. Each character is matched against the registered short options in turn. Long options are matched individually and are not combined. If any character in a combined group is not a registered short option, the whole token is left to be matched as an ordinary argument rather than as options.

### Option Fields and Arguments

A `tclie_cmd_opt_t` has four fields:

| Field       | Description |
|-------------|-------------|
| `short_opt` | Single-character short form, e.g. `'f'` for `-f`. Set to `0` for no short form. |
| `long_opt`  | Long form without the leading dashes, e.g. `"force"` for `--force`. Set to `NULL` for no long form. |
| `desc`      | One-line description shown by `help`. |
| `pattern`   | Argument sub-pattern for the option, or `NULL` for a flag that takes no argument. |

When `pattern` is set, the option takes an argument and the sub-pattern is matched immediately after the option, using the same syntax as command patterns: `<arg>` for a required value, `[<arg>]` for an optional value, or a literal/alternation.

```c
static const tclie_cmd_opt_t set_opts[] = {
    { .short_opt = 'f', .long_opt = "force",   .desc = "Skip confirmation" },
    { .short_opt = 'v', .long_opt = "verbose", .desc = "Print extra detail" },
    { .short_opt = 'r', .long_opt = "retries", .desc = "Retry count",  .pattern = "<n>" },
    { .short_opt = 'o', .long_opt = "out",     .desc = "Output file",  .pattern = "[<file>]" },
};
```

`help <command>` prints each option together with its argument pattern, e.g. `-r|--retries <n>`.

## Configuration

Pattern matching can be configured by the following compile-time parameters in `tclie.h` (see [Configuration](@/configuration.md#tclie-specific)):

- `TCLIE_PATTERN_MATCH_MAX_TOKENS`: upper bound on the number of tokens considered during matching. Defaults to `TCLI_MAX_TOKENS` (12).
- `TCLIE_PATTERN_MATCH_BUF_LEN`: scratch buffer size for pattern-derived tab-completion matches (default 64).

Both are static buffers; the limits can be raised when required without introducing allocation.

## Disabling

Setting `TCLIE_PATTERN_MATCH = 0` compiles the matcher out entirely. The `pattern` and `options` fields on registered commands are then ignored at runtime, and `help` falls back to listing the `desc` field only. This reduces the compiled footprint on devices that do not require pattern matching.
