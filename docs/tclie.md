+++
title = "The tclie Wrapper"
description = "Command tables, optional users with login, built-in help/clear/login/logout"
weight = 20
+++

`tclie` extends `tcli` with a registered command table, optional users with password-based login, the built-in commands `help`, `clear`, `login`, and `logout`, and the [pattern-matching system](@/pattern-matching.md) used for argument validation and context-aware tab-completion.

A `tclie_t` instance embeds a `tcli_t`. All lower-level functions ([prompts](@/tcli.md#prompts), [history](@/tcli.md#command-history), [echo](@/tcli.md#echo-modes), etc.) have a corresponding `tclie_*` wrapper function that delegates internally, so the inner `tcli` _should not_ be accessed directly.

The canonical declarations live in [`include/tclie.h`](https://github.com/dpse/tcli/blob/master/include/tclie.h).

## Initialization

```c
#include "tclie.h"

void out(void *arg, const char *str)
{
    printf("%s", str);
}

tclie_t t;
tclie_init(&t, out, NULL); /* NULL to not pass a custom arg */
```

`tclie_init` calls [`tcli_init`](@/tcli.md#lifecycle) internally and then registers the built-in commands: `help` and `clear` always, plus `login` and `logout` when users are enabled.

## Command Registration

The command table is an array of `tclie_cmd_t` (typically `static const`). The array and its length are passed to `tclie_reg_cmds`:

```c
int cmd_status(void *arg, int argc, const char **argv)
{
    /* … */
    return 0;
}

static const tclie_cmd_t cmds[] = {
    { .name = "status", .fn = cmd_status, .desc = "Show device status" },
    { .name = "reboot", .fn = cmd_reboot, .desc = "Reset the device", .min_user_level = 2 },
};

tclie_reg_cmds(&t, cmds, sizeof(cmds) / sizeof(*cmds));
```

`tclie_reg_cmds` (and `tclie_reg_users`) return `false` if the arguments are invalid, otherwise `true`. The table is referenced _(not copied)_, so it must remain valid for the lifetime of the instance (hence `static const`).

| Field             | When it applies | Description |
|-------------------|---|---|
| `name`            | always | Command name. Matched unless a pattern is specified. |
| `fn`              | always | The callback. Receives the `arg` provided to `tclie_init`. |
| `desc`            | shown by `help` | A short description. The `help` command lists descriptions in a column, so a single line is recommended. |
| `min_user_level`  | when users are enabled | The user must be at least this level (default 0) for the command to run. |
| `pattern`         | when patterns are enabled | Argument shape; see [Pattern Matching](@/pattern-matching.md). |
| `options`         | when patterns are enabled | Long/short options for pattern matching and `help`. |

The callback follows the same calling convention as `main`: `int fn(void *arg, int argc, const char **argv)`. `argv[0]` contains the command name. A return value of zero signals success; a non-zero return switches the next prompt to the error variant (red by default).

## Pre- and Post-Command Hooks

Hooks can be registered for logging, timing, or to inject context before and after each callback:

```c
void pre(void *arg, int argc, const char **argv)
{
    log_info("running: %s", argv[0]);
}

void post(void *arg, int argc, const char **argv, int res)
{
    log_info("%s returned %d", argv[0], res);
}

tclie_set_pre_cmd(&t, pre);
tclie_set_post_cmd(&t, post);
```

Both hooks run only for *registered* commands. The built-ins (`help`, `clear`, `login`, `logout`) bypass them.

## Users and Login

Users are opt-in at compile time via [`TCLIE_ENABLE_USERS`](@/configuration.md#tclie-specific) (default `1`). When enabled, the user table is registered in the same way as the command table:

```c
static const tclie_user_t users[] = {
    { .name = "guest",    .password = NULL,       .level = 1 },  /* no password */
    { .name = "admin",    .password = "12345",    .level = 2 },
    { .name = "operator", .password = "operator", .level = 2 },
};

tclie_reg_users(&t, users, sizeof(users) / sizeof(*users));
```

The level is an unsigned integer; its semantics are determined by the application. Each command uses `min_user_level` to gate access. The default level when no user is logged in is 0.

The built-in `login` command runs the password flow:

```
> login admin
Enter password:
> 
```

The password line is masked: each character is echoed as a `*` (the built-in `login` command sets `TCLI_ECHO_OFF_ONCE`, see [echo modes](@/tcli.md#echo-modes)). Without a username argument, `login` first prompts `Enter username:`.

`logout` returns the level to 0. After [`TCLIE_LOGIN_ATTEMPTS`](@/configuration.md#tclie-specific) (default 3) incorrect passwords, the login attempt is rejected.

For password-only authentication (i.e. without usernames), set [`TCLIE_ENABLE_USERNAMES`](@/configuration.md#tclie-specific) to `0` at compile time. The `login` command then prompts for the password directly and matches against any user.

The level can also be set programmatically:

```c
tclie_set_user_level(&t, 2);
unsigned lvl = tclie_get_user_level(&t);
```

## Built-in Commands

The following commands are always registered (subject to the relevant compile-time flags):

| Command   | Available when                          | Description |
|-----------|-----------------------------------------|------|
| `help`    | always                                  | Lists registered commands with their descriptions. When given a command name as an argument, shows that command's pattern and options only. |
| `clear`   | always                                  | Clears the screen. Equivalent to {{ kbd(key="Ctrl+l") }}. |
| `login`   | `TCLIE_ENABLE_USERS = 1`                | Authenticates as a user. |
| `logout`  | `TCLIE_ENABLE_USERS = 1`                | Returns the current user level to 0. |

These four names are reserved; user-defined commands must not collide with them.

## Input and Output

The same [input](@/tcli.md#input) and [output](@/tcli.md#output) functions as `tcli` provides are wrapped with the `tclie_` prefix. All delegate to the embedded `tcli`:

```c
tclie_in_char(&t, c);
tclie_in_str(&t, "status\r\n");
tclie_in(&t, buf, len);

tclie_out(&t, "msg\n");
tclie_out_printf(&t, buf, sizeof(buf), "value = %d\n", x);
tclie_out_vprintf(&t, buf, sizeof(buf), fmt, va);   /* va_list variant */
tclie_flush(&t);
```

## Other Configuration

The configuration setters delegate and carry the `tclie_` prefix: [`tclie_set_out`](@/tcli.md#lifecycle), [`tclie_set_arg`](@/tcli.md#lifecycle), [`tclie_set_echo`](@/tcli.md#echo-modes), [`tclie_set_prompt`](@/tcli.md#prompts), [`tclie_set_error_prompt`](@/tcli.md#prompts), [`tclie_set_hist`](@/tcli.md#command-history), [`tclie_set_search_prompt`](@/tcli.md#prompts), and [`tclie_set_sigint`](@/tcli.md#sigint-handling). Their behavior and arguments are identical to the `tcli_*` originals described in [The tcli Core](@/tcli.md).

The prompt-preserving log variants are described in [Logging and Output](@/logging.md).
