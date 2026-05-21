+++
title = "Getting Started"
description = "Wire up TinyCLI to a character stream and register a command"
weight = 10
+++

The smallest useful TinyCLI integration consists of reading input characters from some source (e.g. `getchar`, a UART RX, or a [Telnet socket](@/telnet.md)), feeding them to the library, and forwarding the library's output to the corresponding sink.

## 1. Output Callback

TinyCLI does not write anywhere directly. A single callback is provided at initialization and the library routes all output through it: the prompt, echoed input, command output, and formatting escape sequences.

```c
#include <stdio.h>
#include "tclie.h"

void out(void *arg, const char *str)
{
    /* arg is the third argument passed to tclie_init. Below we pass &t so
       command callbacks can call tclie_out; in production it is more often
       a pointer to a UART or socket context, used here as e.g.
       uart_write(arg, str) or telnet_send(arg, str). */
    printf("%s", str);
}
```

## 2. Command Definitions

A command consists of a name, a callback, and a short description used by the built-in `help` command. The callback receives the conventional `argc`/`argv` pair along with the `arg` value supplied to `tclie_init`.

```c
int cmd_echo(void *arg, int argc, const char **argv)
{
    tclie_t *t = arg;
    for (int i = 1; i < argc; i++) {
        tclie_out(t, argv[i]);
        tclie_out(t, i + 1 < argc ? " " : "\n");
    }

    /* zero = success; non-zero switches the prompt to the error variant */
    return 0;
}

int cmd_reboot(void *arg, int argc, const char **argv)
{
    tclie_t *t = arg;
    tclie_out(t, "rebooting...\n");
    /* hardware_reset(); */
    return 0;
}

static const tclie_cmd_t cmds[] = {
    { .name = "echo",   .fn = cmd_echo,   .desc = "Print arguments back" },
    { .name = "reboot", .fn = cmd_reboot, .desc = "Reset the device" },
};
```

Additional fields on `tclie_cmd_t` (`min_user_level`, `pattern`, `options`) are described in [The tclie Wrapper](@/tclie.md) and [Pattern Matching](@/pattern-matching.md). They can be omitted when users and argument validation are not required.

## 3. Initialization and Input

```c
int main(void)
{
    tclie_t t;
    tclie_init(&t, out, &t);
    tclie_reg_cmds(&t, cmds, sizeof(cmds) / sizeof(*cmds));

    int c;
    while ((c = getchar()) != EOF)
        tclie_in_char(&t, (char) c);

    return 0;
}
```

The above is a complete CLI with tab-completion and command history. The built-in `help` command lists registered commands, {{ kbd(key="Tab") }} completes partial commands, {{ kbd(key="Up") }}/{{ kbd(key="Down") }} walks the history, and {{ kbd(key="Ctrl+r") }} performs a backwards history search.

## 4. Next Steps

A SIGINT handler can be registered to catch {{ kbd(key="Ctrl+c") }} (see [`tclie_set_sigint`](@/tclie.md#sigint)).

Commands can be restricted to certain user levels by enabling the optional users feature:

```c
static const tclie_user_t users[] = {
    { .name = "admin", .password = "12345", .level = 2 },
};
tclie_reg_users(&t, users, sizeof(users) / sizeof(*users));
```

A command with `min_user_level = 2` then only runs after `login admin` (see [The tclie Wrapper](@/tclie.md#users-and-login)).

Argument shape can be validated with patterns instead of inspecting `argc` manually:

```c
{ .name = "set", .fn = cmd_set, .desc = "Set value", .pattern = "set <key> <value>" }
```

The pattern is also used to drive context-aware tab-completion (see [Pattern Matching](@/pattern-matching.md)).

Log output that does not interfere with the current prompt is provided by `tclie_log` and `tclie_log_printf` (see [Logging and Output](@/logging.md)).
