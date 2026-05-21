+++
title = "TinyCLI"
description = "A tiny command-line interface for embedded systems"
sort_by = "weight"
+++

_TinyCLI_ is a tiny _command-line interface_ library for embedded systems. It allows you to register a set of commands (and optionally users), and then by directing input and output you automatically get a command-line interface with tab-completion, history, [shortcut support](@/shortcuts.md), [pattern matching](@/pattern-matching.md), etc.
It can also coexist with log or debug-output.

It is written in C, performs no dynamic allocations, and is intended to run on microcontrollers with or without an RTOS. Typical applications include providing a CLI over a serial line or a [Telnet connection](@/telnet.md).

![TinyCLI in action](/sample.gif)

The library is [configured](@/configuration.md) using compiler flags, and features can be deactivated to reduce memory usage to fit on memory-constrained systems.

The library is provided in two layers. Unless you have very specific requirements it is recommended to only use the high-level `tclie` API:

- [`tcli`](@/tcli.md): The lower-level core. Input characters are fed in, and the line buffer, command history, tab-completion, and output callback are managed internally. When the user presses {{ kbd(key="Enter") }}, the registered exec callback is invoked with an `argc`/`argv`-style argument list.

- [`tclie`](@/tclie.md): A thin wrapper on top of `tcli` that adds a registered command table, optional users with login, an optional pattern-matching system for argument validation and automatic tab-completion, and the built-in commands `help`, `clear`, `login`, and `logout`.

Prompt rendering, history, tab-completion, and prompt-preserving log output are common to both layers.

## Quick-Start

Below is a minimal program that shows how to use the library:

```c
#include <stdio.h>
#include "tclie.h"

/* Output callback. The library routes every emitted byte through this;
   on an MCU this would typically write to a UART instead of stdout. */
void out(void *arg, const char *str)
{
    printf("%s", str);
}

/* Command callback for "echo ...". */
int cmd_echo(void *arg, int argc, const char **argv)
{
    for (int i = 1; i < argc; i++)
        printf("%s%s", argv[i], i + 1 < argc ? " " : "\n");
    return 0;
}

/* Command table. The descriptions are printed by the built-in help command. */
static const tclie_cmd_t cmds[] = {
    { .name = "echo", .fn = cmd_echo, .desc = "Print arguments back" },
};

int main(void)
{
    /* Initialize and register command table. */
    tclie_t t;
    tclie_init(&t, out, NULL);
    tclie_reg_cmds(&t, cmds, sizeof(cmds) / sizeof(*cmds));

    /* Feed input characters. */
    int c;
    while ((c = getchar()) != EOF)
        tclie_in_char(&t, (char) c);
}
```

## Documentation

- [Getting Started](@/getting-started.md): a longer walkthrough with prompts, output, and a SIGINT handler.
- [The `tcli` Core](@/tcli.md): basic features and usage for finer control (e.g. writing a custom command dispatch or using TinyCLI without the wrapper).
- [The `tclie` Wrapper](@/tclie.md): command tables, users, and the built-in commands.
- [Pattern Matching](@/pattern-matching.md): argument-shape validation and context-aware tab-completion.
- [Logging and Output](@/logging.md): printing without disturbing the prompt.
- [Keyboard Shortcuts](@/shortcuts.md): the full readline-style shortcut table.
- [Configuration](@/configuration.md): compile-time configuration and ANSI color macros for prompt customization.
- [Telnet Integration](@/telnet.md): option negotiation for a clean Telnet prompt.

## Examples

The [examples directory](https://github.com/dpse/tcli/tree/master/examples) contains:

- [Linux CLI](https://github.com/dpse/tcli/tree/master/examples/linux): full terminal integration with termios, history, signal handling, and a periodic logging demo.
- [Arduino](https://github.com/dpse/tcli/tree/master/examples/arduino): serial CLI for AVR, <abbr>ESP32</abbr>, and <abbr>RP2040</abbr> via PlatformIO, with memory-tight defaults.
- [Shared command set](https://github.com/dpse/tcli/blob/master/examples/common/example_cmds.h): patterns, options, login, and subcommands, reused across platforms.
