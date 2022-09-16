# TinyCLI

*TinyCLI* is a command line interface for embedded systems that is intended to be very easy to use.
Typical applications would e.g. be to provide a simple CLI over a serial line or over a Telnet connection.

![Sample](sample.gif)

## Features

- No dynamic allocations.
- Configurable prompt(s).
- Output buffering.
- Command history in ringbuffer.
- Backwards history search.
- Tab-completion.
- Custom SIGINT handler.
- Functions for printing e.g. log data without disturbing the prompt.

History and output buffering can be disabled to reduce memory requirements for use on smaller systems.

### Wrapper Extensions (`tclie`)

- Extension functions for automatic handling of users, commands and tab-completion.
- Optional pattern matching system:
    - Automatic validation of command syntax and command options.
    - Context-sensitive tab-completion.
- Default commands (`help`, `clear`, `login`, and `logout`)

Users can be registered so that only certain commands are available to certain users.
Login is possibly with either password only or with usernames and optional passwords.
Only users with a level matching the minimum required level for a command can execute the command.

Commands are registered with a command, the minimum user level required (if users are enabled),
the minimum and maximum number of arguments that are allowed, and a description.
The description is automatically printed when the command is invoked with "-h/--help" flags or when the built-in
help command is called.

#### Pattern Matching

The following syntax can be used in patterns:

| Pattern | Description                                    |
|----|------------------------------------------------|
| `abc` | Matches `abc`.                                 |
| `"a b"` or `'a b'` | Matches `a b` including whitespace.            |
| `[abc]` | Optionally matches `abc`.                      |
| `a\|b\|cd`                  | Matches `a`, `b` or `cd`.                      |
| `<abc>` | Wildcard; matches any word.                    |
| `[<abc>]` | Optional wildcard; optionally matches any word. |
| `a\|(b c)` or `a\|{b c}`                             | Matches `a` or `b c`.                         |
| `...` | Matches none or all remaining tokens.          |

The pattern matching system currently only supports matching word-tokens (i.e. no matches inside words).

## Usage

1. Define output function and initialize:

```c
#include "tclie.h"

void output(void * arg, const char * str)
{
    printf("%s", str);
}

tclie_t tclie;
tclie_init(&tclie, output, NULL);
```

2. Register user table (if needed):

```c
static const tclie_user_t users[] = {
    // Name, password, level
    {"debug", NULL, 1},
    {"admin", "12345", 2}
};

tclie_reg_users(&tclie, users, 2);
```

3. Register command table:

```c
int echo(void * arg, int argc, const char ** argv)
{
    if(argc > 1)
        printf("%s\r\n", argv[1]);
    
    return 0;
}

static const tclie_cmd_t cmds[] = {
    // Name, callback, min user level, min args, max args, description (for help)    
    {"echo", echo, 1, "Echo input."}
};

tclie_reg_cmds(&tclie, cmds, 1);
```

4. Feed input characters:

```c
while (1) {
    char c = getchar(); // Read e.g. serial input
    tclie_input_char(&tclie, c);
}
```

See the examples directory for more details.

## Supported Keyboard Shortcuts

| Shortcut | Description                                             |
|----------|---------------------------------------------------------|
| Ctrl+a   | Move cursor to line start.                              |
| Ctrl+b   | Move cursor back one character.                         |
| Ctrl+c   | Sends SIGINT to registred handler.                      |
| Ctrl+d   | Delete current character.                               |
| Ctrl+e   | Move cursor to line end.                                |
| Ctrl+f   | Move cursor forward one character.                      |
| Ctrl+g   | Exit reverse search mode.                               |
| Ctrl+h   | Delete previous character.                              |
| Ctrl+i   | Equivalent to the tab key.                              |
| Ctrl+j   | Equivalent to the enter key.                            |
| Ctrl+k   | Clear line after cursor.                                |
| Ctrl+l   | Clear screen content.                                   |
| Ctrl+n   | Recall next command.                                    |
| Ctrl+p   | Recall previous command.                                |
| Ctrl+r   | Reverse search through command history.                 |
| Ctrl+u   | Clear line before cursor.                               |
| Ctrl+w   | Clear word before cursor.                               |
| Alt+b    | Move cursor backward one word.                          |
| Alt+d    | Delete word after cursor.                               |
| Alt+f    | Move cursor forward one word.                           |
| Alt+r    | Cancel changes to history line.                         |
| Tab      | Tab-complete at cursor or select from multiple matches. |
| Esc        | Exit tab-completion or reverse search mode.                |

