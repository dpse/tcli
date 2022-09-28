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
Login is possible with either password only or with usernames and optional passwords.
Only users with a level matching the minimum required level for a command can execute the command.

Commands are registered with a command, the minimum user level required (if users are enabled), a description, and
optionally a pattern with some options (if pattern matching is enabled).
The description along with any pattern and options (if used) are automatically printed when the built-in help command is called.

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

- The pattern matching system currently only supports matching word-tokens (i.e. no matches inside words).
- The pattern matcher is recursive and stack requirements will increase with pattern complexity.

## Usage

1. Define output function and initialize:

```c
#include "tclie.h"

void output(void * arg, const char * str)
{
    printf("%s", str); // Or send through serial interface
}

tclie_t tclie;
tclie_init(&tclie, output, NULL);
```

2. Register user table (if needed):

```c
static const tclie_user_t users[] = {
    // Name,  password, level
    {"debug", NULL,     1}, // No password required
    {"admin", "12345",  2}
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
    // Name, callback, minimum user level, description (for help)    
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

### Logging

In a multithreaded environment it can be useful to be able to log stuff without disturbing the prompt:

```c
tclie_log(&tclie, "Some message...\r\n");

char buf[64];
tclie_log_printf(&tclie, buf, sizeof(buf), "Hello %s\r\n", "world!");
```

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
| Esc      | Exit tab-completion or reverse search mode.             |

*Note! `Esc` needs to be pressed twice since it is impossible to differentiate from an escape sequence otherwise.*

## Miscellaneous

### Telnet

Telnet newlines (`<CR><NUL>`) are automatically handled but it may be necessary to tell connecting clients (e.g.
PuTTY) how to behave.
This can be done by sending the following sequences to the client:

- `IAC DO ECHO`: Tell client to echo received characters from server.
- `IAC WILL ECHO`: Tell client that the server will echo back received characters.
- `IAC DO SUPPRESS-GO-AHEAD`: Tell client to not send `GO AHEAD` when transmitting.
- `IAC WILL SUPPRESS-GO-AHEAD`: Tell client that the server won't send `GO AHEAD` when transmitting.

```c
const char options[] = {255, 253, 1,  // IAC DO ECHO
                        255, 251, 1,  // IAC WILL ECHO
                        255, 253, 3,  // IAC DO SUPPRESS-GO-AHEAD
                        255, 251, 3}; // IAC WILL SUPPRESS-GO-AHEAD
```
