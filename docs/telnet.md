+++
title = "Telnet Integration"
description = "Telling Telnet clients to behave so the prompt renders cleanly"
weight = 70
+++

By default, Telnet leaves each client to decide whether to echo characters locally, whether to wait for a `GO AHEAD` before transmitting, and how line endings are encoded. None of those defaults are compatible with a CLI that expects character-at-a-time input and renders its own prompt. A short option negotiation, sent once per new connection, is sufficient to put the client into a usable mode.

## Option Negotiation

```c
const unsigned char options[] = {
    255, 253, 1,    /* IAC DO ECHO - request that the client echo received characters */
    255, 251, 1,    /* IAC WILL ECHO - server will echo received characters */
    255, 253, 3,    /* IAC DO SUPPRESS-GO-AHEAD - request that the client not send GO AHEAD before transmitting */
    255, 251, 3,    /* IAC WILL SUPPRESS-GO-AHEAD - server will not send GO AHEAD either */
};
send(client_fd, options, sizeof(options), 0);
```

`IAC` is the byte `255`. `DO` is `253`, meaning "the other side should perform this option". `WILL` is `251`, meaning "this side will perform this option". `ECHO` is option 1 and `SUPPRESS-GO-AHEAD` is option 3.

The combined effect is that the client (e.g. PuTTY) echoes the user's typed characters (which is what TinyCLI assumes) and that neither side waits for a `GO AHEAD` before transmitting. The latter is a line-oriented Telnet behavior that would otherwise break character-at-a-time input.

## Line Endings

A line is terminated by a carriage return (`\r`), a line feed (`\n`), or a NUL (`\0`). The two-byte sequences `\r\n`, `\r\0`, and `\n\r` are each treated as a single terminator: the second byte is consumed rather than starting a new (empty) line. Telnet clients differ in which of these they transmit, but all of the above are handled, so no additional handling on the application side is required.

## Per-Connection Flow

A typical sequence per accepted connection:

1. Send the option-negotiation bytes shown above.
2. Optionally, send a banner, version string, or pre-login prompt: anything that should appear before the first interactive prompt.
3. Call [`tclie_init`](@/tclie.md#initialization) (or reuse a long-lived instance, taking care with the embedded state).
4. Forward each received byte into [`tclie_in_char`](@/tclie.md#input-and-output). The output callback should write to the corresponding socket.
5. On disconnect, ignore any further input. The library does not track sockets itself.

Sharing a single TinyCLI instance between multiple Telnet clients is *not* supported. Each `tcli_t` holds the line state, history, and completion context of one user. One instance is required per connection.
