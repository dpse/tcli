+++
title = "Keyboard Shortcuts"
description = "The full readline-style shortcut table built into TinyCLI"
weight = 50
+++

TinyCLI implements a subset of the standard GNU readline shortcuts for line editing, history, and tab-completion. The bindings are fixed and not configurable.

## Cursor Movement

| Shortcut | Action |
|---|---|
| {{ kbd(key="Left") }} | Move cursor back one character. |
| {{ kbd(key="Right") }} | Move cursor forward one character. |
| {{ kbd(key="Home") }} | Move cursor to start of line. |
| {{ kbd(key="End") }} | Move cursor to end of line. |
| {{ kbd(key="Ctrl+b") }} | Move cursor back one character. (Same as {{ kbd(key="Left") }}.) |
| {{ kbd(key="Ctrl+f") }} | Move cursor forward one character. (Same as {{ kbd(key="Right") }}.) |
| {{ kbd(key="Ctrl+a") }} | Move cursor to start of line. (Same as {{ kbd(key="Home") }}.) |
| {{ kbd(key="Ctrl+e") }} | Move cursor to end of line. (Same as {{ kbd(key="End") }}.) |
| {{ kbd(key="Alt+b") }} | Move cursor back one word. |
| {{ kbd(key="Alt+f") }} | Move cursor forward one word. |

## Deletion

| Shortcut | Action |
|---|---|
| {{ kbd(key="Delete") }} | Delete the character under the cursor. |
| {{ kbd(key="Backspace") }} | Delete the character before the cursor. |
| {{ kbd(key="Ctrl+d") }} | Delete the character under the cursor. (Same as {{ kbd(key="Delete") }}.) |
| {{ kbd(key="Ctrl+h") }} | Delete the character before the cursor. (Same as {{ kbd(key="Backspace") }}.) |
| {{ kbd(key="Ctrl+k") }} | Clear from cursor to end of line. |
| {{ kbd(key="Ctrl+u") }} | Clear from cursor to start of line. |
| {{ kbd(key="Ctrl+w") }} | Clear the word before the cursor. |
| {{ kbd(key="Alt+d") }} | Delete the word after the cursor. |

## History

Available when [`TCLI_HISTORY_BUF_LEN`](@/configuration.md#history) `> 0` (the default).

| Shortcut | Action |
|---|---|
| {{ kbd(key="Up") }} | Recall the previous command. |
| {{ kbd(key="Down") }} | Recall the next command. |
| {{ kbd(key="Ctrl+p") }} | Recall the previous command. (Same as {{ kbd(key="Up") }}.) |
| {{ kbd(key="Ctrl+n") }} | Recall the next command. (Same as {{ kbd(key="Down") }}.) |
| {{ kbd(key="Ctrl+r") }} | Enter reverse-search mode. |
| {{ kbd(key="Ctrl+g") }} | Exit reverse-search mode (without selecting). |
| {{ kbd(key="Alt+r") }} | Cancel any edits to a recalled history line. |

## Tab-Completion

Available when [`TCLI_COMPLETE`](@/configuration.md#tab-completion) `= 1` (the default).

| Shortcut | Action |
|---|---|
| {{ kbd(key="Tab") }} | Complete at cursor; on subsequent presses, cycle through matches. |
| {{ kbd(key="Esc") }} | Exit tab-completion mode (without choosing a match). |

> [!NOTE]
> {{ kbd(key="Esc") }} needs to be pressed twice in some terminal contexts, since the byte sequence is otherwise indistinguishable from the start of an ANSI escape sequence the library is reading.

## Other

| Shortcut | Action |
|---|---|
| {{ kbd(key="Ctrl+c") }} | Send SIGINT to the registered handler (if any); otherwise abort the line. |
| {{ kbd(key="Ctrl+l") }} | Clear the screen. |
| {{ kbd(key="Ctrl+i") }} | Equivalent to {{ kbd(key="Tab") }}. |
| {{ kbd(key="Ctrl+j") }} | Equivalent to {{ kbd(key="Enter") }}. |

## Key Name Notation

{{ kbd(key="Alt+x") }} denotes what most terminals transmit as {{ kbd(key="Esc") }} {{ kbd(key="x") }}, i.e. a literal Escape byte followed by `x`. On a typical terminal this is produced by holding {{ kbd(key="Option") }} or {{ kbd(key="Alt") }} while pressing the corresponding key.
