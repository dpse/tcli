// Shared command setup used by every TinyCLI example. Each example provides
// platform-specific implementations of the three callbacks declared at the
// bottom of this file (echo, fail, exit). The user table, option list, and
// command table are identical across examples so behaviour matches between
// platforms.

#ifndef EXAMPLE_CMDS_H
#define EXAMPLE_CMDS_H

#include "tclie.h"

#define EXAMPLE_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum {
	USER_LEVEL_DEFAULT = 0,
	USER_LEVEL_DEBUG,
	USER_LEVEL_ADMIN,
};

#if TCLIE_ENABLE_USERS
#define EXAMPLE_LEVEL(x) x,
#else
#define EXAMPLE_LEVEL(x)
#endif

#ifdef __cplusplus
extern "C" {
#endif

int example_cmd_echo(void *arg, int argc, const char **argv);
int example_cmd_fail(void *arg, int argc, const char **argv);
int example_cmd_exit(void *arg, int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#if TCLIE_ENABLE_USERS
static const tclie_user_t example_users[] = {
	{"debug", NULL, USER_LEVEL_DEBUG},
	{"admin", "12345", USER_LEVEL_ADMIN},
};
#define EXAMPLE_USERS_COUNT EXAMPLE_ARRAY_SIZE(example_users)
#endif

#if TCLIE_PATTERN_MATCH
static const tclie_cmd_opt_t example_options[] = {
	{'v', "verbose", "Simple option."},
	{'t', "test", "Simple option."},
	{'r', "required", "Option with required argument.", "arg"},
	{'o', "optional", "Option with optional argument.", "[arg]"},
	{'s', NULL, "Option with short option only.", NULL},
	{0, "long", "Option with long option only.", NULL},
};
#endif

static const tclie_cmd_t example_cmds[] = {
	{"exit", example_cmd_exit,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "Exit application.",
#if TCLIE_PATTERN_MATCH
	 "exit|quit|q"
#endif
	},
	{"echo", example_cmd_echo, EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "Echo input.",
#if TCLIE_PATTERN_MATCH
	 "echo ..."
#endif
	},
	{"fail", example_cmd_fail,
	 EXAMPLE_LEVEL(USER_LEVEL_ADMIN) "A command that will fail.",
#if TCLIE_PATTERN_MATCH
	 "fail ..."
#endif
	},
	{"sub one", example_cmd_echo,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "Subcommand example."},
	{"sub other", example_cmd_echo,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "Subcommand example."},
#if TCLIE_PATTERN_MATCH
	{"reset", example_cmd_echo,
	 EXAMPLE_LEVEL(
		 USER_LEVEL_DEFAULT) "Single word command, must match exactly.",
	 "reset"},
	{"config", example_cmd_echo,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "Two word command, spaces around the "
									   "words are ignored.",
	 "config save"},
	{"can", example_cmd_echo,
	 EXAMPLE_LEVEL(
		 USER_LEVEL_DEFAULT) "Two word command, with mandatory argument.",
	 "can speed <rate>"},
	{"set", example_cmd_echo,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "One word command, with mandatory and "
									   "optional argument.",
	 "set <attr> [<value>]"},
	{"=", example_cmd_echo,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "One word command ('=') embedded "
									   "between mandatory arguments.",
	 "<reg> = <value>"},
	{"when", example_cmd_echo,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "Three word command, with two mandatory "
									   "arguments and arbitrary "
									   "optional.",
	 "when <reg> is <value> echo ..."},
	{"or", example_cmd_echo,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "Two word command, with mandatory "
									   "argument selected from options.",
	 "or a|b|c"},
	{"complex", example_cmd_echo,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "Complex example.",
	 "complex {set|reset} [a|(b c)] 1|2 <var> [<opt>] end ..."},
	{"options",
	 example_cmd_echo,
	 EXAMPLE_LEVEL(USER_LEVEL_DEFAULT) "Example with options.",
	 "options [stuff] <attr>",
	 {example_options, EXAMPLE_ARRAY_SIZE(example_options)}},
#endif
};

#define EXAMPLE_CMDS_COUNT EXAMPLE_ARRAY_SIZE(example_cmds)

#endif
