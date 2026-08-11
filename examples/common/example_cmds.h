#ifndef EXAMPLE_CMDS_H
#define EXAMPLE_CMDS_H

#include "tclie.h"

#define EXAMPLE_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum {
	USER_LEVEL_DEFAULT = 0,
	USER_LEVEL_DEBUG,
	USER_LEVEL_ADMIN,
};

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
#if TCLIE_ENABLE_USERNAMES
	{.name = "debug", .password = NULL, .level = USER_LEVEL_DEBUG},
	{.name = "admin", .password = "12345", .level = USER_LEVEL_ADMIN},
#else
	// Without usernames a user is identified by its password alone.
	{.password = "12345", .level = USER_LEVEL_ADMIN},
#endif
};
#define EXAMPLE_USERS_COUNT EXAMPLE_ARRAY_SIZE(example_users)
#endif

#if TCLIE_PATTERN_MATCH
static const tclie_cmd_opt_t example_options[] = {
	{.short_opt = 'v', .long_opt = "verbose", .desc = "Simple option."},
	{.short_opt = 't', .long_opt = "test", .desc = "Simple option."},
	{.short_opt = 'r',
	 .long_opt = "required",
	 .desc = "Option with required argument.",
	 .pattern = "<arg>"},
	{.short_opt = 'o',
	 .long_opt = "optional",
	 .desc = "Option with optional argument.",
	 .pattern = "[<arg>]"},
	{.short_opt = 's', .desc = "Option with short option only."},
	{.long_opt = "long", .desc = "Option with long option only."},
};
#endif

static const tclie_cmd_t example_cmds[] = {
	{
		.name = "exit",
		.fn = example_cmd_exit,
#if TCLIE_ENABLE_USERS
		.min_user_level = USER_LEVEL_DEFAULT,
#endif
		.desc = "Exit application.",
#if TCLIE_PATTERN_MATCH
		.pattern = "exit|quit|q",
#endif
	},
	{
		.name = "echo",
		.fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
		.min_user_level = USER_LEVEL_DEFAULT,
#endif
		.desc = "Echo input.",
#if TCLIE_PATTERN_MATCH
		.pattern = "echo ...",
#endif
	},
	{
		.name = "fail",
		.fn = example_cmd_fail,
#if TCLIE_ENABLE_USERS
		.min_user_level = USER_LEVEL_ADMIN,
#endif
		.desc = "A command that will fail.",
#if TCLIE_PATTERN_MATCH
		.pattern = "fail ...",
#endif
	},
	{
		.name = "sub one",
		.fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
		.min_user_level = USER_LEVEL_DEFAULT,
#endif
		.desc = "Subcommand example.",
	},
	{
		.name = "sub other",
		.fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
		.min_user_level = USER_LEVEL_DEFAULT,
#endif
		.desc = "Subcommand example.",
	},
#if TCLIE_PATTERN_MATCH
	{.name = "reset",
	 .fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
	 .min_user_level = USER_LEVEL_DEFAULT,
#endif
	 .desc = "Single word command, must match exactly.",
	 .pattern = "reset"},
	{.name = "config",
	 .fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
	 .min_user_level = USER_LEVEL_DEFAULT,
#endif
	 .desc = "Two word command, spaces around the words are ignored.",
	 .pattern = "config save"},
	{.name = "can",
	 .fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
	 .min_user_level = USER_LEVEL_DEFAULT,
#endif
	 .desc = "Two word command, with mandatory argument.",
	 .pattern = "can speed <rate>"},
	{.name = "set",
	 .fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
	 .min_user_level = USER_LEVEL_DEFAULT,
#endif
	 .desc = "One word command, with mandatory and optional argument.",
	 .pattern = "set <attr> [<value>]"},
	{.name = "=",
	 .fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
	 .min_user_level = USER_LEVEL_DEFAULT,
#endif
	 .desc = "One word command ('=') embedded between mandatory arguments.",
	 .pattern = "<reg> = <value>"},
	{.name = "when",
	 .fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
	 .min_user_level = USER_LEVEL_DEFAULT,
#endif
	 .desc = "Three word command, with two mandatory arguments and arbitrary "
			 "optional.",
	 .pattern = "when <reg> is <value> echo ..."},
	{.name = "or",
	 .fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
	 .min_user_level = USER_LEVEL_DEFAULT,
#endif
	 .desc = "Two word command, with mandatory argument selected from options.",
	 .pattern = "or a|b|c"},
	{.name = "complex",
	 .fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
	 .min_user_level = USER_LEVEL_DEFAULT,
#endif
	 .desc = "Complex example.",
	 .pattern = "complex {set|reset} [a|(b c)] 1|2 <var> [<opt>] end ..."},
	{.name = "options",
	 .fn = example_cmd_echo,
#if TCLIE_ENABLE_USERS
	 .min_user_level = USER_LEVEL_DEFAULT,
#endif
	 .desc = "Example with options.",
	 .pattern = "options [stuff] <attr>",
	 .options = {example_options, EXAMPLE_ARRAY_SIZE(example_options)}},
#endif
};

#define EXAMPLE_CMDS_COUNT EXAMPLE_ARRAY_SIZE(example_cmds)

#endif
