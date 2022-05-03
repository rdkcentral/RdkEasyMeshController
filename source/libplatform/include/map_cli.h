/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CLI_H_
#define MAP_CLI_H_

#include <stdarg.h>
#include <net/if.h>

#define CLI_SERVER_PORT 10995
#define CLI_SERVER_IP "127.0.0.1"

typedef struct cli_s cli_t;

typedef struct cli_options_s {
	char bindip[20];
	int port;
} cli_options_t;

typedef void (*cli_function_t)(const char *event, const char *payload, void *context);

/**
 * @brief Creates cli.
 *
 * @param[in] options Paramters to create cli.
 * @return created cli struct.
 */
cli_t *cli_create(cli_options_t *options);

/**
 * @brief Destroys cli.
 *
 * @param[in/out] cli Instance to destroy.
 * @return void
 */
void cli_destroy(cli_t *cli);

/**
 * @brief Get file destcriptor of cli.
 *
 * @param[in] cli Instance to return file destcriptor.
 * @return file destcriptor if succesful, -1 if not.
 */
int cli_fd(cli_t *cli);

/**
 * @brief Print to cli
 *
 * @param[in] cli  Instance to return file destcriptor.
 * @param[in] fmt  Printf like string
 * @param[in] ... Printf arguements
 * @return file destcriptor if succesful, -1 if not.
 */
void cli_printf(cli_t *cli, const char *fmt, ...) __attribute__((format(printf,2,3)));

/**
 * @brief Print to cli
 *
 * @param[in] cli  Instance to return file destcriptor.
 * @param[in] fmt  Printf like string
 * @param[in] args Printf arguements
 * @return file destcriptor if succesful, -1 if not.
 */
void cli_vprintf(cli_t *cli, const char *fmt, va_list args);

/**
 * @brief Run cli.
 *
 * @param[in/out] cli Instance to run.
 * @return 0 if successful, -1 if not.
 */
void cli_run(cli_t *cli);

/**
 * @brief Subscribe cli.
 *
 * @param[in] cli      Instance to subscribe event.
 * @param[in] event    Event.
 * @param[in] function Callback functions for event.
 * @param[in] context
 * @return 0 if successful, -1 if not.
 */
int cli_subscribe(cli_t *cli,
                  const char *event,
                  cli_function_t function,
                  void *context);

/**
 * @brief Unsubscribe cli.
 *
 * @param[in/out] cli   Instance to unsubscribe event.
 * @param[in]     event Event.
 * @return 0 if successful, -1 if not.
 */
int cli_unsubscribe(cli_t *cli, const char *event);

#endif	/* MAP_CLI_H_ */
