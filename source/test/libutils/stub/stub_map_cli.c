/********** COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) 2021-2021  -  AirTies Wireless Networks                **
** - All Rights Reserved                                                **
** AirTies hereby informs you that certain portions                     **
** of this software module and/or Work are owned by AirTies             **
** and/or its software providers.                                       **
** Distribution copying and modification of all such work are reserved  **
** to AirTies and/or its affiliates, and are not permitted without      **
** express written authorization from AirTies.                          **
** AirTies is registered trademark and trade name of AirTies,           **
** and shall not be used in any manner without express written          **
** authorization from AirTies                                           **
*************************************************************************/

#include <string.h>

#include "map_cli.h"
#include "map_utils.h"
#include "map_cli_subscription.h"

#include "stub_map_cli.h"

struct cli_s {
    subscriptions_t *subscriptions;
};

static cli_t   g_cli;
static char  **g_print_buf;

int cli_fd(cli_t *cli)
{
    return 123;
}

void cli_vprintf(cli_t *cli, const char *fmt, va_list args)
{
    /* Concatenate print results until cb is (un)registered */
    if (g_print_buf) {
        char *p = NULL, *q = NULL;

        vasprintf(&p, fmt, args);

        asprintf(&q, "%s%s", *g_print_buf ? *g_print_buf : "", p);
        free(p);
        free(*g_print_buf);

        *g_print_buf = q;
    }
}

void cli_printf(cli_t *cli, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    cli_vprintf(cli, fmt, args);
    va_end(args);
}

void cli_run(cli_t *cli)
{
}

cli_t *cli_create(cli_options_t *options)
{
    if (!(g_cli.subscriptions = subscriptions_create())) {
        return NULL;
    }

    return &g_cli;
}

void cli_destroy(cli_t *cli)
{
    subscriptions_destroy(cli->subscriptions);
    cli->subscriptions = NULL;
}

int cli_subscribe(cli_t *cli, const char *event, cli_function_t function, uint32_t flags, void *context)
{
    return subscriptions_add(cli->subscriptions, event, function, flags, context);
}

void stub_map_cli_set_print_buf(char **buf)
{
    g_print_buf = buf;
}

int stub_map_cli_exec(char *cmd, char *payload)
{
    subscription_t *subscription = subscriptions_get(g_cli.subscriptions, cmd);

    if (subscription) {
        log_test_d("found subscription for: '%s'", cmd);
        subscription_function(subscription)(cmd, payload, subscription_context(subscription));

        return 0;
    }

    log_test_e("could not find subscription for: '%s'", cmd);
    return -1;
}
