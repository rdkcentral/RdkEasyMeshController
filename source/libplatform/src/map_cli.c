/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define LOG_TAG "cli"

#include "map_cli_subscription.h"
#include "map_cli.h"
#include "map_utils.h"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
struct cli_s {
    cli_options_t *options;
    subscriptions_t *subscriptions;
    int fd;
    FILE *session_fp;
};

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int cli_fd(cli_t *cli)
{
    if (cli == NULL) {
        log_lib_e("cli is invalid");
        return -1;
    }
    return cli->fd;
}

void cli_vprintf(cli_t *cli, const char *fmt, va_list args)
{
    vfprintf(cli->session_fp, fmt, args);
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
    int rc;

    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    int fd = -1;
    FILE *fp = NULL;
    int r, len;
    char *buffer = NULL;
    char *result = NULL;
    char *event;
    char *payload;

    subscription_t *subscription;

    cli_len = sizeof(cli_addr);
    fd = accept(cli->fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) {
        log_lib_e("can not accept client");
        goto bail;
    }

    /* Create file pointer for writing data */
    fp = fdopen(fd, "w");
    if (NULL == fp) {
        log_lib_e("fdopen failed");
        goto bail;
    }
    cli->session_fp = fp;  /* We can only have one session active at a time, so one fp */

    int val = 1;
    setsockopt(fd, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
    /* After 10 secs of inactivity, probe 5 times in intervals of 10 secs. Max closure time is 60 secs. */
    val = 5;
    setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val));
    val = 10;
    setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val));
    val = 10;
    setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val));

    rc = recv(fd, &len, sizeof(len), MSG_NOSIGNAL);
    len = ntohl(len);
    if (rc != sizeof(len)) {
        log_lib_e("can not read from client");
        goto skip;
    }

    buffer = malloc(len + 1);
    if (buffer == NULL) {
        log_lib_e("can not allocate memory");
        goto bail;
    }

    log_lib_d("waiting for %d bytes", len);
    r = 0;
    while (r < len) {
        rc = recv(fd, buffer + r, len - r, MSG_NOSIGNAL);
        if (rc <= 0) {
            log_lib_e("can not read from client");
            goto skip;
        }
        r += rc;
    }
    buffer[len] = '\0';
    log_lib_d("buffer: %s", buffer);

    event = buffer;
    payload = strstr(buffer, ":");
    if (payload == NULL) {
        log_lib_e("not a cli event");
        goto skip;
    }
    *payload = '\0';
#if 1 /* Not look for { */
    payload += 1;
#else
    payload = strstr(payload + 1, "{");
    if (payload == NULL) {
        log_lib_e("not a cli event");
        goto skip;
    }
#endif

    log_lib_d("search subscription for: '%s'", event);
    subscription = subscriptions_get(cli->subscriptions, event);
    if (subscription != NULL) {
        log_lib_d("found subscription for: '%s'", event);
        subscription_function(subscription)(event, payload, subscription_context(subscription));
    } else {
        log_lib_e("could not find subscription for: '%s'", event);
        cli_printf(cli, "cli '%s' not found!\n", event);
    }

skip:
bail:
    cli->session_fp = NULL;
    if (fp) {
        fclose(fp); /* also closes fd */
    } else if (fd >= 0) {
        close(fd);
    }
    free(buffer);
    free(result);
}

cli_t *cli_create(cli_options_t *options)
{
    int rc;
    int yes = 1;
    struct sockaddr_in serv_addr;

    cli_t *cli;

    log_lib_d("creating cli ip[%s] port[%d]", options->bindip, options->port);

    cli = malloc(sizeof(cli_t));
    if (cli == NULL) {
        log_lib_e("can not allocate memory");
        goto bail;
    }
    memset(cli, 0, sizeof(cli_t));
    cli->fd = -1;

    cli->options = options;
    cli->subscriptions = subscriptions_create();
    if (cli->subscriptions == NULL) {
        log_lib_e("can not create subscriptions");
        goto bail;
    }

    cli->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (cli->fd < 0) {
        log_lib_e("can not open socket");
        goto bail;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    if (strlen(options->bindip) == 0) {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (!inet_aton(options->bindip, &serv_addr.sin_addr)) {
            log_lib_e("can not convert IP address: %s", options->bindip);
            goto bail;
        }
    }
    serv_addr.sin_port = htons(options->port);

    setsockopt(cli->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    rc = bind(cli->fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (rc < 0) {
        log_lib_e("can not bind cli");
        goto bail;
    }

    rc = listen(cli->fd, 10);
    if (rc < 0) {
        log_lib_e("can not set listen backlog");
        goto bail;
    }

    return cli;

bail:
    if (cli != NULL) {
        cli_destroy(cli);
    }
    return NULL;
}

void cli_destroy(cli_t *cli)
{
    log_lib_d("destroying cli");
    if (cli == NULL) {
        return;
    }
    if (cli->subscriptions != NULL) {
        subscriptions_destroy(cli->subscriptions);
    }
    if (cli->fd >= 0) {
        close(cli->fd);
    }
    free(cli);
}

int cli_subscribe(cli_t *cli, const char *event, cli_function_t function, void *context)
{
    if (cli == NULL) {
        log_lib_e("cli is invalid");
        goto bail;
    }
    if (event == NULL) {
        log_lib_e("event is invalid");
        goto bail;
    }
    if (function == NULL) {
        log_lib_e("function is invalid");
        goto bail;
    }
    return subscriptions_add(cli->subscriptions, event, function, context);

bail:
    return -1;
}

int cli_unsubscribe(cli_t *cli, const char *event)
{
    if (cli == NULL) {
        log_lib_e("cli is invalid");
        goto bail;
    }
    if (event == NULL) {
        log_lib_e("event is invalid");
        goto bail;
    }
    return subscriptions_del(cli->subscriptions, event);

bail:
    return -1;
}
