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
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "map_cli.h"

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static int fd = -1;
static struct option options[] = {
    {"background", no_argument, 0, 0x102 },
    {"wait", required_argument, 0, 0x103 },
    {"timeout", required_argument, 0, 0x104 },
    {"command", required_argument, 0, 0x200 },
    {"payload", required_argument, 0, 0x201 },
    {0, 0, 0, 0 }
};

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static void signal_handler(int sig)
{
    (void)sig;
    if (sig == SIGALRM) {
        fprintf(stderr, "map_cli timed out\n");
        if (fd >= 0) {
            close(fd);
        }
        exit(-2);
    }
}

/*#######################################################################
#                       MAIN                                            #
########################################################################*/
int main(int argc, char *argv[])
{
    struct sockaddr_un saddr;

    int c;
    int option_index;

    int wait = 0;
    int timeout = 10000;

    const char *command = NULL;
    const char *payload = "{}";

    const char *prefix = "";;
    const char *seperator = ":";

    int l;
    int s;

    struct pollfd pfd;
    int rc;

    while (1) {
        c = getopt_long(argc, argv, "h", options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'h':
            command = "help";
            break;
        case 0x102:
            /* background parameter is invalid */
            break;
        case 0x103:
            wait = atoi(optarg);
            break;
        case 0x104:
            timeout = atoi(optarg);
            break;
        case 0x200:
            command = optarg;
            break;
        case 0x201:
            payload = optarg;
            break;
        }
    }

    /* If no command if provided, print help */
    if (command == NULL) {
        command = "help";
    }

    /* Create and bind socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "map_cli can not open socket\n");
        goto bail;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    snprintf(saddr.sun_path + 1, sizeof(saddr.sun_path) - 1, "%s.%d", CLI_SOCK_PATH, getpid());
    if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr))) {
        fprintf(stderr, "map_cli bind failed\n");
        goto bail;
    }

    /* Set timeout */
    if (timeout > 0) {
        signal(SIGALRM, signal_handler);
        alarm(timeout / 1000);
    }

    /* Connect to server */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    snprintf(saddr.sun_path + 1, sizeof(saddr.sun_path) - 1, "%s", CLI_SOCK_PATH);
    if (connect(fd, (struct sockaddr*)&saddr, sizeof(struct sockaddr_un))) {
        fprintf(stderr, "map_cli connect failed\n");
        goto bail;
    }

    /* Wait if needed */
    if (wait > 0) {
        usleep(wait * 1000);
    }

    l  = strlen(prefix);
    l += strlen(command);
    l += strlen(seperator);
    l += strlen(payload);

    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    rc = poll(&pfd, 1, 1000/*1 sec*/);
    if (rc < 0) {
        fprintf(stderr, "map_cli poll error\n");
        goto bail;
    }
    if (rc == 0) {
        fprintf(stderr, "map_cli poll timeout\n");
        goto bail;
    }
    if ((pfd.revents & POLLOUT) == 0) {
        fprintf(stderr, "map_cli revents error\n");
        goto bail;
    }
    l = htonl(l);
    s = send(fd, &l, sizeof(l), MSG_NOSIGNAL);

    if (s != sizeof(l)) {
        fprintf(stderr, "map_cli can not write to daemon\n");
        goto bail;
    }
    s = send(fd, prefix, strlen(prefix), MSG_NOSIGNAL);
    if (s != (int)strlen(prefix)) {
        fprintf(stderr, "map_cli can not write to daemon\n");
        goto bail;
    }
    s = send(fd, command, strlen(command), MSG_NOSIGNAL);
    if (s != (int)strlen(command)) {
        fprintf(stderr, "map_cli can not write to daemon\n");
        goto bail;
    }
    s = send(fd, seperator, strlen(seperator), MSG_NOSIGNAL);
    if (s != (int)strlen(seperator)) {
        fprintf(stderr, "map_cli can not write to daemon\n");
        goto bail;
    }
    s = send(fd, payload, strlen(payload), MSG_NOSIGNAL);
    if (s != (int)strlen(payload)) {
        fprintf(stderr, "map_cli can not write to daemon\n");
        goto bail;
    }

    /* Read output until socket closed or timeout */
    pfd.events = POLLIN;

    /* poll returns 0 on timeout, -1 on error */
    while (poll(&pfd, 1, 3000/*3 sec*/) > 0) {
        ssize_t bytes;
        char    read_buf[2048];

        if (!(pfd.revents & POLLIN)) {
            continue;
        }
        bytes = recv(fd, read_buf, sizeof(read_buf) - 1, MSG_NOSIGNAL);
        if (bytes > 0) {
            read_buf[bytes] = 0;
            fprintf(stdout, "%s", read_buf);
        } else {
            break;
        }
    }
    fprintf(stdout, "\n");
    close(fd);

    return rc;

bail:
    if (fd >= 0) {
        close(fd);
    }
    return -1;
}
