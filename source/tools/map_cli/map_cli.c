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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include "map_cli.h"

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static int fd = -1;
static struct option options[] = {
    {"hostname", required_argument, 0, 0x100 },
    {"port", required_argument, 0, 0x101 },
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
    int c;
    int option_index;

    const char *hostname;
    int port;
    char port_str[6] = {'\0'};

    int wait;
    int timeout;

    const char *command = NULL;
    const char *payload;

    const char *prefix;
    const char *seperator;

    int l;
    int s;
    struct addrinfo hints, *addr_list, *cur;

    struct pollfd pfd;
    long arg;
    socklen_t len;
    int rc, val = 1;

    hostname = CLI_SERVER_IP;
    port = CLI_SERVER_PORT;

    wait = 0;
    timeout = 10000;

    command = NULL;
    payload = "{}";

    prefix = "";
    seperator = ":";

    while (1) {
        c = getopt_long(argc, argv, "h", options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'h':
            command = "help";
            break;
        case 0x100:
            hostname = optarg;
            break;
        case 0x101:
            port = atoi(optarg);
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

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(hostname, port_str, &hints, &addr_list) != 0) {
        fprintf(stderr, "map_cli %s, no such host\n", hostname);
        return -1;
    }

    for (cur = addr_list; (cur != NULL) && (fd < 0); cur = cur->ai_next) {
        fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (fd < 0) {
            continue;
        }
        /* Set non-blocking */
        arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, arg) < 0) {
            fprintf(stderr, "map_cli fcntl F_SETFD: %s\n", strerror(errno));
        }

        while (1) {
            rc = connect(fd, cur->ai_addr, cur->ai_addrlen);
            if (rc == 0) {
                break;
            }

            pfd.fd = fd;
            pfd.events = POLLIN | POLLOUT;
            pfd.revents = 0;
            rc = poll(&pfd, 1, 5000/*5 sec*/);
            if (rc == 0) {
                fprintf(stderr, "map_cli connection timeout\n");
                close(fd);
                fd = -1;
                break;
            }

            len = sizeof(val);
            rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)(&val), &len);
            if (rc < 0 || val != 0) {
                fprintf(stderr, "map_cli connection timeout\n");
                close(fd);
                fd = -1;
                break;
            }
        }
    }

    freeaddrinfo(addr_list);
    if (fd < 0) {
        fprintf(stderr, "map_cli can not open socket! command:%s\n", command);
        return -1;
    }

    /* Set to blocking mode again... */
    arg = fcntl(fd, F_GETFL, NULL);
    arg &= (~O_NONBLOCK);
    fcntl(fd, F_SETFL, arg);

    if (timeout > 0) {
        signal(SIGALRM, signal_handler);
        alarm(timeout / 1000);
    }

    val = 1;
    setsockopt(fd, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
    /* After 10 secs of inactivity, probe 5 times in intervals of 10 secs. Max closure time is 60 secs. */
    val = 5;
    setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val));
    val = 10;
    setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val));
    val = 10;
    setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val));
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
