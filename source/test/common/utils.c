/*
 * Copyright (c) 2017-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>

#include <pcap/pcap.h>

#include "test.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MILLISEC 1000

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
#ifdef JSONSCHEMA_TOOL
static uint64_t get_time_msec(void)
{
    struct timespec ts;

    if (0 != clock_gettime(CLOCK_BOOTTIME, &ts)) {
        return 0;
    }
    return (((uint64_t)ts.tv_sec) * MILLISEC) + ((uint64_t)ts.tv_nsec / (MILLISEC * MILLISEC));
}
#endif /* !JSONSCHEMA_TOOL */

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void validate_schema(const char *msg, const char *schema)
{
#ifdef JSONSCHEMA_TOOL
    uint64_t start_ts   = get_time_msec();
    char     filename[] = "/tmp/cr_schema_test.XXXXXX";
    int      fd;
    int      rc;
    char     cmd[512];

    if (NULL == getenv("UNITTEST_VALIDATE_SCHEMA")) {
        return;
    }

    fd = mkstemp(filename);
    fail_unless(0 <= fd);

    write(fd, msg, strlen(msg));
    close(fd);

    sprintf(cmd, "%s -i %s %s 2> /dev/null", JSONSCHEMA_TOOL, filename, schema);
    rc = system(cmd);
    unlink(filename);

    if (0 != rc) {
        fprintf(stderr,"JSON schena validation failed. Schema[%s] msg[%s].\n", schema, msg);
        fail();
    }

    fprintf(stderr, "JSON schema validation ok. Schema[%s] time[%"PRIu64" ms].\n", schema, get_time_msec()-start_ts);
#else
    fail_unless(NULL == getenv("UNITTEST_VALIDATE_SCHEMA"), "JSON schema validation not supported.");
#endif /* !JSONSCHEMA_TOOL */
}

packet_t *pcap_read_first_packet(const char *file)
{
    pcap_t              *pcap = NULL;
    packet_t            *packet = NULL;
    struct  pcap_pkthdr  pcap_hdr;
    char                 err_buf[PCAP_ERRBUF_SIZE];
    const uint8_t       *p;

    fail_unless(!!(pcap = pcap_open_offline(file, err_buf)));
    fail_unless(!!(p = pcap_next(pcap, &pcap_hdr)));
    fail_unless(pcap_hdr.caplen <= MAX_PACKET_LEN);
    fail_unless(!!(packet = malloc(sizeof(packet_t))));

    packet->len = pcap_hdr.caplen;
    memcpy(packet->data, p, pcap_hdr.caplen);

    pcap_close(pcap);

    return packet;
}

packet_t **pcap_read_all_packets(const char *file, size_t *packets_nr)
{
    pcap_t               *pcap = NULL;
    packet_t             *packet = NULL;
    packet_t            **packets = NULL;
    struct  pcap_pkthdr   pcap_hdr;
    char                  err_buf[PCAP_ERRBUF_SIZE];
    const uint8_t        *p;
    size_t                idx = 0;

    fail_unless(!!(pcap = pcap_open_offline(file, err_buf)));

    while ((p = pcap_next(pcap, &pcap_hdr))) {
        fail_unless(pcap_hdr.caplen <= MAX_PACKET_LEN);
        fail_unless(!!(packet = malloc(sizeof(packet_t))));

        packet->len = pcap_hdr.caplen;
        memcpy(packet->data, p, pcap_hdr.caplen);

        fail_unless(!!(packets = realloc(packets, (idx + 1) * sizeof(*packets))));
        packets[idx++] = packet;
    }

    pcap_close(pcap);

    *packets_nr = idx;
    return packets;
}

void free_packets(packet_t **p, size_t nr)
{
    size_t i;

    for (i = 0; i < nr; i++) {
        free(p[i]);
    }

    free(p);
}

