/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

/*
 *  Broadband Forum IEEE 1905.1/1a stack
 *
 *  Copyright (c) 2017, Broadband Forum
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  Subject to the terms and conditions of this license, each copyright
 *  holder and contributor hereby grants to those receiving rights under
 *  this license a perpetual, worldwide, non-exclusive, no-charge,
 *  royalty-free, irrevocable (except for failure to satisfy the
 *  conditions of this license) patent license to make, have made, use,
 *  offer to sell, sell, import, and otherwise transfer this software,
 *  where such license applies only to those patent claims, already
 *  acquired or hereafter acquired, licensable by such copyright holder or
 *  contributor that are necessarily infringed by:
 *
 *  (a) their Contribution(s) (the licensed copyrights of copyright holders
 *      and non-copyrightable additions of contributors, in source or binary
 *      form) alone; or
 *
 *  (b) combination of their Contribution(s) with the work of authorship to
 *      which such Contribution(s) was added by such copyright holder or
 *      contributor, if, at the time the Contribution is added, such addition
 *      causes such combination to be necessarily infringed. The patent
 *      license shall not apply to any other combinations which include the
 *      Contribution.
 *
 *  Except as expressly stated above, no rights or licenses from any
 *  copyright holder or contributor is granted under this license, whether
 *  expressly, by implication, estoppel or otherwise.
 *
 *  DISCLAIMER
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 */

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>

#define LOG_TAG "platform"

#include "platform.h"
#include "platform_os.h"
#include "platform_interfaces.h"
#include "packet_tools.h"
#include "1905_l2.h"
#include "al_datamodel.h"
#include "al_utils.h"

#include "map_utils.h"
#include "map_config.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define PACKET_SOCKET_TYPE_1905   1
#define PACKET_SOCKET_TYPE_LLDP   2

#define TS_ENABLED_VLAN_PATTERN() (TS_ENABLED() && (strlen(map_cfg_get()->primary_vlan_pattern)>0))

#define xstr(s) str(s)
#define str(s) #s

#define ARP_CACHE       "/proc/net/arp"
#define ARP_STRING_LEN  1023
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)

#define ARP_LINE_FORMAT "%" xstr(ARP_STRING_LEN) "s %*s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s"

#define ZERO_MAC        "00:00:00:00:00:00"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct packet_socket_s {
    list_head_t      list;
    int              fd;
    char             if_name[IFNAMSIZ];
    int              if_index;
    int              type;
    acu_evloop_fd_t *evloop_fd;

    uint32_t         tx_packets;
    uint32_t         rx_packets;
} packet_socket_t;

typedef struct interface_s {
    list_head_t            list;
    char                   if_name[IFNAMSIZ];
    bool                   is_vlan;
    char                   vlan_if_name[IFNAMSIZ]; /* Filled in when !is_vlan */
    i1905_interface_info_t if_info;
} interface_t;

typedef struct netlink_req_s {
	struct nlmsghdr hdr;
	struct rtgenmsg gen;
} netlink_req_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static LIST_HEAD(g_packet_socket_list);
static LIST_HEAD(g_interface_list);

static i1905_packet_cb_t     g_packet_cb;

static int                   g_send_ioctl_fd = -1;

static int                   g_netlink_fd = -1;
static acu_evloop_fd_t      *g_netlink_evloop_fd;

static acu_evloop_timer_t   *g_rt_query_timer      = NULL;

/* Gateway mac. a.k.a DHCP server mac address*/
static mac_addr              g_gateway_mac = {0};

static i1905_interface_cb_t  g_interface_cb;

/*#######################################################################
#                       SOCKET LIST                                     #
########################################################################*/
static char* packet_socket_type_str(int type)
{
    return PACKET_SOCKET_TYPE_1905 == type ? "1905" : "LLDP";
}

static packet_socket_t* packet_socket_list_get(const char* if_name, int type)
{
    packet_socket_t *sock;

    list_for_each_entry(sock, &g_packet_socket_list, list) {
        if (type == sock->type && !strcmp(if_name, sock->if_name)) {
            return sock;
        }
    }

    return NULL;
}

static packet_socket_t *packet_socket_list_add(const char *if_name, int if_index, int fd, int type,
                                               acu_evloop_fd_cb_t cb)
{
    packet_socket_t *sock = calloc(1, sizeof(packet_socket_t));

    if (sock) {
        if (if_name) {
            acu_strlcpy(sock->if_name, if_name, sizeof(sock->if_name));
        }
        sock->if_index = if_index;
        sock->fd       = fd;
        sock->type     = type;
        list_add_tail(&sock->list, &g_packet_socket_list);

        sock->evloop_fd = acu_evloop_fd_add(fd, cb, sock);
        if (NULL == sock->evloop_fd) {
            free(sock);
            sock = NULL;
        }
    }
    return sock;
}

static void packet_socket_list_remove(packet_socket_t *sock)
{
    if (sock->evloop_fd) {
        acu_evloop_fd_delete(sock->evloop_fd);
    }
    if (sock->fd >= 0) {
        close(sock->fd);
    }
    list_del(&sock->list);
    free(sock);
}

/*#######################################################################
#                       SOCKET                                          #
########################################################################*/
static void packet_socket_cb(int fd, void *userdata)
{
    packet_socket_t    *sock = userdata;
    struct sockaddr_ll  recv_addr;
    socklen_t           addr_len = sizeof(recv_addr);
    int                 bytes;
    uint8_t             packet[MAX_NETWORK_SEGMENT_SIZE];

    switch(sock->type) {
        case PACKET_SOCKET_TYPE_1905:
        case PACKET_SOCKET_TYPE_LLDP:
            bytes = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&recv_addr, &addr_len);

            /* TODO: can we really capture outgoing packets here??? */
            if (bytes > 0 && recv_addr.sll_pkttype != PACKET_OUTGOING && g_packet_cb) {
                sock->rx_packets++;
                g_packet_cb(sock->if_name, packet, bytes);
            }
        break;
        default:
            log_i1905_e("unknown socket type %d", sock->type);
        break;
    }
}

static void packet_socket_remove(const char* if_name, int type)
{
    packet_socket_t *sock = packet_socket_list_get(if_name, type);

    if (sock != NULL) {
        log_i1905_d("removing socket ifname[%s] ifdx[%d] type[%s] fd[%d]",
                    if_name, sock->if_index, packet_socket_type_str(type), sock->fd);

        packet_socket_list_remove(sock);
    }
}

static int packet_socket_create(const char *if_name, int if_index, int type)
{
    struct sockaddr_ll  sa;
    struct packet_mreq  mr;
    packet_socket_t    *sock      = NULL;
    uint16_t            ethertype = PACKET_SOCKET_TYPE_1905 == type ? ETHERTYPE_1905 : ETHERTYPE_LLDP;
    uint8_t            *mcast_mac = PACKET_SOCKET_TYPE_1905 == type ? g_mcast_mac_1905 : g_mcast_mac_lldp;
    int                 fd        = -1;
    int                 ret       = -1;
    int                 flags;

    do {
        fd = socket(AF_PACKET, SOCK_RAW, htons(ethertype));
        if (fd < 0) {
            break;
        }

        log_i1905_d("creating socket ifname[%s] ifidx[%d] type[%s] fd[%d]",
                    if_name, if_index, packet_socket_type_str(type), fd);

        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            log_i1905_e("cannot get socket flags (%s)", strerror(errno));
            break;
        }

        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            log_i1905_e("cannot set socket to non-blocking (%s)", strerror(errno));
            break;
        }

        /* Bind to ethertype and interface */
        memset(&sa, 0, sizeof(sa));
        sa.sll_family   = PF_PACKET;
        sa.sll_protocol = htons(ethertype);
        sa.sll_halen    = ETH_ALEN;
        sa.sll_ifindex  = if_index;

        if ((bind(fd, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll))) < 0) {
            log_i1905_e("bind on interface %s failed (%s)", if_name, strerror(errno));
            break;
        }

        /* Set socket to multicast promiscuous mode */
        memset(&mr,0,sizeof(mr));
        mr.mr_ifindex = if_index;
        mr.mr_type    = PACKET_MR_MULTICAST;
        mr.mr_alen    = ETH_ALEN;
        memcpy(mr.mr_address, mcast_mac, ETH_ALEN);
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
            log_i1905_e("setsockopt failed (%s)", strerror(errno));
            break;
        }

        /* Add to socket list */
        sock = packet_socket_list_add(if_name, if_index, fd, type, packet_socket_cb);
        if (NULL == sock) {
            log_i1905_e("packet_socket_list_add failed");
            break;
        }

        ret = 0;
    } while(0);

    if (ret && fd >= 0) {
        close(fd);
        if (sock) {
            sock->fd = -1;
            packet_socket_list_remove(sock);
        }
    }

    return ret;
}

static void packet_sockets_create(const char *if_name, int if_index)
{
    if (!packet_socket_list_get(if_name, PACKET_SOCKET_TYPE_1905)) {
        packet_socket_create(if_name, if_index, PACKET_SOCKET_TYPE_1905);

        /* Notify */
        if (g_interface_cb) {
            g_interface_cb(if_name, true);
        }
    }

    if (!packet_socket_list_get(if_name, PACKET_SOCKET_TYPE_LLDP)) {
        packet_socket_create(if_name, if_index, PACKET_SOCKET_TYPE_LLDP);
    }
}

static void packet_sockets_remove(const char *if_name)
{
    if (packet_socket_list_get(if_name, PACKET_SOCKET_TYPE_1905)) {
        /* Notify */
        if (g_interface_cb) {
            g_interface_cb(if_name, false);
        }

        packet_socket_remove(if_name, PACKET_SOCKET_TYPE_1905);
    }

    if (packet_socket_list_get(if_name, PACKET_SOCKET_TYPE_LLDP)) {
        packet_socket_remove(if_name, PACKET_SOCKET_TYPE_LLDP);
    }
}

/*#######################################################################
#                       INTERFACES                                      #
########################################################################*/
static void get_power_state(const char *if_name, uint8_t *power_state)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    acu_strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

    if (0 == ioctl(g_send_ioctl_fd, SIOCGIFFLAGS, &ifr)) {
        *power_state = (ifr.ifr_flags & IFF_RUNNING) ? INTERFACE_POWER_STATE_ON : INTERFACE_POWER_STATE_OFF;
    } else {
        *power_state = INTERFACE_POWER_STATE_OFF;
        log_i1905_e("could not get interface power state %s", if_name);
    }
}

static void get_mac(const char *if_name, mac_addr mac)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    acu_strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

    if (0 == ioctl(g_send_ioctl_fd, SIOCGIFHWADDR, &ifr)) {
        maccpy(mac, ifr.ifr_addr.sa_data);
    } else {
       log_i1905_e("could not get MAC address for %s",if_name);
    }
}

static int fill_interface_data(const char *if_name, i1905_interface_info_t *info)
{
    char short_model_name[sizeof(info->device_name) - 1 - IFNAMSIZ]; /* To avoid loosing if_name when creating info->device_name */

    map_strlcpy(short_model_name, map_cfg_get()->model_name, sizeof(short_model_name));

    info->neighbor_mac_addresses_nr = INTERFACE_NEIGHBORS_UNKNOWN;
    info->interface_type            = INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;

    /* TODO: is uuid really used? */
    snprintf(info->uuid,              sizeof(info->uuid),              "%s",    "0000000000000000");
    snprintf(info->manufacturer_name, sizeof(info->manufacturer_name), "%s",    map_cfg_get()->manufacturer);
    snprintf(info->model_number,      sizeof(info->model_number),      "%s",    map_cfg_get()->model_number);
    snprintf(info->model_name,        sizeof(info->model_name),        "%s",    map_cfg_get()->model_name);
    snprintf(info->serial_number,     sizeof(info->serial_number),     "%s",    map_cfg_get()->serial_number);
    snprintf(info->device_name,       sizeof(info->device_name),       "%s-%s", short_model_name, if_name);

    if (map_is_loopback_iface(if_name)) {
        info->power_state = INTERFACE_POWER_STATE_ON;
    } else {
        get_mac(if_name, info->mac_address);
        get_power_state(if_name, &info->power_state);
    }
    return 0;
}

static void create_primary_vlan_if_name(char *vlan_if_name, const char *if_name, int len)
{
    const char *pattern     = map_cfg_get()->primary_vlan_pattern;
    int         pvid        = map_cfg_get()->primary_vlan_id;
    int         vid_offset  = map_cfg_get()->vlan_ifname_offset;
    int         pos         = 0;

    while (*pattern && pos < len) {
        if (!strncasecmp(pattern, "${ifname}", 9)) {
            pos += snprintf(&vlan_if_name[pos], len - pos, "%s", if_name);
            pattern += 9;
        } else if (!strncasecmp(pattern, "${pvid}", 7)) {
            pos += snprintf(&vlan_if_name[pos], len - pos, "%d", pvid);
            pattern += 7;
        } else if (!strncasecmp(pattern, "${pvid_with_offset}", 19)) {
            pos += snprintf(&vlan_if_name[pos], len - pos, "%d", pvid+vid_offset);
            pattern += 19;
        } else {
            pos += snprintf(&vlan_if_name[pos], len - pos, "%c", *pattern);
            pattern++;
        }
    }
}

static interface_t *interface_add(const char *if_name, int if_index, bool is_vlan)
{
    interface_t *interface = calloc(1, sizeof(interface_t));

    log_i1905_n("add interface %s%s", if_name, is_vlan ? " [vlan]" : "");

    if (interface) {
        acu_strlcpy(interface->if_name, if_name, sizeof(interface->if_name));

        if (TS_ENABLED_VLAN_PATTERN() && !is_vlan) {
            create_primary_vlan_if_name(interface->vlan_if_name, if_name, sizeof(interface->vlan_if_name));
        }
        interface->is_vlan = is_vlan;

        fill_interface_data(if_name, &interface->if_info);

        interface->if_info.interface_index     = if_index;
        interface->if_info.is_secured          = 1;

        list_add_tail(&interface->list, &g_interface_list);

        /* Add entry in DM */
        if (!DMfindInterface((char*)if_name, interface->if_info.mac_address)) {
            DMinsertInterface((char*)if_name, interface->if_info.mac_address);
        }
    }
    return interface;
}

static interface_t *interface_get(const char *if_name)
{
    interface_t *interface;

    list_for_each_entry(interface, &g_interface_list, list) {
        if (!strcmp(if_name, interface->if_name)) {
            return interface;
        }
    }
    return NULL;
}

/* Get interface belonging to the physical interface name matching with vlan interface name */
static interface_t *interface_get_phys(const char *vlan_if_name)
{
    interface_t *interface;

    list_for_each_entry(interface, &g_interface_list, list) {
        if (!interface->is_vlan && 0 == strcmp(vlan_if_name, interface->vlan_if_name)) {
            return interface;
        }
    }
    return NULL;
}

static void interface_remove(interface_t *interface)
{
    log_i1905_n("remove interface %s", interface->if_name);
    list_del(&interface->list);
    free(interface);
}

static bool interface_match(const char *if_name)
{
    regex_t *regex = map_cfg_get()->interfaces_regex;

    return regex && 0 == regexec(regex, if_name, 0, NULL, 0);
}

/* This assumes that all physical interfaces where already found */
static bool interface_match_vlan(const char *if_name)
{
    interface_t *phys_interface = interface_get_phys(if_name);

    if (phys_interface) {
        /* Loopback can never be vlan... */
        if (!map_is_loopback_iface(if_name) && !map_is_loopback_iface(phys_interface->if_name)) {
            return true;
        }
    }
    return false;
}

/* TODO: Handle STP port state */
static void interface_updated_event(const char* if_name, int if_index, int if_flags, UNUSED uint8_t port_state)
{
    interface_t *interface;
    bool         is_up   = if_flags & IFF_RUNNING;
    bool         is_vlan = false;

    if (false == interface_match(if_name)) {
        if (!TS_ENABLED_VLAN_PATTERN() || false == interface_match_vlan(if_name)) {
            return;
        }
        is_vlan = true;
    }

    interface = interface_get(if_name);
    if (NULL == interface) {
        interface = interface_add(if_name, if_index, is_vlan);
        if (NULL == interface) {
            return;
        }
    }

    /* Update index and state */
    interface->if_info.power_state     = is_up ? INTERFACE_POWER_STATE_ON : INTERFACE_POWER_STATE_OFF;
    interface->if_info.interface_index = if_index;

    /* If TS enabled
       - and vlan updated then remove physical interface
       - ignore updates to physical interface
       TBD: should vlan interface be enabled??
    */
    if (TS_ENABLED_VLAN_PATTERN()) {
        if (is_vlan) {
            interface_t *phys_interface = interface_get_phys(if_name);
            if (phys_interface) {
                packet_sockets_remove(phys_interface->if_name);
            }
        } else {
            if (is_up && interface_get(interface->vlan_if_name)) {
                is_up = false;
            }
        }
    }

    if (is_up) {
        packet_sockets_create(if_name, if_index);
    } else {
        packet_sockets_remove(if_name);
    }
}

static void interface_removed_event(const char* if_name)
{
    interface_t *interface = interface_get(if_name);

    if (interface) {
        packet_sockets_remove(if_name);

        /* If TS enabled and vlan is removed, then add physical interface again. */
        if (TS_ENABLED_VLAN_PATTERN() && interface->is_vlan) {
            interface_t *phys_interface = interface_get(if_name);
            if (phys_interface) {
                if (INTERFACE_POWER_STATE_ON == phys_interface->if_info.power_state) {
                    packet_sockets_create(phys_interface->if_name, phys_interface->if_info.interface_index);
                }
            }
        }
        interface_remove(interface);
    }
}

static int interfaces_init()
{
    struct if_nameindex *if_name_idxs, *intf;
    interface_t         *interface;

    /* Although this socket is used for sending and ioctl only, it must be created with
       a specific protocol (not ETH_P_ALL) to avoid impact on acceleration.
    */
    g_send_ioctl_fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_1905));
    if (g_send_ioctl_fd < 0) {
        log_i1905_e("failed to open raw send socket");
        return -1;
    }

    /* Loop over all interfaces */
    if_name_idxs = if_nameindex();
    if (if_name_idxs != NULL) {
        /* Find all physical interfaces */
        for (intf = if_name_idxs; intf->if_index != 0 && intf->if_name != NULL; intf++) {
            if (interface_match(intf->if_name)) {
                interface_add(intf->if_name, intf->if_index, false);
            }
        }

        /* Add all vlan interfaces that match the primary vlan pattern */
        if (TS_ENABLED_VLAN_PATTERN()) {
            for (intf = if_name_idxs; intf->if_index != 0 && intf->if_name != NULL; intf++) {
                if (interface_match_vlan(intf->if_name)) {
                    interface_add(intf->if_name, intf->if_index, true);
                }
            }
        }

        /* Create sockets */
        list_for_each_entry(interface, &g_interface_list, list) {
            if (TS_ENABLED_VLAN_PATTERN()) {
                /* Skip physical if vlan exists */
                if (!interface->is_vlan && interface_get(interface->vlan_if_name)) {
                    continue;
                }
            }

            /* Create sockets if interface is enabled. */
            if (INTERFACE_POWER_STATE_ON == interface->if_info.power_state) {
                packet_sockets_create(interface->if_name, interface->if_info.interface_index);
            }
        }

        if_freenameindex(if_name_idxs);
    }

    return 0;
}

static void interfaces_fini(void)
{
    interface_t *interface, *next;

    list_for_each_entry_safe(interface, next, &g_interface_list, list) {
        packet_sockets_remove(interface->if_name);
        interface_remove(interface);
    }

    if (g_send_ioctl_fd > 0) {
        close(g_send_ioctl_fd);
    }
}
/*#######################################################################
#                       ROUTE                                           #
########################################################################*/
static int route_get_arp_entry (char *ip, size_t ip_len, char *mac, int mac_len)
{
    FILE *arp_table;

    char header[ARP_BUFFER_LEN];
    char ip_addr[ARP_BUFFER_LEN];
    char hw_addr[ARP_BUFFER_LEN];
    char device[ARP_BUFFER_LEN];

    arp_table = NULL;

    if (ip == NULL) {
        goto bail;
    }
    if (mac == NULL) {
        goto bail;
    }

    arp_table = fopen(ARP_CACHE, "r");
    if (arp_table == NULL) {
        goto bail;
    }

    if (!fgets(header, sizeof(header), arp_table)) {
        goto bail;
    }

    while (fscanf(arp_table, ARP_LINE_FORMAT, ip_addr, hw_addr, device) == 3) {
        if (strcasecmp(ip_addr, ip) == 0 && strlen(ip_addr) == ip_len) {
            if (strncasecmp(hw_addr, ZERO_MAC, mac_len) != 0) {
                int ret = snprintf(mac, mac_len, "%s", hw_addr);
                if (ret >= mac_len) {
                    log_i1905_e("mac too long [%d]", ret);
                    goto bail;
                }
                fclose(arp_table);
                return 0;
            }
        }
    }

bail:
    if (arp_table != NULL) {
        fclose(arp_table);
    }
    return -1;
}

static void periodic_nl_route_query_cb(void *userdata)
{
    (void) userdata;

    struct sockaddr_nl kernel;
    struct msghdr rtnl_msg;
    struct iovec io;
    netlink_req_t req;

    memset(&rtnl_msg, 0, sizeof(rtnl_msg));
    memset(&kernel, 0, sizeof(kernel));
    memset(&req, 0, sizeof(req));

    kernel.nl_family = AF_NETLINK;
    kernel.nl_groups = 0;

    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.hdr.nlmsg_type = RTM_GETROUTE;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.hdr.nlmsg_pid = getpid();
    req.gen.rtgen_family = AF_INET;

    io.iov_base = &req;
    io.iov_len = req.hdr.nlmsg_len;
    rtnl_msg.msg_iov = &io;
    rtnl_msg.msg_iovlen = 1;
    rtnl_msg.msg_name = &kernel;
    rtnl_msg.msg_namelen = sizeof(kernel);

    if (sendmsg(g_netlink_fd, (struct msghdr *) &rtnl_msg, 0) < 0) {
        log_i1905_e("sendmsg() failed:");
    }

}

static int route_init()
{
    g_rt_query_timer = acu_evloop_timer_add(0, 10000, periodic_nl_route_query_cb, NULL);
    if (NULL == g_rt_query_timer) {
        return -1;
    }

    return 0;
}

static void route_fini()
{
    if (g_rt_query_timer) {
        acu_evloop_timer_delete(g_rt_query_timer);
    }
}
/*#######################################################################
#                       NETLINK                                         #
########################################################################*/
static void parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta, int len,
                               unsigned short flags)
{
    unsigned short type;

    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        type = rta->rta_type & ~flags;
        if (type <= max) {
            tb[type] = rta;
        }
        rta = RTA_NEXT(rta, len);
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
static void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    parse_rtattr_flags(tb, max, rta, len, 0);
}

static void parse_nested_rtattr(struct rtattr *tb[], int max, struct rtattr *rta)
{
    parse_rtattr(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0) */

static void parse_if_info_state(struct nlmsghdr *h, struct ifinfomsg *ifi, char *if_name, size_t if_name_len, uint8_t* port_state)
{
    struct rtattr *ifla[__IFLA_MAX];

    parse_rtattr_flags(ifla, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(h), 1<<15);

    /* get interface name */
    if (ifla[IFLA_IFNAME]) {
        acu_strlcpy(if_name, RTA_DATA(ifla[IFLA_IFNAME]), if_name_len);
    }

/* Getting bridge port state is only supported from kernel 3.8.0.
   NOTE: we are not using the port state yet.  Should be done when
         STP can block ports on the device controller is running on??
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
    /* get brige port state from interface protocol information */
    if (ifla[IFLA_PROTINFO]) {
        struct rtattr *brp[__IFLA_BRPORT_MAX];
        parse_nested_rtattr(brp, IFLA_BRPORT_MAX, ifla[IFLA_PROTINFO]);
        if(brp[IFLA_BRPORT_STATE]) {
            *port_state = *((uint8_t *)RTA_DATA(brp[IFLA_BRPORT_STATE]));
        }
    }
#else
    *port_state = INTERFACE_PORT_STATE_FORWARDING;
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0) */
}

static void netlink_event_newlink(struct nlmsghdr *h, size_t len)
{
    struct ifinfomsg *ifi;
    char              if_name[IFNAMSIZ] = { 0 };
    uint8_t           port_state = 0;

    if (len < sizeof(*ifi)) {
        return;
    }

    if (NULL == (ifi = NLMSG_DATA(h))) {
        log_i1905_e("netlink: header contains no data");
        return;
    }

    parse_if_info_state(h, ifi, if_name, sizeof(if_name), &port_state);

    interface_updated_event(if_name, ifi->ifi_index, ifi->ifi_flags, port_state);
}

static void netlink_event_dellink(struct nlmsghdr *h, size_t len)
{
    struct ifinfomsg *ifi;
    char              if_name[IFNAMSIZ] = { 0 };
    uint8_t           port_state = 0;

    if (len < sizeof(*ifi)) {
        return;
    }

    if (NULL == (ifi = NLMSG_DATA(h))) {
        log_i1905_e("netlink: header contains no data");
        return;
    }

    parse_if_info_state(h, ifi, if_name, sizeof(if_name), &port_state);

    interface_removed_event(if_name);
}

static void netlink_event_newroute(struct nlmsghdr *h, size_t len)
{
    int rc = 0;
    struct rtmsg *rtmsg;
    struct rtattr *rtattr[__RTA_MAX];
    char gw_ip[32] = {0};
    char gw_mac_str[32];

    if (len < sizeof(*rtmsg)) {
        return;
    }

    if (NULL == (rtmsg = NLMSG_DATA(h))) {
        log_i1905_e("netlink: header contains no data");
        return;
    }

    parse_rtattr_flags(rtattr, RTA_MAX, RTM_RTA(rtmsg), RTM_PAYLOAD(h), 0);

    if (rtattr[RTA_GATEWAY]) {
        inet_ntop(AF_INET, RTA_DATA(rtattr[RTA_GATEWAY]), gw_ip, sizeof(gw_ip));
        if(strlen(gw_ip) > 0) {
            rc = route_get_arp_entry(gw_ip, strlen(gw_ip), gw_mac_str, sizeof(gw_mac_str));
            if (!rc) {
                log_i1905_d("gateway: default ip: %s mac: %s", gw_ip, gw_mac_str);
                mac_from_string(gw_mac_str, g_gateway_mac);
            } else {
                log_i1905_e("can not get mac entry for %s", gw_ip);
            }
        }
    }

}

static void netlink_socket_cb(int fd, UNUSED void *userdata)
{
    char             buf[8192];
    int              left;
    struct nlmsghdr *h;

    left = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (left < 0) {
        if (errno != EINTR && errno != EAGAIN) {
            log_i1905_e("netlink: recv failed");
        }
        return;
    }

    h = (struct nlmsghdr *) buf;
    while (left >= (int) sizeof(*h)) {
        int len, plen;

        len = h->nlmsg_len;
        plen = len - sizeof(*h);
        if (len > left || plen < 0) {
            log_i1905_e("netlink: malformed message: len=%d left=%d plen=%d",
                        len, left, plen);
            break;
        }

        switch (h->nlmsg_type) {
            case RTM_NEWLINK:
                netlink_event_newlink(h, plen);
            break;
            case RTM_DELLINK:
                netlink_event_dellink(h, plen);
            break;
            case RTM_NEWROUTE:
                netlink_event_newroute(h, plen);
            break;
            default:
            break;
        }

        len = NLMSG_ALIGN(len);
        left -= len;
        h = (struct nlmsghdr *) ((char *) h + len);
    }

    if (left > 0) {
        log_i1905_e("netlink: %d extra bytes in the end of netlink message", left);
    }
}

static int netlink_init(void)
{
    struct sockaddr_nl local;
    int                fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        log_i1905_e("could not create netlink socket");
        return -1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK;
    if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0) {
        log_i1905_e("could not bind netlink socket");
        close(fd);
        return -1;
    }

    g_netlink_evloop_fd = acu_evloop_fd_add(fd, netlink_socket_cb, NULL);
    if (NULL == g_netlink_evloop_fd) {
        log_i1905_e("failed register netlink socket");
        return -1;
    }

    g_netlink_fd = fd;

    return 0;
}

static void netlink_fini()
{
    if (g_netlink_evloop_fd) {
        acu_evloop_fd_delete(g_netlink_evloop_fd);
    }

    if (g_netlink_fd >= 0) {
        close(g_netlink_fd);
    }
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void PLATFORM_OS_DUMP_INTERFACES(map_printf_cb_t print_cb)
{
    interface_t     *interface;
    packet_socket_t *sock;
    mac_addr_str     mac_str;

    print_cb("Interfaces:\n");
    list_for_each_entry(interface, &g_interface_list, list) {
        acu_mac_to_string(interface->if_info.mac_address, mac_str);
        print_cb("  ifname[%s] ifidx[%d] mac[%s] state[%d] vlan[%d]\n",
                 interface->if_name, interface->if_info.interface_index, mac_str,
                 interface->if_info.power_state == INTERFACE_POWER_STATE_ON ? 1 : 0,
                 interface->is_vlan ? 1 : 0);
    }

    print_cb("\nSockets:\n");
    list_for_each_entry(sock, &g_packet_socket_list, list) {
        print_cb("  ifname[%s] ifidx[%d] type[%s] fd[%d] txp[%"PRIu32"] rxp[%"PRIu32"]\n",
                 sock->if_name, sock->if_index,
                 packet_socket_type_str(sock->type),
                 sock->fd, sock->tx_packets, sock->rx_packets);
    }
}

char **PLATFORM_OS_GET_LIST_OF_1905_INTERFACES(uint8_t *nr)
{
    interface_t *interface;
    char        **interfaces;
    char         *p;
    int           count = 0;
    int           idx = 0;

    /* Count interfaces: all enabled interfaces, for TS, do not add physical interface
       if there is a primary vlan.
    */
    list_for_each_entry(interface, &g_interface_list, list) {
        if ((INTERFACE_POWER_STATE_ON != interface->if_info.power_state) ||
            (TS_ENABLED_VLAN_PATTERN() && !interface->is_vlan && interface_get(interface->vlan_if_name))) {
            continue;
        }
        count++;
    }

    /* Allocate memory for both char** and if names */
    if ((interfaces = malloc(count * (sizeof(char**) + IFNAMSIZ) + 1))) { /* + 1 to avoid malloc(0) */
        p = (char*) interfaces;
        p += count * sizeof(char**);
        list_for_each_entry(interface, &g_interface_list, list) {
            if ((INTERFACE_POWER_STATE_ON != interface->if_info.power_state) ||
                (TS_ENABLED_VLAN_PATTERN() && !interface->is_vlan && interface_get(interface->vlan_if_name))) {
                continue;
            }
            interfaces[idx] = p;
            acu_strlcpy(p, interface->if_name, IFNAMSIZ);
            idx++;
            p += IFNAMSIZ;

        }
    }

    *nr = idx;
    return interfaces;
}

void PLATFORM_OS_FREE_LIST_OF_1905_INTERFACES(char **interfaces, UNUSED uint8_t nr)
{
    free(interfaces);
}

void PLATFORM_OS_GET_1905_INTERFACE_INFO(char *if_name, i1905_interface_info_t *info)
{
    interface_t *interface = interface_get(if_name);

    if (interface) {
        *info = interface->if_info;
    }
}

bool PLATFORM_OS_IS_INTERFACE_UP(char *if_name)
{
    interface_t *interface = interface_get(if_name);

    return interface &&
           interface->if_info.power_state == INTERFACE_POWER_STATE_ON &&
            interface->if_info.interface_index > 0;
}

int PLATFORM_OS_GET_IFINDEX(char *if_name)
{
    interface_t *interface = interface_get(if_name);

    return interface ? interface->if_info.interface_index : -1;
}

void PLATFORM_OS_PACKET_SENT(char *if_name, uint16_t ether_type)
{
    packet_socket_t *sock = NULL;

    if (ETHERTYPE_1905 == ether_type) {
        sock = packet_socket_list_get(if_name, PACKET_SOCKET_TYPE_1905);
    } else if (ETHERTYPE_LLDP == ether_type) {
        sock = packet_socket_list_get(if_name, PACKET_SOCKET_TYPE_LLDP);
    }

    if (sock) {
        sock->tx_packets++;
    }
}

int PLATFORM_OS_GET_RAW_SEND_FD(void)
{
    return g_send_ioctl_fd;
}

bool PLATFORM_OS_LOG_LEVEL_TRACE(void)
{
    return map_cfg_get()->ieee1905_log_level >= LOG_TRACE;
}

mac_addr* PLATFORM_OS_GET_GATEWAY_MAC(void)
{
    return &g_gateway_mac;
}

uint8_t PLATFORM_OS_INIT(i1905_interface_cb_t interface_cb, i1905_packet_cb_t packet_cb)
{
    g_interface_cb = interface_cb;
    g_packet_cb = packet_cb;

    if (netlink_init()) {
        return 0;
    }

    if (interfaces_init()) {
        return 0;
    }

    if (route_init()) {
        return 0;
    }

    return 1;
}

void PLATFORM_OS_FINI(void)
{
    netlink_fini();
    interfaces_fini();
    route_fini();
}
