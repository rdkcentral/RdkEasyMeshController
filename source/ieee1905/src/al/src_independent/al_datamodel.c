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
#include "platform.h"
#include "utils.h"

#include "al_datamodel.h"
#include "al_utils.h"

#include "1905_tlvs.h"
#include "1905_cmdus.h"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
struct _dataModel
{
    uint8_t            map_whole_network_flag;

    uint8_t            registrar_mac_address[6];

    uint8_t            al_mac_address[6];
    uint8_t            local_interfaces_nr;

    struct _localInterface  {
        char               *name;
        uint8_t             mac_address[6];

        uint8_t             neighbors_nr;

        struct _neighbor {
            uint8_t             al_mac_address[6];
            uint8_t             remote_interfaces_nr;

            struct _remoteInterface {
                uint8_t             mac_address[6];
                uint64_t            last_topology_discovery_ts;
                uint64_t            last_bridge_discovery_ts;

            }                  *remote_interfaces;

        }                  *neighbors;

    }                 *local_interfaces;

    uint8_t        network_devices_nr;

    struct _networkDevice {
            uint64_t                                    update_timestamp;

            struct deviceInformationTypeTLV            *info;

            uint8_t                                     bridges_nr;
            struct deviceBridgingCapabilityTLV        **bridges;

            uint8_t                                     non1905_neighbors_nr;
            struct non1905NeighborDeviceListTLV       **non1905_neighbors;

            uint8_t                                     x1905_neighbors_nr;
            struct neighborDeviceListTLV              **x1905_neighbors;

            uint8_t                                     power_off_nr;
            struct powerOffInterfaceTLV               **power_off;

            uint8_t                                     l2_neighbors_nr;
            struct l2NeighborDeviceTLV                **l2_neighbors;

            struct genericPhyDeviceInformationTypeTLV  *generic_phy;

            struct x1905ProfileVersionTLV              *profile;

            struct deviceIdentificationTypeTLV         *identification;

            struct controlUrlTypeTLV                   *control_url;

            struct ipv4TypeTLV                         *ipv4;

            struct ipv6TypeTLV                         *ipv6;

            uint8_t                                     metrics_with_neighbors_nr;
            struct _metricsWithNeighbor {
                uint8_t                                     neighbor_al_mac_address[6];

                uint64_t                                    tx_metrics_timestamp;
                struct transmitterLinkMetricTLV            *tx_metrics;

                uint64_t                                    rx_metrics_timestamp;
                struct receiverLinkMetricTLV               *rx_metrics;

            }                                          *metrics_with_neighbors;

            uint8_t                                     extensions_nr;
            struct vendorSpecificTLV                  **extensions;

    }                 *network_devices;
                         /* This list will always contain at least ONE entry,
                         *  containing the info of the *local* device.
                         */
} data_model;

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
/* Given a 'mac_address', return a pointer to the "struct _localInterface" that
*  represents the local interface with that address.
*  Returns NONE if such a local interface could not be found.
*/
static struct _localInterface *_macAddressToLocalInterfaceStruct(uint8_t *mac_address)
{
    uint8_t i;

    if (NULL != mac_address) {
        for (i=0; i<data_model.local_interfaces_nr; i++) {
            if (0 == memcmp(data_model.local_interfaces[i].mac_address, mac_address, 6)) {
                return &data_model.local_interfaces[i];
            }
        }
    }

    /* Not found! */
    return NULL;
}

/* Given a 'name', return a pointer to the "struct _localInterface" that
*  represents the local interface with that interface name.
*  Returns NONE if such a local interface could not be found.
*/
static struct _localInterface *_nameToLocalInterfaceStruct(char *name)
{
    uint8_t i;

    if (NULL != name) {
        for (i=0; i<data_model.local_interfaces_nr; i++) {
            if (0 == memcmp(data_model.local_interfaces[i].name, name, strlen(data_model.local_interfaces[i].name)+1)) {
                return &data_model.local_interfaces[i];
            }
        }
    }

    /* Not found! */
    return NULL;
}

/* Given an 'al_mac_address', return a pointer to the "struct _neighbor" that
*  represents a 1905 neighbor with that 'al_mac_address' visible from the
*  provided 'local_interface_name'.
*  Returns NONE if such a neighbor could not be found.
*/
static struct _neighbor *_alMacAddressToNeighborStruct(char *local_interface_name, uint8_t *al_mac_address)
{
    uint8_t i;

    struct _localInterface *x;

    if (NULL == (x = _nameToLocalInterfaceStruct(local_interface_name))) {
        /* Non existent interface */
        return NULL;
    }

    if (NULL != al_mac_address) {
        for (i=0; i<x->neighbors_nr; i++) {
            if (0 == memcmp(x->neighbors[i].al_mac_address, al_mac_address, 6)) {
                return &x->neighbors[i];
            }
        }
    }

    /* Not found! */
    return NULL;
}

/* Given a 'mac_address', return a pointer to the "struct _remoteInterface" that
*  represents an interface in the provided 1905 neighbor (identified by its
*  'neighbor_al_mac_address' and visible in 'local_interface) that contains that
*  address.
*  Returns NONE if such a remote interface could not be found.
*/
static struct _remoteInterface *_macAddressToRemoteInterfaceStruct(char *local_interface_name, uint8_t *neighbor_al_mac_address, uint8_t *mac_address)
{
    uint8_t i;

    struct _neighbor *x;

    if (NULL == (x = _alMacAddressToNeighborStruct(local_interface_name, neighbor_al_mac_address))) {
        /* Non existent neighbor */
        return NULL;
    }

    if (NULL != mac_address) {
        for (i=0; i<x->remote_interfaces_nr; i++) {
            if (0 == memcmp(x->remote_interfaces[i].mac_address, mac_address, 6)) {
                return &x->remote_interfaces[i];
            }
        }
    }

    /* Not found! */
    return NULL;
}

/* When a new 1905 neighbor is discovered on a local interface, this function
*  must be called to update the database.
*  Returns '0' if there was a problem (out of memory, etc...), '2' if the
*  neighbor had already been inserted, '1' if the new neighbor was succesfully
*  inserted.
*/
static uint8_t _insertNeighbor(char *local_interface_name, uint8_t *al_mac_address)
{
    struct _localInterface *x;

    /* First, make sure the interface exists */
    if (NULL == (x = _nameToLocalInterfaceStruct(local_interface_name))) {
        return 0;
    }

    /* Next, make sure this neighbor does not already exist */
    if (NULL != _alMacAddressToNeighborStruct(local_interface_name, al_mac_address)) {
        /* The neighbor exists! We don't need to do anything special. */
        return 2;
    }

    if (0 == x->neighbors_nr) {
        x->neighbors = malloc(sizeof (struct _neighbor));
        if (!x->neighbors) {
            return 0;
        }
    } else {
        struct _neighbor *p;

        p = realloc(x->neighbors, sizeof (struct _neighbor) * (x->neighbors_nr + 1));
        if (!p) {
            return 0;
        }
        x->neighbors = p;
    }

    memcpy(x->neighbors[x->neighbors_nr].al_mac_address, al_mac_address, 6);
    x->neighbors[x->neighbors_nr].remote_interfaces_nr = 0;
    x->neighbors[x->neighbors_nr].remote_interfaces    = NULL;

    x->neighbors_nr++;

    return 1;
}

/* When a new interface of a 1905 neighbor is discovered, this function must be
*  called to update the database.
*  Returns '0' if there was a problem (out of memory, etc...), '2' if the
*  neighbor interface had already been inserted, '1' if the new neighbor
*  interface was successfully inserted.
*/
static uint8_t _insertNeighborInterface(char *local_interface_name, uint8_t *neighbor_al_mac_address, uint8_t *mac_address)
{
    struct _neighbor        *x;

    /* First, make sure the interface and neighbor exist */
    if (NULL == (x = _alMacAddressToNeighborStruct(local_interface_name, neighbor_al_mac_address))) {
        return 0;
    }

    /* Next, make sure this neighbor interface does not already exist */
    if (NULL != _macAddressToRemoteInterfaceStruct(local_interface_name, neighbor_al_mac_address, mac_address))  {
        /* The neighbor exists! We don't need to do anything special. */
        return 2;
    }

    if (0 == x->remote_interfaces_nr) {
        x->remote_interfaces = malloc(sizeof (struct _remoteInterface));
        if (!x->remote_interfaces) {
            return 0;
        }
    } else {
        struct _remoteInterface *p;
        
        p = realloc(x->remote_interfaces, sizeof (struct _remoteInterface) * (x->remote_interfaces_nr + 1));
        if (!p) {
            return 0;
        }        
        x->remote_interfaces = p;
    }

    memcpy(x->remote_interfaces[x->remote_interfaces_nr].mac_address, mac_address, 6);
    x->remote_interfaces[x->remote_interfaces_nr].last_topology_discovery_ts = 0;
    x->remote_interfaces[x->remote_interfaces_nr].last_bridge_discovery_ts   = 0;

    x->remote_interfaces_nr++;

    return 1;
}

static int8_t _runGarbageCollector(bool remove_all)
{
    uint8_t i, j, k;
    uint8_t removed_entries = 0;
    uint8_t original_devices_nr;

    /* Visit all existing devices, searching for those with a timestamp older
    *  than GC_MAX_AGE
    *
    *  Note that we skip element "0", which is always the local device. We don't
    *  care when it was last updated as it is always updated "on demand", just
    *  before someone requests its data (right now the only place where this
    *  happens is when using an ALME custom command)
    */

    original_devices_nr = data_model.network_devices_nr;
    for (i = remove_all ? 0 : 1; i<data_model.network_devices_nr; i++) {
        uint8_t *p = NULL;

        if (remove_all || (PLATFORM_GET_TIMESTAMP() - data_model.network_devices[i].update_timestamp > (GC_MAX_AGE*1000)) ||
            (NULL != data_model.network_devices[i].info && NULL == (p = DMmacToAlMac(data_model.network_devices[i].info->al_mac_address))))
        {
            /* Entry too old or with a MAC address no longer registered in the
            *  "topology discovery" database. Remove it.
            */
            uint8_t  al_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            struct _networkDevice *x;

            removed_entries++;

            x = &data_model.network_devices[i];

            /* First, free all child structures */
            if (NULL != x->info) {
                /* Save the MAC of the node that is going to be removed for later use */
                memcpy(al_mac_address, x->info->al_mac_address, 6);

                log_i1905_d("Removing old device entry (%02x:%02x:%02x:%02x:%02x:%02x)", x->info->al_mac_address[0], x->info->al_mac_address[1], x->info->al_mac_address[2], x->info->al_mac_address[3], x->info->al_mac_address[4], x->info->al_mac_address[5]);
                free_1905_TLV_structure((uint8_t*)x->info);
                x->info = NULL;
            } else {
                log_i1905_w("Removing old device entry (Unknown AL MAC)");
            }

            for (j=0; j<x->bridges_nr; j++) {
                free_1905_TLV_structure((uint8_t*)x->bridges[j]);
            }
            if (0 != x->bridges_nr && NULL != x->bridges) {
                free(x->bridges);
                x->bridges_nr = 0;
                x->bridges    = NULL;
            }

            for (j=0; j<x->non1905_neighbors_nr; j++) {
                free_1905_TLV_structure((uint8_t*)x->non1905_neighbors[j]);
            }
            if (0 != x->non1905_neighbors_nr && NULL != x->non1905_neighbors) {
                free(x->non1905_neighbors);
                x->non1905_neighbors_nr = 0;
                x->non1905_neighbors    = NULL;
            }

            for (j=0; j<x->x1905_neighbors_nr; j++) {
                free_1905_TLV_structure((uint8_t*)x->x1905_neighbors[j]);
            }
            if (0 != x->x1905_neighbors_nr && NULL != x->x1905_neighbors) {
                free(x->x1905_neighbors);
                x->x1905_neighbors_nr = 0;
                x->x1905_neighbors    = NULL;
            }

            for (j=0; j<x->power_off_nr; j++) {
                free_1905_TLV_structure((uint8_t*)x->power_off[j]);
            }
            if (0 != x->power_off_nr && NULL != x->power_off) {
                free(x->power_off);
                x->power_off_nr = 0;
                x->power_off    = NULL;
            }

            for (j=0; j<x->l2_neighbors_nr; j++) {
                free_1905_TLV_structure((uint8_t*)x->l2_neighbors[j]);
            }
            if (0 != x->l2_neighbors_nr && NULL != x->l2_neighbors) {
                free(x->l2_neighbors);
                x->l2_neighbors_nr = 0;
                x->l2_neighbors    = NULL;
            }

            if (NULL != x->generic_phy) {
                free_1905_TLV_structure((uint8_t*)x->generic_phy);
                x->generic_phy = NULL;
            }

            if (NULL != x->profile) {
                free_1905_TLV_structure((uint8_t*)x->profile);
                x->profile = NULL;
            }

            if (NULL != x->identification) {
                free_1905_TLV_structure((uint8_t*)x->identification);
                x->identification = NULL;
            }

            if (NULL != x->control_url) {
                free_1905_TLV_structure((uint8_t*)x->control_url);
                x->control_url = NULL;
            }

            if (NULL != x->ipv4) {
                free_1905_TLV_structure((uint8_t*)x->ipv4);
                x->ipv4 = NULL;
            }

            if (NULL != x->ipv6) {
                free_1905_TLV_structure((uint8_t*)x->ipv6);
                x->ipv6 = NULL;
            }

            for (j=0; j<x->metrics_with_neighbors_nr; j++) {
                free_1905_TLV_structure((uint8_t*)x->metrics_with_neighbors[j].tx_metrics);
                free_1905_TLV_structure((uint8_t*)x->metrics_with_neighbors[j].rx_metrics);
            }
            if (0 != x->metrics_with_neighbors_nr && NULL != x->metrics_with_neighbors) {
                free(x->metrics_with_neighbors);
                x->metrics_with_neighbors = NULL;
            }

            /* Next, remove the _networkDevice entry */
            if (i == (data_model.network_devices_nr-1)) {
                /* Last element. It will automatically be removed below (keep reading) */
            } else {
                /* Place the last element here (we don't care about preserving order) */
                data_model.network_devices[i] = data_model.network_devices[data_model.network_devices_nr-1];
                i--;
            }
            data_model.network_devices_nr--;

            /* Next, Remove all references to this node from other node's
            *  metrics information entries
            */
            for (j=0; j<data_model.network_devices_nr; j++) {
                uint8_t original_neighbors_nr;

                original_neighbors_nr = data_model.network_devices[j].metrics_with_neighbors_nr;

                for (k=0; k<data_model.network_devices[j].metrics_with_neighbors_nr; k++) {
                    if (0 == memcmp(al_mac_address, data_model.network_devices[j].metrics_with_neighbors[k].neighbor_al_mac_address, 6)) {
                        free_1905_TLV_structure((uint8_t*)data_model.network_devices[j].metrics_with_neighbors[k].tx_metrics);
                        free_1905_TLV_structure((uint8_t*)data_model.network_devices[j].metrics_with_neighbors[k].rx_metrics);

                        /* Place last element here (we don't care about preserving order) */
                        if (k == (data_model.network_devices[j].metrics_with_neighbors_nr-1)) {
                            /* Last element. It will automatically be removed below (keep reading) */
                        } else {
                            data_model.network_devices[j].metrics_with_neighbors[k] = data_model.network_devices[j].metrics_with_neighbors[data_model.network_devices[j].metrics_with_neighbors_nr-1];
                            k--;
                        }
                        data_model.network_devices[j].metrics_with_neighbors_nr--;
                    }
                }

                if (original_neighbors_nr != data_model.network_devices[j].metrics_with_neighbors_nr) {
                    if (0 == data_model.network_devices[j].metrics_with_neighbors_nr) {
                        free(data_model.network_devices[j].metrics_with_neighbors);
                    } else {
                        data_model.network_devices[j].metrics_with_neighbors = (struct _metricsWithNeighbor *)realloc(data_model.network_devices[j].metrics_with_neighbors, sizeof(struct _metricsWithNeighbor)*(data_model.network_devices[j].metrics_with_neighbors_nr));
                    }
                }
            }

            /* And also from the local interfaces database */
            DMremoveALNeighborFromInterface(al_mac_address, "all");
        }

        free(p);
    }

    /* If at least one element was removed, we need to realloc */
    if (original_devices_nr != data_model.network_devices_nr) {
        if (0 == data_model.network_devices_nr) {
            free(data_model.network_devices);
        } else {
            data_model.network_devices = (struct _networkDevice *)realloc(data_model.network_devices, sizeof(struct _networkDevice)*(data_model.network_devices_nr));
        }
    }

    return removed_entries;
}

/*#######################################################################
#                       GLOBAL FUNCTIONS                                #
########################################################################*/
void DMinit()
{
    data_model.map_whole_network_flag   = 0;

    data_model.registrar_mac_address[0] = 0x00;
    data_model.registrar_mac_address[1] = 0x00;
    data_model.registrar_mac_address[2] = 0x00;
    data_model.registrar_mac_address[3] = 0x00;
    data_model.registrar_mac_address[4] = 0x00;
    data_model.registrar_mac_address[5] = 0x00;

    data_model.al_mac_address[0]        = 0x00;
    data_model.al_mac_address[1]        = 0x00;
    data_model.al_mac_address[2]        = 0x00;
    data_model.al_mac_address[3]        = 0x00;
    data_model.al_mac_address[4]        = 0x00;
    data_model.al_mac_address[5]        = 0x00;

    data_model.local_interfaces_nr      = 0;
    data_model.local_interfaces         = NULL;

    /* Regarding the "network_devices" list, we will init it with one element,
    *  representing the local node
    */
    data_model.network_devices_nr       = 1;
    data_model.network_devices          = malloc(sizeof(struct _networkDevice));

    data_model.network_devices[0].update_timestamp          = PLATFORM_GET_TIMESTAMP();
    data_model.network_devices[0].info                      = NULL;
    data_model.network_devices[0].bridges_nr                = 0;
    data_model.network_devices[0].bridges                   = NULL;
    data_model.network_devices[0].non1905_neighbors_nr      = 0;
    data_model.network_devices[0].non1905_neighbors         = NULL;
    data_model.network_devices[0].x1905_neighbors_nr        = 0;
    data_model.network_devices[0].x1905_neighbors           = NULL;
    data_model.network_devices[0].power_off_nr              = 0;
    data_model.network_devices[0].power_off                 = NULL;
    data_model.network_devices[0].l2_neighbors_nr           = 0;
    data_model.network_devices[0].l2_neighbors              = NULL;
    data_model.network_devices[0].generic_phy               = NULL;
    data_model.network_devices[0].profile                   = NULL;
    data_model.network_devices[0].identification            = NULL;
    data_model.network_devices[0].control_url               = NULL;
    data_model.network_devices[0].ipv4                      = NULL;
    data_model.network_devices[0].ipv6                      = NULL;
    data_model.network_devices[0].metrics_with_neighbors_nr = 0;
    data_model.network_devices[0].metrics_with_neighbors    = NULL;
    data_model.network_devices[0].extensions                = NULL;
    data_model.network_devices[0].extensions_nr             = 0;
}

void DMfini(void)
{
    size_t i, j;

    /* Remove network devices */
    _runGarbageCollector(true);

    /* Remove local interfaces */
    for (i = 0; i < data_model.local_interfaces_nr; i++) {
        free(data_model.local_interfaces[i].name);
        for (j = 0; j < data_model.local_interfaces[i].neighbors_nr; j++) {
            free(data_model.local_interfaces[i].neighbors[j].remote_interfaces);
        }
        free(data_model.local_interfaces[i].neighbors);
    }

    free(data_model.local_interfaces);
}

void DMalMacSet(uint8_t *al_mac_address)
{
    memcpy(data_model.al_mac_address, al_mac_address, 6);
}

uint8_t *DMalMacGet()
{
    return data_model.al_mac_address;
}

void DMregistrarMacSet(uint8_t *registrar_mac_address)
{
    memcpy(data_model.registrar_mac_address, registrar_mac_address, 6);
}

uint8_t *DMregistrarMacGet()
{
    return data_model.registrar_mac_address;
}

void DMmapWholeNetworkSet(uint8_t map_whole_network_flag)
{
    data_model.map_whole_network_flag =  map_whole_network_flag;
}

uint8_t DMmapWholeNetworkGet()
{
    return data_model.map_whole_network_flag;
}

uint8_t DMfindInterface(char *name, uint8_t *mac_address)
{
    struct _localInterface *x;

    /* First, make sure this interface does not already exist */
    if (NULL != (x = _nameToLocalInterfaceStruct(name))) {
        /* The interface exists!
        *
        *  Even if it already exists, if the provided 'mac_address' and the
        *  already existing entry match, do not return an error.
        */
        if (0 == memcmp(x->mac_address, mac_address, 6)) {
            /* Ok */
            return 1;
        }
    }
    return 0;
}

uint8_t DMinsertInterface(char *name, uint8_t *mac_address)
{
    struct _localInterface *x;

    /* First, make sure this interface does not already exist */
    if (NULL != (x = _nameToLocalInterfaceStruct(name))) {
        /* The interface exists!
        *
        *  Even if it already exists, if the provided 'mac_address' and the
        *  already existing entry match, do not return an error.
        */
        if (0 == memcmp(x->mac_address, mac_address, 6)) {
            /* Ok */
            return 1;
        } else {
            /* Interface exists and its MAC address is different from the
            *  provided one. Maybe the caller should first "remove" this
            *  interface and then try to add the new one.
            */
            return 0;
        }
    }

    if (0 == data_model.local_interfaces_nr) {
        data_model.local_interfaces = malloc(sizeof (struct _localInterface));

    } else {
        data_model.local_interfaces = realloc(data_model.local_interfaces, sizeof (struct _localInterface) * (data_model.local_interfaces_nr + 1));
    }

    data_model.local_interfaces[data_model.local_interfaces_nr].name = strdup(name);
    memcpy(data_model.local_interfaces[data_model.local_interfaces_nr].mac_address, mac_address, 6);
    data_model.local_interfaces[data_model.local_interfaces_nr].neighbors    = NULL;
    data_model.local_interfaces[data_model.local_interfaces_nr].neighbors_nr = 0;

    data_model.local_interfaces_nr++;

    return 1;
}

char *DMmacToInterfaceName(uint8_t *mac_address)
{
    struct _localInterface *x;

    x = _macAddressToLocalInterfaceStruct(mac_address);

    return x ? x->name : NULL;
}

uint8_t *DMinterfaceNameToMac(char *interface_name)
{
    uint8_t i;

    if (NULL != interface_name) {
        for (i=0; i<data_model.local_interfaces_nr; i++) {
            if (0 == memcmp(data_model.local_interfaces[i].name, interface_name, strlen(data_model.local_interfaces[i].name)+1)) {
                return data_model.local_interfaces[i].mac_address;
            }
        }
    }

    /* Not found! */
    return NULL;
}

uint8_t DMupdateDiscoveryTimeStamps(uint8_t *receiving_interface_addr, uint8_t *al_mac_address, uint8_t *mac_address, uint8_t timestamp_type, uint64_t *ellapsed)
{
    char  *receiving_interface_name;

    struct _remoteInterface *x;

    uint64_t aux1, aux2;
    uint8_t  insert_result;
    uint8_t  ret = 2;

    if (NULL == receiving_interface_addr) {
        log_i1905_e("Invalid 'receiving_interface_addr'");
        return 0;
    }

    if (NULL == (receiving_interface_name = DMmacToInterfaceName(receiving_interface_addr))) {
        log_i1905_e("The provided 'receiving_interface_addr' (%02x:%02x:%02x:%02x:%02x:%02x) does not match any local interface", receiving_interface_addr[0], receiving_interface_addr[1], receiving_interface_addr[2], receiving_interface_addr[3], receiving_interface_addr[4], receiving_interface_addr[5]);
        return 0;
    }

    if (0 == (insert_result = _insertNeighbor(receiving_interface_name, al_mac_address)) ||
        0 == _insertNeighborInterface(receiving_interface_name, al_mac_address, mac_address)) {
        log_i1905_e("Could not create new entries in the database");
        return 0;
    }

    if (1 == insert_result) {
        /* This is the first time we know of this neighbor (ie. the neighbor
        *  has been inserted in the data model for the first time)
        */
        ret = 1;
    }

    x = _macAddressToRemoteInterfaceStruct(receiving_interface_name, al_mac_address, mac_address);
    if (!x) {
        return 0;
    }

    log_i1905_d("New discovery timestamp udpate:");
    log_i1905_d("  - local_interface      : %s", receiving_interface_name);
    log_i1905_d("  - 1905 neighbor AL MAC : %02x:%02x:%02x:%02x:%02x:%02x:", al_mac_address[0], al_mac_address[1], al_mac_address[2], al_mac_address[3], al_mac_address[4], al_mac_address[5]);
    log_i1905_d("  - remote interface MAC : %02x:%02x:%02x:%02x:%02x:%02x:", mac_address[0],    mac_address[1],    mac_address[2],    mac_address[3],    mac_address[4],    mac_address[5]);

    aux1 = x->last_topology_discovery_ts;
    aux2 = x->last_bridge_discovery_ts;

    switch (timestamp_type) {
        case TIMESTAMP_TOPOLOGY_DISCOVERY: {
            uint64_t aux = PLATFORM_GET_TIMESTAMP();

            if (NULL != ellapsed) {
                if (2 == ret) {
                    *ellapsed = aux - x->last_topology_discovery_ts;
                } else {
                    *ellapsed = 0;
                }
            }

            x->last_topology_discovery_ts = aux;
            break;
        }
        case TIMESTAMP_BRIDGE_DISCOVERY: {
            uint64_t aux = PLATFORM_GET_TIMESTAMP();

            if (NULL != ellapsed) {
                if (2 == ret) {
                    *ellapsed = aux - x->last_bridge_discovery_ts;
                } else {
                    *ellapsed = 0;
                }
            }
            x->last_bridge_discovery_ts = aux;
            break;
        }
        default: {
            log_i1905_e("Unknown 'timestamp_type' (%d)", timestamp_type);
            return 0;
        }
    }

    log_i1905_d("  - topology disc TS     : %"PRIu64" --> %"PRIu64"",aux1, x->last_topology_discovery_ts);
    log_i1905_d("  - bridge   disc TS     : %"PRIu64" --> %"PRIu64"",aux2, x->last_bridge_discovery_ts);

    return ret;
}

uint8_t DMisLinkBridged(char *local_interface_name, uint8_t *neighbor_al_mac_address, uint8_t *neighbor_mac_address)
{
    struct _remoteInterface *x;

    uint64_t aux;

    if (NULL == (x = _macAddressToRemoteInterfaceStruct(local_interface_name, neighbor_al_mac_address, neighbor_mac_address))) {
        /* Non existent neighbor */
        return 2;
    }


    if (x->last_topology_discovery_ts > x->last_bridge_discovery_ts) {
        aux = x->last_topology_discovery_ts - x->last_bridge_discovery_ts;
    } else {
        aux = x->last_bridge_discovery_ts   - x->last_topology_discovery_ts;
    }

    if (aux < DISCOVERY_THRESHOLD_MS) {
        /* Links is *not* bridged */
        return 0;
    } else {
        /* Link is bridged */
        return 1;
    }
}

uint8_t DMisNeighborBridged(char *local_interface_name, uint8_t *neighbor_al_mac_address)
{
    struct _neighbor *x;

    uint8_t i;

    if (NULL == (x = _alMacAddressToNeighborStruct(local_interface_name, neighbor_al_mac_address))) {
        /* Non existent neighbor */
        return 2;
    }

    for (i=0; i<x->remote_interfaces_nr; i++) {
        if (1 == DMisLinkBridged(local_interface_name, neighbor_al_mac_address, x->remote_interfaces[i].mac_address)) {
            /* If at least one link is bridged, then this neighbor is
            *  considered to be bridged.
            */
            return 1;
        }
    }

    /* All links are not bridged, thus the neighbor is considered to be not bridged also. */
    return 0;
}

uint8_t DMisInterfaceBridged(char *local_interface_name)
{
    struct _localInterface *x;

    uint8_t i;

    x = _nameToLocalInterfaceStruct(local_interface_name);
    if (NULL == x) {
        log_i1905_e("Invalid local interface name");
        return 2;
    }

    for (i=0; i<x->neighbors_nr; i++) {
        if (1 == DMisNeighborBridged(local_interface_name, x->neighbors[i].al_mac_address)) {
            /* If at least one neighbor is bridged, then this interface is
            *  considered to be bridged.
            */
            return 1;
        }
    }

    /* All neighbors are not bridged, thus the interface is considered to be not bridged also. */
    return 0;
}

uint8_t *DMmacToAlMac(uint8_t *mac_address)
{
    uint8_t i, j, k;

    uint8_t *al_mac = malloc(sizeof(uint8_t)*6);
    uint8_t found = 0;

    if (al_mac == NULL) {
        log_i1905_e("memory allocation failure");
        return NULL;
    }


    if (0 == memcmp(data_model.al_mac_address, mac_address, 6)) {
        free(al_mac);
        return data_model.al_mac_address;
    }

    for (i=0; i<data_model.local_interfaces_nr; i++) {
        if (0 == memcmp(data_model.local_interfaces[i].mac_address, mac_address, 6)) {
            found = 1;
            memcpy(al_mac, data_model.al_mac_address, 6);
        }

        for (j=0; j<data_model.local_interfaces[i].neighbors_nr; j++) {
            if (0 == memcmp(data_model.local_interfaces[i].neighbors[j].al_mac_address, mac_address, 6)) {
                found = 1;
                memcpy(al_mac, data_model.local_interfaces[i].neighbors[j].al_mac_address, 6);
            }

            for (k=0; k<data_model.local_interfaces[i].neighbors[j].remote_interfaces_nr; k++) {
                if (0 == memcmp(data_model.local_interfaces[i].neighbors[j].remote_interfaces[k].mac_address, mac_address, 6)) {
                    found = 1;
                    memcpy(al_mac, data_model.local_interfaces[i].neighbors[j].al_mac_address, 6);
                }
            }
        }
    }

    if (1 == found) {
        return al_mac;
    } else {
      /* No matching MAC address was found */
      free(al_mac);
      return NULL;
    }
}

uint8_t DMupdateNetworkDeviceInfo(uint8_t *al_mac_address,
                                  uint8_t in_update,  struct deviceInformationTypeTLV             *info,
                                  uint8_t br_update,  struct deviceBridgingCapabilityTLV         **bridges,           uint8_t bridges_nr,
                                  uint8_t no_update,  struct non1905NeighborDeviceListTLV        **non1905_neighbors, uint8_t non1905_neighbors_nr,
                                  uint8_t x1_update,  struct neighborDeviceListTLV               **x1905_neighbors,   uint8_t x1905_neighbors_nr,
                                  uint8_t po_update,  struct powerOffInterfaceTLV                **power_off,         uint8_t power_off_nr,
                                  uint8_t l2_update,  struct l2NeighborDeviceTLV                 **l2_neighbors,      uint8_t l2_neighbors_nr,
                                  uint8_t ge_update,  struct genericPhyDeviceInformationTypeTLV   *generic_phy,
                                  uint8_t pr_update,  struct x1905ProfileVersionTLV               *profile,
                                  uint8_t id_update,  struct deviceIdentificationTypeTLV          *identification,
                                  uint8_t co_update,  struct controlUrlTypeTLV                    *control_url,
                                  uint8_t v4_update,  struct ipv4TypeTLV                          *ipv4,
                                  uint8_t v6_update,  struct ipv6TypeTLV                          *ipv6)
{
    uint8_t i,j;

    if ((NULL == al_mac_address)                                                     ||
        (br_update == 1 && (bridges_nr            > 0 && NULL == bridges)          ) ||
        (no_update == 1 && (non1905_neighbors_nr  > 0 && NULL == non1905_neighbors)) ||
        (x1_update == 1 && (x1905_neighbors_nr    > 0 && NULL == x1905_neighbors)  ) ||
        (po_update == 1 && (power_off_nr          > 0 && NULL == power_off)        ) ||
        (l2_update == 1 && (l2_neighbors_nr       > 0 && NULL == l2_neighbors)     ))
    {
        return 0;
    }

    /* First, search for an existing entry with the same AL MAC address
    *  Remember that the first entry holds a reference to the *local* node.
    */
    if (0 == memcmp(DMalMacGet(), al_mac_address, 6)) {
        i=0;
    } else {
        for (i=1; i<data_model.network_devices_nr; i++) {
            if (NULL != data_model.network_devices[i].info) {
                if (0 == memcmp(data_model.network_devices[i].info->al_mac_address, al_mac_address, 6)) {
                    break;
                }
            }
        }
    }

    if (i == data_model.network_devices_nr) {
        /* A matching entry was *not* found. Create a new one, but only if this
        *  new information contains the "info" TLV (otherwise don't do anything
        *  and wait for the "info" TLV to be received in the future)
        */
        if (1 == in_update && NULL != info) {
            if (0 == data_model.network_devices_nr) {
                data_model.network_devices = malloc(sizeof(struct _networkDevice));
            } else {
                data_model.network_devices = realloc(data_model.network_devices, sizeof(struct _networkDevice)*(data_model.network_devices_nr+1));
            }

            data_model.network_devices[data_model.network_devices_nr].update_timestamp          = PLATFORM_GET_TIMESTAMP();
            data_model.network_devices[data_model.network_devices_nr].info                      = 1 == in_update ? info                 : NULL;
            data_model.network_devices[data_model.network_devices_nr].bridges_nr                = 1 == br_update ? bridges_nr           : 0;
            data_model.network_devices[data_model.network_devices_nr].bridges                   = 1 == br_update ? bridges              : NULL;
            data_model.network_devices[data_model.network_devices_nr].non1905_neighbors_nr      = 1 == no_update ? non1905_neighbors_nr : 0;
            data_model.network_devices[data_model.network_devices_nr].non1905_neighbors         = 1 == no_update ? non1905_neighbors    : NULL;
            data_model.network_devices[data_model.network_devices_nr].x1905_neighbors_nr        = 1 == x1_update ? x1905_neighbors_nr   : 0;
            data_model.network_devices[data_model.network_devices_nr].x1905_neighbors           = 1 == x1_update ? x1905_neighbors      : NULL;
            data_model.network_devices[data_model.network_devices_nr].power_off_nr              = 1 == po_update ? power_off_nr         : 0;
            data_model.network_devices[data_model.network_devices_nr].power_off                 = 1 == po_update ? power_off            : NULL;
            data_model.network_devices[data_model.network_devices_nr].l2_neighbors_nr           = 1 == l2_update ? l2_neighbors_nr      : 0;
            data_model.network_devices[data_model.network_devices_nr].l2_neighbors              = 1 == l2_update ? l2_neighbors         : NULL;
            data_model.network_devices[data_model.network_devices_nr].generic_phy               = 1 == ge_update ? generic_phy          : NULL;
            data_model.network_devices[data_model.network_devices_nr].profile                   = 1 == pr_update ? profile              : NULL;
            data_model.network_devices[data_model.network_devices_nr].identification            = 1 == id_update ? identification       : NULL;
            data_model.network_devices[data_model.network_devices_nr].control_url               = 1 == co_update ? control_url          : NULL;
            data_model.network_devices[data_model.network_devices_nr].ipv4                      = 1 == v4_update ? ipv4                 : NULL;
            data_model.network_devices[data_model.network_devices_nr].ipv6                      = 1 == v6_update ? ipv6                 : NULL;

            data_model.network_devices[data_model.network_devices_nr].metrics_with_neighbors_nr = 0;
            data_model.network_devices[data_model.network_devices_nr].metrics_with_neighbors    = NULL;

            data_model.network_devices[data_model.network_devices_nr].extensions                = NULL;
            data_model.network_devices[data_model.network_devices_nr].extensions_nr             = 0;

            data_model.network_devices_nr++;
        }
    } else {
        /* A matching entry was found. Update it. But first, free the old TLV
        *  structures (but only if a new value was provided!... otherwise retain
        *  the old item)
        */
        data_model.network_devices[i].update_timestamp = PLATFORM_GET_TIMESTAMP();

        if (NULL != info) {
            if (NULL != data_model.network_devices[i].info) {
                free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].info);
            }
            data_model.network_devices[i].info = info;
        }

        if (1 == br_update) {
            for (j=0; j<data_model.network_devices[i].bridges_nr; j++) {
                free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].bridges[j]);
            }
            if (data_model.network_devices[i].bridges_nr > 0 && NULL != data_model.network_devices[i].bridges) {
                free(data_model.network_devices[i].bridges);
            }
            data_model.network_devices[i].bridges_nr = bridges_nr;
            data_model.network_devices[i].bridges    = bridges;
        }

        if (1 == no_update) {
            for (j=0; j<data_model.network_devices[i].non1905_neighbors_nr; j++) {
                free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].non1905_neighbors[j]);
            }
            if (data_model.network_devices[i].non1905_neighbors_nr > 0 && NULL != data_model.network_devices[i].non1905_neighbors) {
                free(data_model.network_devices[i].non1905_neighbors);
            }
            data_model.network_devices[i].non1905_neighbors_nr = non1905_neighbors_nr;
            data_model.network_devices[i].non1905_neighbors    = non1905_neighbors;
        }

        if (1 == x1_update) {
            for (j=0; j<data_model.network_devices[i].x1905_neighbors_nr; j++) {
                free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].x1905_neighbors[j]);
            }
            if (data_model.network_devices[i].x1905_neighbors_nr > 0 && NULL != data_model.network_devices[i].x1905_neighbors) {
                free(data_model.network_devices[i].x1905_neighbors);
            }
            data_model.network_devices[i].x1905_neighbors_nr = x1905_neighbors_nr;
            data_model.network_devices[i].x1905_neighbors    = x1905_neighbors;
        }

        if (1 == po_update) {
            for (j=0; j<data_model.network_devices[i].power_off_nr; j++) {
                free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].power_off[j]);
            }
            if (data_model.network_devices[i].power_off_nr > 0 && NULL != data_model.network_devices[i].power_off) {
                free(data_model.network_devices[i].power_off);
            }
            data_model.network_devices[i].power_off_nr = power_off_nr;
            data_model.network_devices[i].power_off    = power_off;
        }

        if (1 == l2_update) {
            for (j=0; j<data_model.network_devices[i].l2_neighbors_nr; j++) {
                free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].l2_neighbors[j]);
            }
            if (data_model.network_devices[i].l2_neighbors_nr > 0 && NULL != data_model.network_devices[i].l2_neighbors) {
                free(data_model.network_devices[i].l2_neighbors);
            }
            data_model.network_devices[i].l2_neighbors_nr = l2_neighbors_nr;
            data_model.network_devices[i].l2_neighbors    = l2_neighbors;
        }

        if (1 == ge_update) {
            free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].generic_phy);
            data_model.network_devices[i].generic_phy = generic_phy;
        }

        if (1 == pr_update) {
            free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].profile);
            data_model.network_devices[i].profile = profile;
        }

        if (1 == id_update) {
            free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].identification);
            data_model.network_devices[i].identification = identification;
        }

        if (1 == co_update) {
            free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].control_url);
            data_model.network_devices[i].control_url = control_url;
        }

        if (1 == v4_update) {
            free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].ipv4);
            data_model.network_devices[i].ipv4 = ipv4;
        }

        if (1 == v6_update) {
            free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].ipv6);
            data_model.network_devices[i].ipv6 = ipv6;
        }
    }

    return 1;
}

uint8_t DMnetworkDeviceInfoNeedsUpdate(uint8_t *al_mac_address)
{
    uint8_t i;

    /* First, search for an existing entry with the same AL MAC address */
    for (i=0; i<data_model.network_devices_nr; i++) {
        if (NULL != data_model.network_devices[i].info) {
            if (0 == memcmp(data_model.network_devices[i].info->al_mac_address, al_mac_address, 6)) {
                break;
            }
        }
    }

    if (i == data_model.network_devices_nr) {
        /* A matching entry was *not* found. Thus a refresh of the information is needed. */
        return 1;
    } else {
        /* A matching entry was found. Check its timestamp. */
        if (PLATFORM_GET_TIMESTAMP() - data_model.network_devices[i].update_timestamp > MAX_AGE * 1000) {
            return 1;
        } else {
            return 0;
        }
    }
}

uint8_t DMupdateNetworkDeviceMetrics(uint8_t *metrics)
{
    uint8_t *FROM_al_mac_address;  /* Metrics are reported FROM this AL entity... */
    uint8_t *TO_al_mac_address;    /* ... TO this other one. */

    uint8_t i, j;

    if (NULL == metrics) {
        log_i1905_e("Invalid 'metrics' argument");
        return 0;
    }

    /* Obtain the AL MAC of the devices involved in the metrics report (ie.
    *  the "from" and the "to" AL MAC addresses).
    *  This information is contained inside the 'metrics' structure itself.
    */
    if (TLV_TYPE_TRANSMITTER_LINK_METRIC == *metrics) {
        struct transmitterLinkMetricTLV *p;

        p = (struct transmitterLinkMetricTLV *)metrics;

        FROM_al_mac_address = p->local_al_address;
        TO_al_mac_address   = p->neighbor_al_address;

    } else if (TLV_TYPE_RECEIVER_LINK_METRIC == *metrics) {
        struct receiverLinkMetricTLV *p;

        p = (struct receiverLinkMetricTLV *)metrics;

        FROM_al_mac_address = p->local_al_address;
        TO_al_mac_address   = p->neighbor_al_address;
    } else {
        log_i1905_d("Invalid 'metrics' argument. Type = %d", *metrics);
        return 0;
    }

    /* Next, search for an existing entry with the same AL MAC address */
    for (i=0; i<data_model.network_devices_nr; i++) {
        if (NULL == data_model.network_devices[i].info) {
            /* We haven't received general info about this device yet.
            *  This can happen, for example, when only metrics have been
            *  received so far.
            */
            continue;
        }
        if (0 == memcmp(data_model.network_devices[i].info->al_mac_address, FROM_al_mac_address, 6)) {
            break;
        }
    }

    if (i == data_model.network_devices_nr) {
        /* A matching entry was *not* found.
        *
        *  At this point, even if we could just create a new device entry with
        *  everything set to zero (except for the metrics that we have just
        *  received), it is probably wiser to simply discard the data.
        *
        *  In other words, we should not accept metrics data until the "general
        *  info" for this node has been processed.
        */
        log_i1905_d("Metrics received from an unknown 1905 node (%02x:%02x:%02x:%02x:%02x:%02x). Ignoring data...", FROM_al_mac_address[0], FROM_al_mac_address[1], FROM_al_mac_address[2], FROM_al_mac_address[3], FROM_al_mac_address[4], FROM_al_mac_address[5]);
        return 0;
    }

    /* Now that we have found the corresponding neighbor entry (or created a
    *  new one) search for a sub-entry that matches the AL MAC of the node the
    *  metrics are being reported against.
    */
    for (j=0; j<data_model.network_devices[i].metrics_with_neighbors_nr; j++) {
        if (0 == memcmp(data_model.network_devices[i].metrics_with_neighbors[j].neighbor_al_mac_address, TO_al_mac_address, 6))  {
            break;
        }
    }

    if (j == data_model.network_devices[i].metrics_with_neighbors_nr) {
        /* A matching entry was *not* found. Create a new one */
        if (0 == data_model.network_devices[i].metrics_with_neighbors_nr) {
            data_model.network_devices[i].metrics_with_neighbors = malloc(sizeof(struct _metricsWithNeighbor));
        } else {
            data_model.network_devices[i].metrics_with_neighbors = realloc(data_model.network_devices[i].metrics_with_neighbors, sizeof(struct _metricsWithNeighbor)*(data_model.network_devices[i].metrics_with_neighbors_nr+1));
        }

        memcpy(data_model.network_devices[i].metrics_with_neighbors[data_model.network_devices[i].metrics_with_neighbors_nr].neighbor_al_mac_address, TO_al_mac_address, 6);

        if (TLV_TYPE_TRANSMITTER_LINK_METRIC == *metrics) {
            data_model.network_devices[i].metrics_with_neighbors[data_model.network_devices[i].metrics_with_neighbors_nr].tx_metrics_timestamp = PLATFORM_GET_TIMESTAMP();
            data_model.network_devices[i].metrics_with_neighbors[data_model.network_devices[i].metrics_with_neighbors_nr].tx_metrics           = (struct transmitterLinkMetricTLV*)metrics;

            data_model.network_devices[i].metrics_with_neighbors[data_model.network_devices[i].metrics_with_neighbors_nr].rx_metrics_timestamp = 0;
            data_model.network_devices[i].metrics_with_neighbors[data_model.network_devices[i].metrics_with_neighbors_nr].rx_metrics           = NULL;
        } else  {
            data_model.network_devices[i].metrics_with_neighbors[data_model.network_devices[i].metrics_with_neighbors_nr].tx_metrics_timestamp = 0;
            data_model.network_devices[i].metrics_with_neighbors[data_model.network_devices[i].metrics_with_neighbors_nr].tx_metrics           = NULL;

            data_model.network_devices[i].metrics_with_neighbors[data_model.network_devices[i].metrics_with_neighbors_nr].rx_metrics_timestamp = PLATFORM_GET_TIMESTAMP();
            data_model.network_devices[i].metrics_with_neighbors[data_model.network_devices[i].metrics_with_neighbors_nr].rx_metrics           = (struct receiverLinkMetricTLV*)metrics;
        }

        data_model.network_devices[i].metrics_with_neighbors_nr++;
    } else {
        /* A matching entry was found. Update it. But first, free the old TLV
        *  structures.
        */
        if (TLV_TYPE_TRANSMITTER_LINK_METRIC == *metrics) {
            free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].metrics_with_neighbors[j].tx_metrics);

            data_model.network_devices[i].metrics_with_neighbors[j].tx_metrics_timestamp = PLATFORM_GET_TIMESTAMP();
            data_model.network_devices[i].metrics_with_neighbors[j].tx_metrics           = (struct transmitterLinkMetricTLV*)metrics;
        } else {
            free_1905_TLV_structure((uint8_t *)data_model.network_devices[i].metrics_with_neighbors[j].rx_metrics);

            data_model.network_devices[i].metrics_with_neighbors[j].rx_metrics_timestamp = PLATFORM_GET_TIMESTAMP();
            data_model.network_devices[i].metrics_with_neighbors[j].rx_metrics           = (struct receiverLinkMetricTLV*)metrics;
        }
    }

    return 1;
}

void DMdumpNetworkDevices(void (*write_function)(const char *fmt, ...))
{
    // Buffer size to store a prefix string that will be used to show each
    // element of a structure on screen
    //
    #define MAX_PREFIX  100

    uint8_t  i, j;

    write_function("");

    write_function("  device_nr: %d", data_model.network_devices_nr);

    for (i=0; i<data_model.network_devices_nr; i++)
    {
        char new_prefix[MAX_PREFIX];

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->", i);
        write_function("%supdate timestamp: %d", new_prefix, data_model.network_devices[i].update_timestamp);

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->general_info->", i);
        visit_1905_TLV_structure((uint8_t* )data_model.network_devices[i].info, print_callback, write_function, new_prefix);

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->bridging_capabilities_nr: %d", i, data_model.network_devices[i].bridges_nr);
        write_function("%s", new_prefix);
        for (j=0; j<data_model.network_devices[i].bridges_nr; j++) {
            snprintf(new_prefix, MAX_PREFIX, "  device[%d]->bridging_capabilities[%d]->", i, j);
            visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].bridges[j], print_callback, write_function, new_prefix);
        }

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->non_1905_neighbors_nr: %d", i, data_model.network_devices[i].non1905_neighbors_nr);
        write_function("%s", new_prefix);
        for (j=0; j<data_model.network_devices[i].non1905_neighbors_nr; j++) {
            snprintf(new_prefix, MAX_PREFIX, "  device[%d]->non_1905_neighbors[%d]->", i, j);
            visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].non1905_neighbors[j], print_callback, write_function, new_prefix);
        }

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->x1905_neighbors_nr: %d", i, data_model.network_devices[i].x1905_neighbors_nr);
        write_function("%s", new_prefix);
        for (j=0; j<data_model.network_devices[i].x1905_neighbors_nr; j++) {
            snprintf(new_prefix, MAX_PREFIX, "  device[%d]->x1905_neighbors[%d]->", i, j);
            visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].x1905_neighbors[j], print_callback, write_function, new_prefix);
        }

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->power_off_interfaces_nr: %d", i, data_model.network_devices[i].power_off_nr);
        write_function("%s", new_prefix);
        for (j=0; j<data_model.network_devices[i].power_off_nr; j++)
        {
            snprintf(new_prefix, MAX_PREFIX, "  device[%d]->power_off_interfaces[%d]->", i, j);
            visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].power_off[j], print_callback, write_function, new_prefix);
        }

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->l2_neighbors_nr: %d", i, data_model.network_devices[i].l2_neighbors_nr);
        write_function("%s", new_prefix);
        for (j=0; j<data_model.network_devices[i].l2_neighbors_nr; j++) {
            snprintf(new_prefix, MAX_PREFIX, "  device[%d]->l2_neighbors[%d]->", i, j);
            visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].l2_neighbors[j], print_callback, write_function, new_prefix);
        }

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->generic_phys->", i);
        visit_1905_TLV_structure((uint8_t* )data_model.network_devices[i].generic_phy, print_callback, write_function, new_prefix);

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->profile->", i);
        visit_1905_TLV_structure((uint8_t* )data_model.network_devices[i].profile, print_callback, write_function, new_prefix);

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->identification->", i);
        visit_1905_TLV_structure((uint8_t* )data_model.network_devices[i].identification, print_callback, write_function, new_prefix);

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->control_url->", i);
        visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].control_url, print_callback, write_function, new_prefix);

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->ipv4->", i);
        visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].ipv4, print_callback, write_function, new_prefix);

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->ipv6->", i);
        visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].ipv6, print_callback, write_function, new_prefix);

        snprintf(new_prefix, MAX_PREFIX, "  device[%d]->metrics_nr: %d", i, data_model.network_devices[i].metrics_with_neighbors_nr);
        write_function("%s", new_prefix);
        for (j=0; j<data_model.network_devices[i].metrics_with_neighbors_nr; j++) {
            snprintf(new_prefix, MAX_PREFIX, "  device[%d]->metrics[%d]->tx->", i, j);
            if (NULL != data_model.network_devices[i].metrics_with_neighbors[j].tx_metrics) {
                write_function("%slast_updated: %d", new_prefix, data_model.network_devices[i].metrics_with_neighbors[j].tx_metrics_timestamp);
                visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].metrics_with_neighbors[j].tx_metrics, print_callback, write_function, new_prefix);
            }
            snprintf(new_prefix, MAX_PREFIX, "  device[%d]->metrics[%d]->rx->", i, j);
            if (NULL != data_model.network_devices[i].metrics_with_neighbors[j].rx_metrics) {
                write_function("%slast updated: %d", new_prefix, data_model.network_devices[i].metrics_with_neighbors[j].rx_metrics_timestamp);
                visit_1905_TLV_structure((uint8_t *)data_model.network_devices[i].metrics_with_neighbors[j].rx_metrics, print_callback, write_function, new_prefix);
            }
        }
    }
}

uint8_t DMrunGarbageCollector(void)
{
    return _runGarbageCollector(false);
}

void DMremoveALNeighborFromInterface(uint8_t *al_mac_address, char *interface_name)
{
    uint8_t i, j;

    for (i=0; i<data_model.local_interfaces_nr; i++) {
        uint8_t original_neighbors_nr;

        if ((0 != memcmp(data_model.local_interfaces[i].name, interface_name, strlen(data_model.local_interfaces[i].name)+1)) &&
            (0 != memcmp(interface_name,                      "all",          strlen(interface_name)+1)))
        {
            /* Ignore this interface */
            continue;
        }

        original_neighbors_nr = data_model.local_interfaces[i].neighbors_nr;

        for (j=0; j<data_model.local_interfaces[i].neighbors_nr; j++) {
            if (0 == memcmp(al_mac_address, data_model.local_interfaces[i].neighbors[j].al_mac_address, 6)) {
                if (data_model.local_interfaces[i].neighbors[j].remote_interfaces_nr > 0 && NULL != data_model.local_interfaces[i].neighbors[j].remote_interfaces) {
                    free(data_model.local_interfaces[i].neighbors[j].remote_interfaces);

                    data_model.local_interfaces[i].neighbors[j].remote_interfaces    = NULL;
                    data_model.local_interfaces[i].neighbors[j].remote_interfaces_nr = 0;
                }

                /* Place last element here (we don't care about preserving order) */
                if (j == (data_model.local_interfaces[i].neighbors_nr-1)) {
                    /* Last element. It will automatically be removed below (keep reading) */
                } else {
                    data_model.local_interfaces[i].neighbors[j] = data_model.local_interfaces[i].neighbors[data_model.local_interfaces[i].neighbors_nr-1];
                    j--;
                }
                data_model.local_interfaces[i].neighbors_nr--;
            }
        }

        if (original_neighbors_nr != data_model.local_interfaces[i].neighbors_nr) {
            if (0 == data_model.local_interfaces[i].neighbors_nr) {
                free(data_model.local_interfaces[i].neighbors);
            } else {
                data_model.local_interfaces[i].neighbors = (struct _neighbor *)realloc(data_model.local_interfaces[i].neighbors, sizeof(struct _neighbor)*(data_model.local_interfaces[i].neighbors_nr));
            }
        }
    }
}

struct vendorSpecificTLV ***DMextensionsGet(uint8_t *al_mac_address, uint8_t **nr)
{
    uint8_t                       i;
    struct vendorSpecificTLV   ***extensions;

    /* Find device */
    if ((NULL == al_mac_address) || (NULL == nr)) {
        log_i1905_e("Invalid 'DMextensionsGet' argument");
        return NULL;
    }

    /* Search for an existing entry with the same AL MAC address */
    for (i=0; i<data_model.network_devices_nr; i++) {
        if (NULL == data_model.network_devices[i].info) {
            /* We haven't received general info about this device yet. */
            continue;
        }
        if (0 == memcmp(data_model.network_devices[i].info->al_mac_address, al_mac_address, 6)) {
            break;
        }
    }

    if (i == data_model.network_devices_nr) {
        /* A matching entry was *not* found. */
        log_i1905_d("Extension received from an unknown 1905 node (%02x:%02x:%02x:%02x:%02x:%02x). Ignoring data...", al_mac_address[0], al_mac_address[1], al_mac_address[2], al_mac_address[3], al_mac_address[4], al_mac_address[5]);
        extensions = NULL;
    } else {
        /* Point to the datamodel extensions section */
        extensions = &data_model.network_devices[i].extensions;
        *nr        = &data_model.network_devices[i].extensions_nr;
    }

    return extensions;
}
