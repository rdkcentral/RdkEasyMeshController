/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

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

#ifndef AL_DATAMODEL_H_
#define AL_DATAMODEL_H_

#include "1905_tlvs.h"

/*#######################################################################
# Data model initialization and general functions                       #
########################################################################*/

/* This function must be called before any other function of this header file */
void DMinit();

/* De-initialize datamodel */
void DMfini();

/* When the AL entity is initialized, it knows its AL MAC address. At this point
*  the "DMalMacSet()" function must be called to store this value in the
*  database.
*  Later, anyone can consult this value with "DMalMacGet()"
*/
void  DMalMacSet(uint8_t *al_mac_address);
uint8_t *DMalMacGet();

/* When the AL entity is initialized, it knows the MAC address of the interface
*  designated as 'network registrar'. At this point the "DMregistrarMacSet()"
*  function must be called to store this value in the database.
*  Later, anyone can consult this value with "DMregistrarMacGet()"
*
*  Note that the registrar MAC address can or cannot match any of the local
*  interfaces.
*/
void  DMregistrarMacSet(uint8_t *registrar_mac_address);
uint8_t *DMregistrarMacGet();

/* When the AL entity is initialized, it knows whether the user want to map the
*  whole network or only direct neighbors (using much less memory).
*  the "DMalMacSet()" function must be called to store this value in the
*  database.
*  Later, anyone can consult this value with "DMmapWholeNetworkGet()"
*/
void  DMmapWholeNetworkSet(uint8_t map_whole_network_flag);
uint8_t DMmapWholeNetworkGet();

/* This function is called to check if interface name-mac pair already exists in
*  the datamodel.
*/
uint8_t DMfindInterface(char *name, uint8_t *mac_address);

/* When a new local interface is made available to the AL entity, this function
*  must be called to update the database.
*  Returns '0' if there was a problem (out of memory, etc...), '1' otherwise
*  (including if the interface had already been inserted)
*/
uint8_t DMinsertInterface(char *name, uint8_t *mac_address);

/* These are used to convert between names (ex: "eth0", "wlan1",...) and MAC
*  addresses of local interfaces which have previously been inserted in the
*  database using "DMinsertInterface()"
*
*  Returned values must not be freed.
*/
char *DMmacToInterfaceName(uint8_t *mac_address);
uint8_t *DMinterfaceNameToMac(char *interface_name);


/*#######################################################################
# (Local / interface level) topology discovery related functions        #
########################################################################*/

/* Call this function when a new "discovery message" has been received on
*  'receiving_interface_addr' whose payload containing 'al_mac_address' and
*  'mac_address'.
*  This function will then update the timestamps of that particular link so
*  that they contain the current time.
*
*  'timestamp_type' can be either TIMESTAMP_TOPOLOGY_DISCOVERY (to be used when
*  the received "discovery message" is a "1905 topology discovery message") or
*  TIMESTAMP_BRIDGE_DISCOVERY (when receiving a "LLDP bridge discovery message")
*
*  Return '0' if there was a problem, '1' if this is the first time updating
*  the timestamp of neighbor 'al_mac_address' and '2' otherwise
*
*  When the return value is '2', output variable 'ellapsed' contains the amount
*  of milliseconds since the last update and this one (NOTE: if you are not
*  interested in this value, use "ellapsed = NULL" when calling this function)
*/
#define TIMESTAMP_TOPOLOGY_DISCOVERY  0
#define TIMESTAMP_BRIDGE_DISCOVERY    1
uint8_t DMupdateDiscoveryTimeStamps(uint8_t *receiving_interface_addr, uint8_t *al_mac_address, uint8_t *mac_address, uint8_t timestamp_type, uint64_t *ellapsed);

/* These functions returns "1" or "0" according to the "bridge flag" rules
*  detailed in "IEEE Std 1905.1-2013 Section 8.1"
*
*  A link is bridged when "1905 topology discovery" and "LLDP bridge discovery"
*  messages are received from the end point of that link in less than
*  DISCOVERY_THRESHOLD_MS apart.
*
*  A neighbor is bridged when at least one of the links between the local AL
*  entity and that neighbor is bridged.
*
*  An interface is bridged when at least one of its neighbors is bridged.
*/
#define DISCOVERY_THRESHOLD_MS  (120000)  /* 120 seconds */
uint8_t DMisLinkBridged     (char *local_interface_name, uint8_t *neighbor_al_mac_address, uint8_t *neighbor_mac_address);
uint8_t DMisNeighborBridged (char *local_interface_name, uint8_t *neighbor_al_mac_address);
uint8_t DMisInterfaceBridged(char *local_interface_name);

/* Given the MAC of an interface (could be local or not) returns the AL MAC of
*  the AL entity which owns that interface.
*  All AL 1905 neighbors are considered (ie. first level neighbors, second level
*  neighbors, ...)
*
*  If the provided MAC is an AL MAC address itself (and it is either the local
*  AL MAC address or a neighbor AL MAC address), then its value is returned.
*
*  Returns NULL if no AL entity owning an interface with that MAC address was
*  found.
*
*  The returned pointer becomes the caller's responsability and must be freed
*  with "PLATFORM_FREE()" once it is no longer needed.
*/
uint8_t *DMmacToAlMac(uint8_t *mac_addresses);


/*#######################################################################
# (Global) network topology related functions                           #
########################################################################*/

/* Update a "device" entry in the data model.
*
*  Call this function every time new information regarding one network device
*  is received (ie.  when receiving either a "topology response", a "generic
*  phy response" or a "high layer response" message).
*
*  As you can see, this function takes many arguments. You don't need to provide
*  all of them at the same time (just leave the ones you don't want to update
*  set to NULL and their associated "*_update" value set to "0").
*  For example, when receiving a "generic phy response" message you will only
*  want to update the "genericPhyDeviceInformationTypeTLV" structure, thus you
*  would call this function like this:
*
*    DMupdateNetworkDeviceInfo(al_mac_address,
*                              0, NULL,
*                              0, NULL, 0,
*                              0, NULL, 0,
*                              0, NULL, 0,
*                              0, NULL, 0,
*                              0, NULL, 0,
*                              1, generic_phy,
*                              0, NULL,
*                              0, NULL,
*                              0, NULL, 0);
*
*  The "*_update" argument is needed because sometimes you want to update
*  something to be NULL (for example, when something disappears from the
*  network)
*
*  Note that for certain types of TLVs the data model can only contain *one*
*  of them ("deviceInformationTypeTLV", "genericPhyDeviceInformationTypeTLV",
*  "x1905ProfileVersionTLV", "deviceInformationTypeTLV" and
*  "deviceInformationTypeTLV").
*  For these TLVs you only need to provide a pointer to the structure.
*
*  For all the others the data model might contain more than one element. That's
*  why you need to provide a pointer to a list of elements and its length.
*
*    NOTE: The 1905 standard allows for more than one "powerOffInterfaceTLV"
*    and "l2NeighborDeviceTLV" TLVs to be received in the "topology response"
*    message, and that's why I require a pointer to a list (and its length) for
*    them. HOWEVER, this is probably an error in the standard (particularly in
*    "Section 6.3.3" after the corrections included in the 1a revision) because
*    one single of these is more than enough as it can contain as many
*    "subentries" (for the particular items they list) as desired.
*    If this is corrected in future revisions of the standard, I just need to
*    change the prototype of this function to accept regular pointers for
*    "power_off" and "l2_neighbors" (instead of pointers to pointers) and remove
*    their associated "power_off_nr" and "l2_neighbors_nr" variables.
*
*  The only parameter you *must* provide is the first one, which identifies the
*  1905 node that is going to be udpated (or created, if this is the first time
*  this node is being used in a call to this function).
*
*  The pointers this function receives become its responsability, thus the
*  caller must not free them at any point (they will automatically be freed the
*  next time this function is called with new (updated) data)
*
*    NOTE: For metrics, a different function is used
*         ("DMupdateNetworkDeviceMetrics()"). The reason for this is that
*         "metrics" work in a slighlty different way: they are not overwritten
*         as a whole (as all the TLVs in this function are) every time they are
*         updated... instead only the "matching" (ie. same origin and
*         destination) metric is.
*         In other words:
*           - When using THIS function, every time you provide a new pointer to
*             a TLV, the data model is updated to contain that TLV (and free the
*             old one)
*           - When using "DMupdateNetworkDeviceMetrics()", every time you
*             provide a new pointer, the data model is updated to *add* it to
*             the already existing metrics information (unless it refers to an
*             already existing link, in which case it is updated)
*
*   TODO: Would it be worth to merge these functions in the future?
*
*  Return '0' if there was a problem, '1' otherwise
*/
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
                                uint8_t v6_update,  struct ipv6TypeTLV                          *ipv6);

/* Given the AL MAC address of a node, returns "0" if the last time its "device
*  info" was updated (ie. the last time someone called
*  "DMupdateNetworkDeviceInfo()" on that node) was quite recently, indicating
*  the caller should not initiate the process to re-fresh this information.
*
*  Returns "1" otherwise.
*
*  NOTE: "recently" means no longer than MAX_AGE seconds ago
*/
#define MAX_AGE 50 /* Must be smaller than the "TIMER_TOKEN_DISCOVERY" period
                   *  (which is 60 seconds)
                   */
uint8_t DMnetworkDeviceInfoNeedsUpdate(uint8_t *al_mac_address);

/* Update the "metrics" information of a neighbor node
*
*  'metrics' is a pointer to either a "struct transmitterLinkMetricTLV" or a
*  "struct receiverLinkMetricTLV".
*
*  Because 'metrics' contains all the needed information (including who are the
*  two 1905 nodes the metrics information make reference to) no additional
*  parameters are needed.
*
*  The pointer this function receives become its responsability, thus the caller
*  must not free them at any point.
*  They will automatically be freed the next time this function is called with
*  new (updated) data *that matches* the same metric (otherwise, a new "metrics"
*  entry will be created).
*
*  Return '0' if there was a problem, '1' otherwise
*/
uint8_t DMupdateNetworkDeviceMetrics(uint8_t *metrics);

/* Print the contents of the "devices" database using the provided printf-like
*  function.
*/
void DMdumpNetworkDevices(void (*write_function)(const char *fmt, ...));

/* This function must be called from time to time (every "x" seconds, where "x"
*  should be a number slightly greate than "GC_MAX_AGE") to remove device
*  entries from the database.
*
*  If an entry is older than "GC_MAX_AGE" seconds, this function removes it.
*
*  "GC_MAX_AGE" must be higher than 60 seconds, which is the network rediscovery
*  period defined in the IEEE1905 standard.
*
*  The return value is the number of entries deleted from the database (that
*  means it will return "0" if no entry eas removed)
*/
#define GC_MAX_AGE (90)
uint8_t DMrunGarbageCollector(void);

/* Remove a neighbor from a particular local interface.
*
*  'al_mac_address' is the 1905 neighbour MAC address that you want to remove.
*
*  'interface_name' is the name of the local interface where you want to remove
*  this neighbor from.
*
*  Nodes are usually removed by calling "DMrunGarbageCollector()". Use this
*  function to speed up the process when, somehow, you are sure that a specific
*  AL node is no longer visible from a particular interface.
*  This might happen, for example, when a L2-specific mechanism triggers a
*  callback when a neighbour dissapears.
*  In these cases you have to first call "DMremoveALNeighborFromInterface()"
*  followed by "DMrunGarbageCollector()".
*
*  Remember: you don't need to call this function if you don't want to and are
*  ok with the ~60 seconds period of the garbage collector mechanism.
*/
void DMremoveALNeighborFromInterface(uint8_t *al_mac_address, char *interface_name);

/* Get TLV extensions from a particular device
*
*  The datamodel provides a list of TLV extensions per device (including
*  itself).  Actually, the datamodel simply provides a pointer to an array of
*  Vendor Specific TLVs. This pointer is really managed by third-party entities
*  (like BBF), adding/removing TLVs.
*  This function is used to obtain the TLV extensions pointer for a particular
*  device.
*
*  'al_mac_address' is the mac address of the requested 1905 device
*
*  'nr' is the number of TLVs belonging to this 'al_mac _adress'
*
*  Return a pointer to the datamodel extensions pointer. This will allow
*  third-party extenders to create/resize the TLV list
*/
struct vendorSpecificTLV ***DMextensionsGet(uint8_t *al_mac_address, uint8_t **nr);

#endif /* AL_DATAMODEL_H_ */
