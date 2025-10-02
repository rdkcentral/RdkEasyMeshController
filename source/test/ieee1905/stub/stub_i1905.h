/*
 * Copyright (c) 2020-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef STUB_I1905_H_
#define STUB_I1905_H_

#include "i1905.h"

typedef void (*stub_i1905_lldp_send_cb_t)(char *ifname, mac_addr smac, i1905_lldp_payload_t *payload, void *args);

typedef void (*stub_i1905_cmdu_send_cb_t)(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args);

typedef void (*stub_i1905_raw_send_cb_t)(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len, void *args);

void stub_i1905_register_lldp_send_cb(stub_i1905_lldp_send_cb_t cb, void *args);

void stub_i1905_register_cmdu_send_cb(stub_i1905_cmdu_send_cb_t cb, void *args);

void stub_i1905_register_raw_send_cb(stub_i1905_raw_send_cb_t cb, void *args);

void stub_i1905_reset_send_nr(void);

int  stub_i1905_get_send_nr(void);

#endif /* STUB_I1905_H_ */
