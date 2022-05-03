/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_AIRDATA_H
#define MAP_AIRDATA_H


typedef void (airdata_notify_cb_t)(unsigned int module_type, unsigned int ctl_type,
                                   const char *ctl_name,
                                   const char *old_val, const char *new_val,
                                   unsigned int idx_cnt, unsigned int *idxes,
                                   void *userdata);

const char *map_airdata_get_id(void);

int map_airdata_register_notify_cb_led(airdata_notify_cb_t *cb, void *userdata);
int map_airdata_register_notify_cb(airdata_notify_cb_t *cb, void *userdata);

/* getval and setval air-comm bus */
int map_airdata_acbus_getval(const char *key, void *keyval);
int map_airdata_acbus_setval(const char *key, void *keyval);

int map_airdata_init(char *lib_path);
void map_airdata_fini(void);

#endif /* !MAP_AIRDATA_H */
