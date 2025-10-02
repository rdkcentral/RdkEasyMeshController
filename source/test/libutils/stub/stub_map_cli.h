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

#ifndef STUB_MAP_CLI_H_
#define STUB_MAP_CLI_H_

typedef void (*stub_map_cli_print_cb_t)(const char *buf);

void stub_map_cli_set_print_buf(char **buf);

int stub_map_cli_exec(char *cmd, char *payload);

#endif /* STUB_MAP_CLI_H_ */
