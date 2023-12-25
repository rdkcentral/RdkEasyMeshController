/*
 * Copyright (c) 2021-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <libubox/utils.h>
#include <rbus/rbus.h>

#define LOG_TAG "dm_rbus"

#include "map_utils.h"
#include "map_config.h"
#include "map_topology_tree.h"
#include "1905_platform.h"

/* NOTES:
- At this moment object indexes are not preserved
- Indexes start from 0.  In case of TR69 functions +1 is needed
- Local agent is added already during init to assure it gets index 0
*/

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAX_TS_STR_LEN          36
#define MAX_PROP_PARAM_LEN      64
#define MAX_DEVICE_PER_NETWORK  32
#define MAX_IFACE_PER_AGENT     8
#define MAX_DEVICE_PER_IFACE    32

#define DM_RBUS_COMPONENT_ID    "EasyMeshController"

#define DM_EMCTL_OBJ            "Device.EasyMeshController."
#define DM_EMCTL_ENABLE         DM_EMCTL_OBJ        "Enable"
#define DM_EMCTL_IFACELIST      DM_EMCTL_OBJ        "InterfaceList"
#define DM_EMCTL_LOCALAGENTMAC  DM_EMCTL_OBJ        "LocalAgentMACAddress"
#define DM_EMCTL_MACADDRESS     DM_EMCTL_OBJ        "MACAddress"
#define DM_EMCTL_PRIMVLANID     DM_EMCTL_OBJ        "PrimaryVLANID"
#define DM_EMCTL_PVIFACEPTTRN   DM_EMCTL_OBJ        "PrimaryVLANInterfacePattern"
#define DM_CHANSEL_OBJ          DM_EMCTL_OBJ        "ChanSel."
#define DM_CHANSEL_DEF2GPCHLST  DM_CHANSEL_OBJ      "Default2GPreferredChannelList"
#define DM_CHANSEL_DEF5GPCHLST  DM_CHANSEL_OBJ      "Default5GPreferredChannelList"
#define DM_CHANSEL_DEF6GPCHLST  DM_CHANSEL_OBJ      "Default6GPreferredChannelList"
#define DM_CHANSEL_ALLWDCHLST2G DM_CHANSEL_OBJ      "AllowedChannelList2G"
#define DM_CHANSEL_ALLWDCHLST5G DM_CHANSEL_OBJ      "AllowedChannelList5G"
#define DM_CHANSEL_ALLWDCHLST6G DM_CHANSEL_OBJ      "AllowedChannelList6G"
#define DM_CHANSEL_ALLWDBW2G    DM_CHANSEL_OBJ      "AllowedBandwidth2G"
#define DM_CHANSEL_ALLWDBW5G    DM_CHANSEL_OBJ      "AllowedBandwidth5G"
#define DM_CHANSEL_ALLWDBW6G    DM_CHANSEL_OBJ      "AllowedBandwidth6G"

#define DM_DATAELEMS_OBJ        "Device.WiFi.DataElements."
/* Device.WiFi.DataElements.Network */
#define DM_NETWORK_OBJ          DM_DATAELEMS_OBJ    "Network."
#define DM_NETWORK_ID           DM_NETWORK_OBJ      "ID"
#define DM_NETWORK_TSTAMP       DM_NETWORK_OBJ      "TimeStamp"
#define DM_NETWORK_DEVNOE       DM_NETWORK_OBJ      "DeviceNumberOfEntries"
#define DM_NETWORK_SSIDNOE      DM_NETWORK_OBJ      "SSIDNumberOfEntries"
#define DM_NETWORK_SETSSID      DM_NETWORK_OBJ      "SetSSID()"
/* Device.WiFi.DataElements.Network.SSID */
#define DM_SSID_TBL             DM_NETWORK_OBJ      "SSID.{i}."
#define DM_SSID_SSID            DM_SSID_TBL         "SSID"
#define DM_SSID_ENABLED         DM_SSID_TBL         "Enabled"
#define DM_SSID_BAND            DM_SSID_TBL         "Band"
#define DM_SSID_ADVENABLED      DM_SSID_TBL         "AdvertisementEnabled"
#define DM_SSID_PASSPHRASE      DM_SSID_TBL         "Passphrase"
#define DM_SSID_AKMSALLOWED     DM_SSID_TBL         "AKMsAllowed"
#define DM_SSID_REFERENCE       DM_SSID_TBL         "Reference"
#define DM_SSID_DIRECTION       DM_SSID_TBL         "Direction"
#define DM_SSID_VID             DM_SSID_TBL         "X_AIRTIES_VID"
/* Device.WiFi.DataElements.Network.Device */
#define DM_DEVICE_TBL           DM_NETWORK_OBJ      "Device.{i}."
#define DM_DEVICE_ID            DM_DEVICE_TBL       "ID"
#define DM_DEVICE_MANU          DM_DEVICE_TBL       "Manufacturer"
#define DM_DEVICE_SERNO         DM_DEVICE_TBL       "SerialNumber"
#define DM_DEVICE_MODEL         DM_DEVICE_TBL       "ManufacturerModel"
#define DM_DEVICE_SWVER         DM_DEVICE_TBL       "SoftwareVersion"
#define DM_DEVICE_EXECENV       DM_DEVICE_TBL       "ExecutionEnv"
#define DM_DEVICE_CCODE         DM_DEVICE_TBL       "CountryCode"
#define DM_DEVICE_MAPPROFILE    DM_DEVICE_TBL       "MultiAPProfile"
#define DM_DEVICE_RADIONOE      DM_DEVICE_TBL       "RadioNumberOfEntries"
#define DM_DEVICE_CACSTATUSNOE  DM_DEVICE_TBL       "CACStatusNumberOfEntries"
#define DM_DEVICE_UNASSOC_STA_QUERY  DM_DEVICE_TBL  "X_AIRTIES_UnassociatedStaLinkMetricsQuery()"
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice */
#define DM_MULTIAPDEV_OBJ       DM_DEVICE_TBL       "MultiAPDevice."
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul */
#define DM_BACKHAUL_OBJ         DM_MULTIAPDEV_OBJ   "Backhaul."
#define DM_BACKHAUL_LINKTYPE    DM_BACKHAUL_OBJ     "LinkType"
#define DM_BACKHAUL_BHMACADDR   DM_BACKHAUL_OBJ     "BackhaulMACAddress"
#define DM_BACKHAUL_BHDEVICEID  DM_BACKHAUL_OBJ     "BackhaulDeviceID"
#define DM_BACKHAUL_MACADDRESS  DM_BACKHAUL_OBJ     "MACAddress"
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul.Stats */
#define DM_BHSTATS_OBJ          DM_BACKHAUL_OBJ     "Stats."
#define DM_BHSTATS_BYTESRCVD    DM_BHSTATS_OBJ      "BytesReceived"
#define DM_BHSTATS_BYTESSENT    DM_BHSTATS_OBJ      "BytesSent"
#define DM_BHSTATS_PACKETSRCVD  DM_BHSTATS_OBJ      "PacketsReceived"
#define DM_BHSTATS_PACKETSSENT  DM_BHSTATS_OBJ      "PacketsSent"
#define DM_BHSTATS_ERRORSRCVD   DM_BHSTATS_OBJ      "ErrorsReceived"
#define DM_BHSTATS_ERRORSSENT   DM_BHSTATS_OBJ      "ErrorsSent"
#define DM_BHSTATS_SIGNALSTR    DM_BHSTATS_OBJ      "SignalStrength"
#define DM_BHSTATS_LASTDTADLR   DM_BHSTATS_OBJ      "LastDataDownlinkRate"
#define DM_BHSTATS_LASTDTAULR   DM_BHSTATS_OBJ      "LastDataUplinkRate"
#define DM_BHSTATS_TSTAMP       DM_BHSTATS_OBJ      "TimeStamp"
/* Device.WiFi.DataElements.Network.Device.CACStatus */
#define DM_CACSTATUS_TBL        DM_DEVICE_TBL       "CACStatus.{i}."
#define DM_CACSTATUS_TSTAMP     DM_CACSTATUS_TBL    "TimeStamp"
#define DM_CACSTATUS_AVAILNOE   DM_CACSTATUS_TBL    "CACAvailableChannelNumberOfEntries"
#define DM_CACSTATUS_NONOCCNOE  DM_CACSTATUS_TBL    "CACNonOccupancyChannelNumberOfEntries"
#define DM_CACSTATUS_ACTIVENOE  DM_CACSTATUS_TBL    "CACActiveChannelNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.CACStatus.CACAvailableChannel */
#define DM_CACAVAIL_TBL         DM_CACSTATUS_TBL    "CACAvailableChannel.{i}."
#define DM_CACAVAIL_OPCLASS     DM_CACAVAIL_TBL     "OpClass"
#define DM_CACAVAIL_CHANNEL     DM_CACAVAIL_TBL     "Channel"
#define DM_CACAVAIL_MINUTES     DM_CACAVAIL_TBL     "Minutes"
/* Device.WiFi.DataElements.Network.Device.CACStatus.CACNonOccupancyChannel */
#define DM_CACNONOCC_TBL        DM_CACSTATUS_TBL    "CACNonOccupancyChannel.{i}."
#define DM_CACNONOCC_OPCLASS    DM_CACNONOCC_TBL    "OpClass"
#define DM_CACNONOCC_CHANNEL    DM_CACNONOCC_TBL    "Channel"
#define DM_CACNONOCC_SECONDS    DM_CACNONOCC_TBL    "Seconds"
/* Device.WiFi.DataElements.Network.Device.CACStatus.CACActiveChannel */
#define DM_CACACTIVE_TBL        DM_CACSTATUS_TBL    "CACActiveChannel.{i}."
#define DM_CACACTIVE_OPCLASS    DM_CACACTIVE_TBL    "OpClass"
#define DM_CACACTIVE_CHANNEL    DM_CACACTIVE_TBL    "Channel"
#define DM_CACACTIVE_COUNTDOWN  DM_CACACTIVE_TBL    "Countdown"
/* Device.WiFi.DataElements.Network.Device.Radio */
#define DM_RADIO_TBL            DM_DEVICE_TBL       "Radio.{i}."
#define DM_RADIO_ID             DM_RADIO_TBL        "ID"
#define DM_RADIO_ENABLED        DM_RADIO_TBL        "Enabled"
#define DM_RADIO_NOISE          DM_RADIO_TBL        "Noise"
#define DM_RADIO_UTILIZATION    DM_RADIO_TBL        "Utilization"
#define DM_RADIO_TRANSMIT       DM_RADIO_TBL        "Transmit"
#define DM_RADIO_RCVSELF        DM_RADIO_TBL        "ReceiveSelf"
#define DM_RADIO_RCVOTHER       DM_RADIO_TBL        "ReceiveOther"
#define DM_RADIO_TEMPERATURE    DM_RADIO_TBL        "X_AIRTIES_Temperature"
#define DM_RADIO_BSSNOE         DM_RADIO_TBL        "BSSNumberOfEntries"
#define DM_RADIO_CURROPCLASSNOE DM_RADIO_TBL        "CurrentOperatingClassProfileNumberOfEntries"
#define DM_RADIO_SCANRESULTNOE  DM_RADIO_TBL        "ScanResultNumberOfEntries"
#define DM_RADIO_CHSCANREQUEST  DM_RADIO_TBL        "ChannelScanRequest()"
#define DM_RADIO_UNASSOC_NOE    DM_RADIO_TBL        "UnassociatedSTANumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.BackhaulSta */
#define DM_BACKHAULSTA_OBJ      DM_RADIO_TBL        "BackhaulSta."
#define DM_BACKHAULSTA_MACADDR  DM_BACKHAULSTA_OBJ  "MACAddress"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities */
#define DM_CAPS_OBJ             DM_RADIO_TBL        "Capabilities."
#define DM_CAPS_HTCAPS          DM_CAPS_OBJ         "HTCapabilities"
#define DM_CAPS_VHTCAPS         DM_CAPS_OBJ         "VHTCapabilities"
#define DM_CAPS_HECAPS          DM_CAPS_OBJ         "HECapabilities"
#define DM_CAPS_CAPOPCLASSNOE   DM_CAPS_OBJ         "CapableOperatingClassProfileNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.CapableOperatingClassProfile */
#define DM_CAPOPCLASS_TBL       DM_CAPS_OBJ         "CapableOperatingClassProfile.{i}."
#define DM_CAPOPCLASS_CLASS     DM_CAPOPCLASS_TBL   "Class"
#define DM_CAPOPCLASS_MAXTSPOW  DM_CAPOPCLASS_TBL   "MaxTxPower"
#define DM_CAPOPCLASS_NONOPER   DM_CAPOPCLASS_TBL   "NonOperable"
#define DM_CAPOPCLASS_NONONOPER DM_CAPOPCLASS_TBL   "NumberOfNonOperChan"
/* Device.WiFi.DataElements.Network.Device.Radio.MultiAPRadio */
#define DM_MULTIAPRAD_OBJ       DM_RADIO_TBL        "MultiAPRadio."
#define DM_MULTIAPRAD_CHSCAN    DM_MULTIAPRAD_OBJ   "ChannelScan()"
#define DM_MULTIAPRAD_FULLSCAN  DM_MULTIAPRAD_OBJ   "FullScan()"
/* Device.WiFi.DataElements.Network.Device.Radio.CurrentOperatingClassProfile */
#define DM_CURROPCLASS_TBL      DM_RADIO_TBL        "CurrentOperatingClassProfile.{i}."
#define DM_CURROPCLASS_CLASS    DM_CURROPCLASS_TBL  "Class"
#define DM_CURROPCLASS_CHANNEL  DM_CURROPCLASS_TBL  "Channel"
#define DM_CURROPCLASS_TXPOWER  DM_CURROPCLASS_TBL  "TxPower"
#define DM_CURROPCLASS_TSTAMP   DM_CURROPCLASS_TBL  "TimeStamp"
/* Device.WiFi.DataElements.Network.Device.Radio.ScanResult */
#define DM_SCANRES_TBL          DM_RADIO_TBL        "ScanResult.{i}."
#define DM_SCANRES_TSTAMP       DM_SCANRES_TBL      "TimeStamp"
#define DM_SCANRES_OPCLASSNOE   DM_SCANRES_TBL      "OpClassScanNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.ScanResult.OpClassScan */
#define DM_OPCLSCAN_TBL         DM_SCANRES_TBL      "OpClassScan.{i}."
#define DM_OPCLSCAN_OPCLASS     DM_OPCLSCAN_TBL     "OperatingClass"
#define DM_OPCLSCAN_CHANNELNOE  DM_OPCLSCAN_TBL     "ChannelScanNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.ScanResult.OpClassScan.ChannelScan */
#define DM_CHSCAN_TBL           DM_OPCLSCAN_TBL     "ChannelScan.{i}."
#define DM_CHSCAN_CHANNEL       DM_CHSCAN_TBL       "Channel"
#define DM_CHSCAN_TSTAMP        DM_CHSCAN_TBL       "TimeStamp"
#define DM_CHSCAN_UTILIZATION   DM_CHSCAN_TBL       "Utilization"
#define DM_CHSCAN_NOISE         DM_CHSCAN_TBL       "Noise"
#define DM_CHSCAN_NEIGHBSSNOE   DM_CHSCAN_TBL       "NeighborBSSNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.ScanResult.OpClassScan.ChannelScan.NeighborBSS */
#define DM_NEIGHBSS_TBL         DM_CHSCAN_TBL       "NeighborBSS.{i}."
#define DM_NEIGHBSS_BSSID       DM_NEIGHBSS_TBL     "BSSID"
#define DM_NEIGHBSS_SSID        DM_NEIGHBSS_TBL     "SSID"
#define DM_NEIGHBSS_SIGNALSTR   DM_NEIGHBSS_TBL     "SignalStre"
#define DM_NEIGHBSS_CHANBW      DM_NEIGHBSS_TBL     "ChannelBan"
#define DM_NEIGHBSS_CHANUTIL    DM_NEIGHBSS_TBL     "ChannelUti"
#define DM_NEIGHBSS_STACOUNT    DM_NEIGHBSS_TBL     "StationCou"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS */
#define DM_BSS_TBL              DM_RADIO_TBL        "BSS.{i}."
#define DM_BSS_BSSID            DM_BSS_TBL          "BSSID"
#define DM_BSS_SSID             DM_BSS_TBL          "SSID"
#define DM_BSS_ENABLED          DM_BSS_TBL          "Enabled"
#define DM_BSS_LASTCHANGE       DM_BSS_TBL          "LastChange"
#define DM_BSS_TSTAMP           DM_BSS_TBL          "TimeStamp"
#define DM_BSS_UCASTBYTESRCVD   DM_BSS_TBL          "UnicastBytesReceived"
#define DM_BSS_UCASTBYTESSENT   DM_BSS_TBL          "UnicastBytesSent"
#define DM_BSS_MCASTBYTESRCVD   DM_BSS_TBL          "MulticastBytesReceived"
#define DM_BSS_MCASTBYTESSENT   DM_BSS_TBL          "MulticastBytesSent"
#define DM_BSS_BCASTBYTESRCVD   DM_BSS_TBL          "BroadcastBytesReceived"
#define DM_BSS_BCASTBYTESSENT   DM_BSS_TBL          "BroadcastBytesSent"
#define DM_BSS_BACKHAULUSE      DM_BSS_TBL          "BackhaulUse"
#define DM_BSS_FRONTHAULUSE     DM_BSS_TBL          "FronthaulUse"
#define DM_BSS_FHAKMSALLOWED    DM_BSS_TBL          "FronthaulAKMsAllowed"
#define DM_BSS_BHAKMSALLOWED    DM_BSS_TBL          "BackhaulAKMsAllowed"
#define DM_BSS_STANOE           DM_BSS_TBL          "STANumberOfEntries"
#define DM_BSS_CLIASSOCCTRL     DM_BSS_TBL          "X_AIRTIES_ClientAssocControl()"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA */
#define DM_STA_TBL              DM_BSS_TBL          "STA.{i}."
#define DM_STA_MACADDRESS       DM_STA_TBL          "MACAddress"
#define DM_STA_TSTAMP           DM_STA_TBL          "TimeStamp"
#define DM_STA_HTCAPS           DM_STA_TBL          "HTCapabilities"
#define DM_STA_VHTCAPS          DM_STA_TBL          "VHTCapabilities"
#define DM_STA_HECAPS           DM_STA_TBL          "HECapabilities"
#define DM_STA_CLIENTCAPS       DM_STA_TBL          "ClientCapabilities"
#define DM_STA_LASTDTADLINKR    DM_STA_TBL          "LastDataDownlinkRate"
#define DM_STA_LASTDTAULINKR    DM_STA_TBL          "LastDataUplinkRate"
#define DM_STA_UTILIZATIONRX    DM_STA_TBL          "UtilizationReceive"
#define DM_STA_UTILIZATIONTX    DM_STA_TBL          "UtilizationTransmit"
#define DM_STA_ESTMACDRDL       DM_STA_TBL          "EstMACDataRateDownlink"
#define DM_STA_ESTMACDRUL       DM_STA_TBL          "EstMACDataRateUplink"
#define DM_STA_SIGNALSTRENGTH   DM_STA_TBL          "SignalStrength"
#define DM_STA_LASTCONTIME      DM_STA_TBL          "LastConnectTime"
#define DM_STA_BYTESRCVD        DM_STA_TBL          "BytesReceived"
#define DM_STA_BYTESSENT        DM_STA_TBL          "BytesSent"
#define DM_STA_PACKETSRCVD      DM_STA_TBL          "PacketsReceived"
#define DM_STA_PACKETSSENT      DM_STA_TBL          "PacketsSent"
#define DM_STA_ERRORSRCVD       DM_STA_TBL          "ErrorsReceived"
#define DM_STA_ERRORSSENT       DM_STA_TBL          "ErrorsSent"
#define DM_STA_RETRANSCNT       DM_STA_TBL          "RetransCount"
#define DM_STA_MEASUREREP       DM_STA_TBL          "MeasurementReport"
#define DM_STA_NOMEASUREREP     DM_STA_TBL          "NumberOfMeasureReports"
#define DM_STA_BEACNMETRCSQUERY DM_STA_TBL          "X_AIRTIES_BeaconMetricsQuery()"
#define DM_STA_CLIENTSTEER      DM_STA_TBL          "ClientSteer()"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA.MultiAPSTA */
#define DM_MULTIAPSTA_OBJ       DM_STA_TBL          "MultiAPSTA."
#define DM_MULTIAPSTA_STEHISNOE DM_MULTIAPSTA_OBJ   "SteeringHistoryNumberOfEntries"
#define DM_MULTIAPSTA_DISASSOC  DM_MULTIAPSTA_OBJ   "Disassociate()"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA.MultiAPSTA.SteeringSummaryStats */
#define DM_STEERSUMST_OBJ       DM_MULTIAPSTA_OBJ   "SteeringSummaryStats."
#define DM_STEERSUM_NOCANDFAIL  DM_STEERSUMST_OBJ   "NoCandidateAPFailures"
#define DM_STEERSUM_BLCKLSTATT  DM_STEERSUMST_OBJ   "BlacklistAttempts"
#define DM_STEERSUM_BLCKLSTSUCC DM_STEERSUMST_OBJ   "BlacklistSuccesses"
#define DM_STEERSUM_BLCKLSTFAIL DM_STEERSUMST_OBJ   "BlacklistFailures"
#define DM_STEERSUM_BTMATTEMPT  DM_STEERSUMST_OBJ   "BTMAttempts"
#define DM_STEERSUM_BTMSUCCESS  DM_STEERSUMST_OBJ   "BTMSuccesses"
#define DM_STEERSUM_BTMFAILURE  DM_STEERSUMST_OBJ   "BTMFailures"
#define DM_STEERSUM_BTMQUERYRSP DM_STEERSUMST_OBJ   "BTMQueryResponses"
#define DM_STEERSUM_LASTSTEERTM DM_STEERSUMST_OBJ   "LastSteerTime"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA.MultiAPSTA.SteeringHistory */
#define DM_STEERHIST_TBL        DM_MULTIAPSTA_OBJ   "SteeringHistory.{i}."
#define DM_STEERHIST_TIME       DM_STEERHIST_TBL    "Time"
#define DM_STEERHIST_APORIGIN   DM_STEERHIST_TBL    "APOrigin"
#define DM_STEERHIST_TRIGGEREVE DM_STEERHIST_TBL    "TriggerEvent"
#define DM_STEERHIST_STEERAPP   DM_STEERHIST_TBL    "SteeringApproach"
#define DM_STEERHIST_APDEST     DM_STEERHIST_TBL    "APDestination"
#define DM_STEERHIST_STEERDUR   DM_STEERHIST_TBL    "SteeringDuration"
/* Device.WiFi.DataElements.Network.Device.Radio.UnassociatedSTA */
#define DM_UNASSOC_TBL          DM_RADIO_TBL        "UnassociatedSTA.{i}."
#define DM_UNASSOC_MAC          DM_UNASSOC_TBL      "MACAddress"
#define DM_UNASSOC_SIGNALSTRENGTH DM_UNASSOC_TBL    "SignalStrength"
#define DM_UNASSOC_TIMESTAMP    DM_UNASSOC_TBL      "TimeStamp"
/* Device.WiFi.DataElements.Network.Device.X_AIRTIES_Ethernet */
#define DM_ETHERNET_OBJ         DM_DEVICE_TBL       "X_AIRTIES_Ethernet."
#define DM_ETHERNET_IFACENOE    DM_ETHERNET_OBJ     "InterfaceNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.X_AIRTIES_Ethernet.Interface */
#define DM_ETHIFACE_TBL         DM_ETHERNET_OBJ     "Interface.{i}."
#define DM_ETHIFACE_MACADDR     DM_ETHIFACE_TBL     "MACAddress"
#define DM_ETHIFACE_DEVICENOE   DM_ETHIFACE_TBL     "DeviceNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.X_AIRTIES_Ethernet.Interface.Device */
#define DM_ETHDEVICE_TBL        DM_ETHIFACE_TBL     "Device.{i}."
#define DM_ETHDEVICE_MACADDR    DM_ETHDEVICE_TBL    "MACAddress"
/* Device.WiFi.DataElements.Network.Device.X_AIRTIES_DeviceInfo */
#define DM_DEVINFO_OBJ          DM_DEVICE_TBL       "X_AIRTIES_DeviceInfo."
#define DM_DEVINFO_UPTIME       DM_DEVINFO_OBJ      "Uptime"
/* Device.WiFi.DataElements.Network.Device.X_AIRTIES_DeviceInfo.MemoryStatus */
#define DM_MEMSTATUS_OBJ        DM_DEVINFO_OBJ      "MemoryStatus."
#define DM_MEMSTATUS_TOTAL      DM_MEMSTATUS_OBJ    "Total"
#define DM_MEMSTATUS_FREE       DM_MEMSTATUS_OBJ    "Free"
#define DM_MEMSTATUS_CACHED     DM_MEMSTATUS_OBJ    "Cached"
/* Device.WiFi.DataElements.Network.Device.X_AIRTIES_DeviceInfo.ProcessStatus */
#define DM_PROCSTATUS_OBJ       DM_DEVINFO_OBJ      "ProcessStatus."
#define DM_PROCSTATUS_CPUUSAGE  DM_PROCSTATUS_OBJ   "CPUUsage"
#define DM_PROCSTATUS_CPUTEMP   DM_PROCSTATUS_OBJ   "CPUTemperature"
/* Device.WiFi.DataElements.AssociationEvent */
#define DM_ASSOCEVT_OBJ         DM_DATAELEMS_OBJ    "AssociationEvent."
#define DM_ASSOCEVT_DATANOE     DM_ASSOCEVT_OBJ     "AssociationEventDataNumberOfEntries"
#define DM_ASSOCEVT_ASSOCIATED  DM_ASSOCEVT_OBJ     "Associated!"
/* Device.WiFi.DataElements.AssociationEvent.AssociationEventData */
#define DM_ASSOCDTA_TBL         DM_ASSOCEVT_OBJ     "AssociationEventData.{i}."
#define DM_ASSOCDTA_MACADDR     DM_ASSOCDTA_TBL     "MACAddress"
#define DM_ASSOCDTA_BSSID       DM_ASSOCDTA_TBL     "BSSID"
#define DM_ASSOCDTA_STATUS      DM_ASSOCDTA_TBL     "StatusCode"
#define DM_ASSOCDTA_TSTAMP      DM_ASSOCDTA_TBL     "TimeStamp"
/* Device.WiFi.DataElements.DisassociationEvent */
#define DM_DISASSEVT_OBJ        DM_DATAELEMS_OBJ    "DisassociationEvent."
#define DM_DISASSEVT_DATANOE    DM_DISASSEVT_OBJ    "DisassociationEventDataNumberOfEntries"
#define DM_DISASSEVT_DISASSOCED DM_DISASSEVT_OBJ    "Disassociated!"
/* Device.WiFi.DataElements.DisassociationEvent.DisassociationEventData */
#define DM_DISASSDTA_TBL        DM_DISASSEVT_OBJ    "DisassociationEventData.{i}."
#define DM_DISASSDTA_MACADDR    DM_DISASSDTA_TBL    "MACAddress"
#define DM_DISASSDTA_BSSID      DM_DISASSDTA_TBL    "BSSID"
#define DM_DISASSDTA_REASON     DM_DISASSDTA_TBL    "ReasonCode"
#define DM_DISASSDTA_TSTAMP     DM_DISASSDTA_TBL    "TimeStamp"
/* Device.WiFi.DataElements.FailedConnectionEvent */
#define DM_FAILCONNEVT_OBJ      DM_DATAELEMS_OBJ    "FailedConnectionEvent."
#define DM_FAILCONNEVT_DATANOE  DM_FAILCONNEVT_OBJ  "FailedConnectionEventDataNumberOfEntries"
#define DM_FAILCONNEVT_FAILCONN DM_FAILCONNEVT_OBJ  "FailedConnection!"
/* Device.WiFi.DataElements.FailedConnectionEvent.FailedConnectionEventData */
#define DM_FAILCONNDTA_TBL      DM_FAILCONNEVT_OBJ  "FailedConnectionEventData.{i}."
#define DM_FAILCONNDTA_MACADDR  DM_FAILCONNDTA_TBL  "MACAddress"
#define DM_FAILCONNDTA_BSSID    DM_FAILCONNDTA_TBL  "BSSID"
#define DM_FAILCONNDTA_STATUS   DM_FAILCONNDTA_TBL  "StatusCode"
#define DM_FAILCONNDTA_REASON   DM_FAILCONNDTA_TBL  "ReasonCode"
#define DM_FAILCONNDTA_TSTAMP   DM_FAILCONNDTA_TBL  "TimeStamp"

/* Missing Methods */
#define DM_NETWORK_SETTRAFFSEP  DM_NETWORK_OBJ      "SetTrafficSeparation()"
#define DM_NETWORK_SETSERVPRIO  DM_NETWORK_OBJ      "SetServicePriorization()"
#define DM_NETWORK_SETPREFBHAUL DM_NETWORK_OBJ      "SetPreferredBackhauls()"
#define DM_NETWORK_SETMSCSDIS   DM_NETWORK_OBJ      "SetMSCSDisallowed()"
#define DM_NETWORK_SETSCSDIS    DM_NETWORK_OBJ      "SetSCSDisallowed()"
#define DM_DEVICE_SETSTASTSTATE DM_DEVICE_TBL       "SetSTASteeringState()"
#define DM_DEVICE_SETDFSSTATE   DM_DEVICE_TBL       "SetDFSState()"
#define DM_DEVICE_SETANTCHPREF  DM_DEVICE_TBL       "SetAnticipatedChannelPreference()"
#define DM_BACKHAUL_STEERWIFIBH DM_BACKHAUL_OBJ     "SteerWiFiBackhaul()"
#define DM_RADIO_RADIOENABLE    DM_RADIO_TBL        "RadioEnable()"
#define DM_RADIO_SETTXPOWERLIM  DM_RADIO_TBL        "SetTxPowerLimit()"
#define DM_RADIO_SETSPATREUSE   DM_RADIO_TBL        "SetSpatialReuse()"
#define DM_RADIO_WIFIRESTART    DM_RADIO_TBL        "WiFiRestart()"
#define DM_MULTIAPSTA_BTMREQ    DM_MULTIAPSTA_OBJ   "BTMRequest()"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
/* Forward declarations */
struct dm_scan_table_s;
struct dm_opcl_table_s;
struct dm_chan_table_s;
struct dm_radio_table_s;

typedef struct dm_nbss_table_s {
    unsigned int      idx;
    mac_addr          id;

    list_head_t       list;

    struct dm_chan_table_s *dm_chan;
} dm_nbss_table_t;

typedef struct dm_chan_table_s {
    unsigned int      idx;
    unsigned int      id;

    list_head_t       list;

    unsigned int      nbss_idx;
    unsigned int      nbss_cnt;
    list_head_t       nbss_list;

    struct dm_opcl_table_s *dm_opcl;
} dm_chan_table_t;

typedef struct dm_opcl_table_s {
    unsigned int      idx;
    unsigned int      id;

    list_head_t       list;

    unsigned int      chan_idx;
    unsigned int      chan_cnt;
    list_head_t       chan_list;

    struct dm_scan_table_s *dm_scan;
} dm_opcl_table_t;

typedef struct dm_scan_table_s {
    unsigned int      idx;
    unsigned int      id;

    list_head_t       list;

    unsigned int      opcl_idx;
    unsigned int      opcl_cnt;
    list_head_t       opcl_list;

    struct dm_radio_table_s *dm_radio;
} dm_scan_table_t;

typedef struct dm_sta_payload_s {
    rbusMethodAsyncHandle_t rbus_steering_async_hnd;
} dm_sta_payload_t;

typedef struct dm_sta_table_s {
    const char       *sta_id;
    rbusMethodAsyncHandle_t bmquery_reply;
} dm_sta_table_t;

typedef struct dm_bss_table_s {
    const char       *bss_id;
    dm_sta_table_t    dm_sta[MAX_STATION_PER_BSS];
} dm_bss_table_t;

typedef struct dm_radio_table_s {
    const char       *radio_id;
    unsigned int      capops;
    unsigned int      currops;

    dm_bss_table_t    dm_bss[MAX_BSS_PER_RADIO];

    unsigned int      scan_idx;
    unsigned int      scan_cnt;
    list_head_t       scan_list;
    unsigned int      nbss_cnt;
    rbusMethodAsyncHandle_t scan_reply;
} dm_radio_table_t;

typedef struct dm_ethif_table_s {
    unsigned int      eth_devs;
} dm_ethif_table_t;

typedef struct dm_dev_table_s {
    char             *al_mac;

    bool              cac_valid;
    unsigned int      cac_avail;
    unsigned int      cac_nonocc;
    unsigned int      cac_active;
    unsigned int      eth_ifaces;

    dm_radio_table_t  dm_radio[MAX_RADIO_PER_AGENT];

    dm_ethif_table_t  dm_ethif[MAX_IFACE_PER_AGENT];
    rbusMethodAsyncHandle_t unassoc_sta_link_metrics_query_handle;
} dm_dev_table_t;

typedef struct dm_evt_table_s {
    uint16_t          assoc_idx;
    uint16_t          assoc_sub_cnt;

    uint16_t          disassoc_idx;
    uint16_t          disassoc_sub_cnt;

    uint16_t          failconn_idx;
    uint16_t          failconn_sub_cnt;
} dm_evt_table_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static dm_dev_table_t g_dm_dev_table[MAX_DEVICE_PER_NETWORK];
static dm_evt_table_t g_dm_evt_table;

static rbusHandle_t   g_bus_handle;

static int dm_rbus_remove_scan(dm_scan_table_t *dm_scan, bool rm_row,
    unsigned int didx, unsigned int ridx);

/*#######################################################################
#                       INDEX HELPERS                                   #
########################################################################*/
static rbusMethodAsyncHandle_t get_device_unassoc_sta_link_metrics_query_reply(map_ale_info_t *ale);
static void set_device_unassoc_sta_link_metrics_query_reply(map_ale_info_t *ale,
                                                            rbusMethodAsyncHandle_t async_handle);

static inline bool is_controller_mac(mac_addr mac)
{
    return !maccmp(mac, map_cfg_get()->controller_cfg.al_mac);
}

static inline bool is_local_agent(map_ale_info_t *ale)
{
    return ale->is_local;
}

static void remove_all_ap_device(void)
{
    if (g_dm_dev_table[0].al_mac) {
        free(g_dm_dev_table[0].al_mac);
    }
    memset(&g_dm_dev_table, 0, sizeof(g_dm_dev_table));
}

static int get_dev_dm_idx(mac_addr_str al_mac_str, unsigned int *didx)
{
    unsigned int idx = 0;

    while (g_dm_dev_table[idx].al_mac) {
        if (++idx >= MAX_DEVICE_PER_NETWORK) {
            return -1;
        }
    }

    g_dm_dev_table[idx].al_mac = strdup(al_mac_str);

    *didx = idx;

    return 0;
}

static void get_dev_dm_cac_valid(map_ale_info_t *ale, bool *cac_valid)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    *cac_valid = dm_dev->cac_valid;
}

static void get_dev_dm_cac_avail(map_ale_info_t *ale, unsigned int *cac_avail)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    *cac_avail = dm_dev->cac_avail;
}

static void get_dev_dm_cac_nonocc(map_ale_info_t *ale, unsigned int *cac_nonocc)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    *cac_nonocc = dm_dev->cac_nonocc;
}

static void get_dev_dm_cac_active(map_ale_info_t *ale, unsigned int *cac_active)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    *cac_active = dm_dev->cac_active;
}

static void get_dev_dm_eth_ifaces(map_ale_info_t *ale, unsigned int *eth_ifaces)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    *eth_ifaces = dm_dev->eth_ifaces;
}

static void get_dev_dm_eth_devs(map_ale_info_t *ale, unsigned int iidx, unsigned int *eth_devs)
{
    dm_ethif_table_t *dm_ethif;

    dm_ethif = &g_dm_dev_table[ale->dm_idx].dm_ethif[iidx];
    *eth_devs = dm_ethif->eth_devs;
}

static void set_dev_dm_cac_valid(map_ale_info_t *ale, bool cac_valid)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    dm_dev->cac_valid = cac_valid;
}

static void set_dev_dm_cac_avail(map_ale_info_t *ale, unsigned int cac_avail)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    dm_dev->cac_avail = cac_avail;
}

static void set_dev_dm_cac_nonocc(map_ale_info_t *ale, unsigned int cac_nonocc)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    dm_dev->cac_nonocc = cac_nonocc;
}

static void set_dev_dm_cac_active(map_ale_info_t *ale, unsigned int cac_active)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    dm_dev->cac_active = cac_active;
}

static void set_dev_dm_eth_ifaces(map_ale_info_t *ale,  unsigned int eth_ifaces)
{
    dm_dev_table_t *dm_dev;

    dm_dev = &g_dm_dev_table[ale->dm_idx];
    if (eth_ifaces < dm_dev->eth_ifaces) {
        memset(&g_dm_dev_table[ale->dm_idx].dm_ethif[eth_ifaces], 0,
            (dm_dev->eth_ifaces - eth_ifaces) * sizeof(dm_ethif_table_t));
    }
    dm_dev->eth_ifaces = eth_ifaces;
}

static void set_dev_dm_eth_devs(map_ale_info_t *ale, unsigned int iidx, unsigned int eth_devs)
{
    dm_ethif_table_t *dm_ethif;

    dm_ethif = &g_dm_dev_table[ale->dm_idx].dm_ethif[iidx];
    dm_ethif->eth_devs = eth_devs;
}

static int check_dev_dm_idx(map_ale_info_t *ale)
{
    if (ale->dm_idx < 0) {
        return -1;
    }

    return 0;
}

static inline void free_dev_dm_idx(unsigned int didx)
{
    if (g_dm_dev_table[didx].al_mac) {
        free(g_dm_dev_table[didx].al_mac);
    }
    memset(&g_dm_dev_table[didx], 0, sizeof(dm_dev_table_t));
}

static int get_radio_dm_idx(unsigned int didx,
                            map_radio_info_t *radio, unsigned int *ridx)
{
    dm_dev_table_t *dm_dev;
    unsigned int    idx = 0;

    dm_dev = &g_dm_dev_table[didx];
    while (dm_dev->dm_radio[idx].radio_id) {
        if (++idx >= MAX_RADIO_PER_AGENT) {
            return -1;
        }
    }

    dm_dev->dm_radio[idx].radio_id = radio->radio_id_str;

    INIT_LIST_HEAD(&dm_dev->dm_radio[idx].scan_list);

    radio->dm_idx = *ridx = idx;

    return 0;
}

static void get_radio_dm_capops(map_radio_info_t *radio, unsigned int *capops)
{
    dm_radio_table_t *dm_radio;

    dm_radio = &g_dm_dev_table[radio->ale->dm_idx].dm_radio[radio->dm_idx];
    *capops = dm_radio->capops;
}

static void get_radio_dm_currops(map_radio_info_t *radio, unsigned int *currops)
{
    dm_radio_table_t *dm_radio;

    dm_radio = &g_dm_dev_table[radio->ale->dm_idx].dm_radio[radio->dm_idx];
    *currops = dm_radio->currops;
}

static void get_radio_dm_scan_reply(map_radio_info_t *radio, rbusMethodAsyncHandle_t *scan_reply)
{
    dm_radio_table_t *dm_radio;

    dm_radio = &g_dm_dev_table[radio->ale->dm_idx].dm_radio[radio->dm_idx];
    *scan_reply = dm_radio->scan_reply;
}

static dm_scan_table_t *get_dm_radio_scan(dm_radio_table_t *dm_radio, unsigned int scan_idx)
{
    dm_scan_table_t *dm_scan;

    list_for_each_entry(dm_scan, &dm_radio->scan_list, list) {
        if (scan_idx == dm_scan->idx) {
            return dm_scan;
        }
    }

    return NULL;
}

static dm_scan_table_t *get_radio_dm_scan(map_radio_info_t *radio, unsigned int scan_idx)
{
    dm_radio_table_t *dm_radio;

    dm_radio = &g_dm_dev_table[radio->ale->dm_idx].dm_radio[radio->dm_idx];
    return get_dm_radio_scan(dm_radio, scan_idx);
}

static dm_opcl_table_t *get_dm_scan_opcl(dm_scan_table_t *dm_scan, unsigned int opcl_idx)
{
    dm_opcl_table_t *dm_opcl;

    list_for_each_entry(dm_opcl, &dm_scan->opcl_list, list) {
        if (opcl_idx == dm_opcl->idx) {
            return dm_opcl;
        }
    }

    return NULL;
}

static dm_chan_table_t *get_dm_opcl_chan(dm_opcl_table_t *dm_opcl, unsigned int chan_idx)
{
    dm_chan_table_t *dm_chan;

    list_for_each_entry(dm_chan, &dm_opcl->chan_list, list) {
        if (chan_idx == dm_chan->idx) {
            return dm_chan;
        }
    }

    return NULL;
}

static dm_nbss_table_t *get_dm_chan_nbss(dm_chan_table_t *dm_chan, unsigned int nbss_idx)
{
    dm_nbss_table_t *dm_nbss;

    list_for_each_entry(dm_nbss, &dm_chan->nbss_list, list) {
        if (nbss_idx == dm_nbss->idx) {
            return dm_nbss;
        }
    }

    return NULL;
}

static void set_radio_dm_capops(map_radio_info_t *radio, unsigned int capops)
{
    dm_radio_table_t *dm_radio;

    dm_radio = &g_dm_dev_table[radio->ale->dm_idx].dm_radio[radio->dm_idx];
    dm_radio->capops = capops;
}

static void set_radio_dm_currops(map_radio_info_t *radio, unsigned int currops)
{
    dm_radio_table_t *dm_radio;

    dm_radio = &g_dm_dev_table[radio->ale->dm_idx].dm_radio[radio->dm_idx];
    dm_radio->currops = currops;
}

static void set_radio_dm_scan_reply(map_radio_info_t *radio, rbusMethodAsyncHandle_t scan_reply)
{
    dm_radio_table_t *dm_radio;

    dm_radio = &g_dm_dev_table[radio->ale->dm_idx].dm_radio[radio->dm_idx];
    dm_radio->scan_reply = scan_reply;
}

static int check_radio_dm_idx(map_radio_info_t *radio)
{
    if (radio->dm_idx < 0) {
        return -1;
    }

    return check_dev_dm_idx(radio->ale);
}

static void free_radio_dm_idx(unsigned int didx, unsigned int ridx)
{
    dm_radio_table_t *dm_radio;
    dm_scan_table_t  *dm_scan, *next;

    dm_radio = &g_dm_dev_table[didx].dm_radio[ridx];

    /* Cleanup dm_scan nodes under the radio */
    list_for_each_entry_safe(dm_scan, next, &dm_radio->scan_list, list) {
        dm_rbus_remove_scan(dm_scan, false, didx, ridx);
        dm_radio->scan_cnt--;
    }

    memset(&g_dm_dev_table[didx].dm_radio[ridx], 0, sizeof(dm_radio_table_t));
}

static int get_bss_dm_idx(unsigned int didx, unsigned int ridx,
                          map_bss_info_t *bss, unsigned  int *bidx)
{
    dm_radio_table_t *dm_radio;
    unsigned int      idx = 0;

    dm_radio = &g_dm_dev_table[didx].dm_radio[ridx];
    while (dm_radio->dm_bss[idx].bss_id) {
        if (++idx >= MAX_BSS_PER_RADIO) {
            return -1;
        }
    }

    dm_radio->dm_bss[idx].bss_id = bss->bssid_str;

    bss->dm_idx = *bidx = idx;

    return 0;
}

static int check_bss_dm_idx(map_bss_info_t *bss)
{
    if (bss->dm_idx < 0) {
        return -1;
    }

    return check_radio_dm_idx(bss->radio);
}

static inline void free_bss_dm_idx(unsigned int didx, unsigned int ridx,
                                   unsigned int bidx)
{
    memset(&g_dm_dev_table[didx].dm_radio[ridx].dm_bss[bidx], 0,
        sizeof(dm_bss_table_t));
}

static int get_sta_dm_idx(unsigned int didx, unsigned int ridx, unsigned int bidx,
                          map_sta_info_t *sta, unsigned int *sidx)
{
    dm_bss_table_t *dm_bss;
    unsigned int    idx = 0;

    dm_bss = &g_dm_dev_table[didx].dm_radio[ridx].dm_bss[bidx];
    while (dm_bss->dm_sta[idx].sta_id) {
        if (++idx >= MAX_STATION_PER_BSS) {
            return -1;
        }
    }

    dm_bss->dm_sta[idx].sta_id = sta->mac_str;

    sta->dm_idx = *sidx = idx;

    return 0;
}

static int check_sta_dm_idx(map_sta_info_t *sta)
{
    if (sta->dm_idx < 0) {
        return -1;
    }

    return check_bss_dm_idx(sta->bss);
}

static inline void free_sta_dm_idx(unsigned int didx, unsigned int ridx,
                                   unsigned int bidx, unsigned int sidx)
{
    g_dm_dev_table[didx].dm_radio[ridx].dm_bss[bidx].dm_sta[sidx].sta_id = NULL;
}

static void update_ale_idxs(map_ale_info_t *removed_ale)
{
    map_ale_info_t *ale;
    unsigned int    idx;

    map_dm_foreach_agent_ale(ale) {
        if (!is_local_agent(ale) && ale != removed_ale) {
            ale->dm_idx = -1;
            get_dev_dm_idx(ale->al_mac_str, &idx);
            ale->dm_idx = idx;
        }
    }
}

static void update_radio_idxs(map_ale_info_t *ale, map_radio_info_t *removed_radio)
{
    map_radio_info_t *radio;
    unsigned int      idx;

    map_dm_foreach_radio(ale, radio) {
        if (radio != removed_radio) {
            radio->dm_idx = -1;
            get_radio_dm_idx(ale->dm_idx, radio, &idx);
        }
    }
}

static void update_bss_idxs(map_radio_info_t *radio, map_bss_info_t *removed_bss)
{
    map_bss_info_t *bss;
    unsigned int    idx;

    map_dm_foreach_bss(radio, bss) {
        if (bss != removed_bss) {
            bss->dm_idx = -1;
            get_bss_dm_idx(radio->ale->dm_idx, radio->dm_idx, bss, &idx);
        }
    }
}

static void update_sta_idxs(map_bss_info_t *bss, map_sta_info_t *removed_sta)
{
    map_sta_info_t *sta;
    unsigned int    idx;

    map_dm_foreach_sta(bss, sta) {
        if (sta != removed_sta) {
            sta->dm_idx = -1;
            get_sta_dm_idx(bss->radio->ale->dm_idx,
                bss->radio->ale->dm_idx, bss->radio->dm_idx, sta, &idx);
        }
    }
}

static dm_sta_table_t *get_dm_sta(map_sta_info_t *sta)
{
    unsigned int ale_idx;
    unsigned int radio_idx;
    unsigned int bss_idx;
    unsigned int sta_idx;

    if (sta->dm_removed) {
        log_lib_e("Sta was removed already: %s", sta->mac_str);
        return NULL;
    }

    if (check_sta_dm_idx(sta) < 0) {
        log_lib_e("Invalid indexing for sta: %s", sta->mac_str);
        return NULL;
    }

    sta_idx   = sta->dm_idx;
    bss_idx   = sta->bss->dm_idx;
    radio_idx = sta->bss->radio->dm_idx;
    ale_idx   = sta->bss->radio->ale->dm_idx;

    return &g_dm_dev_table[ale_idx].dm_radio[radio_idx].dm_bss[bss_idx].dm_sta[sta_idx];
}

static void mark_stas_removed(map_bss_info_t *bss)
{
    map_sta_info_t *sta;

    map_dm_foreach_sta(bss, sta) {
        sta->dm_removed = true;
    }
}

static void mark_bsss_removed(map_radio_info_t *radio)
{
    map_bss_info_t *bss;

    map_dm_foreach_bss(radio, bss) {
        bss->dm_removed = true;
        mark_stas_removed(bss);
    }
}

static void mark_radios_removed(map_ale_info_t *ale)
{
    map_radio_info_t *radio;

    map_dm_foreach_radio(ale, radio) {
        radio->dm_removed = true;
        mark_bsss_removed(radio);
    }
}

static int get_sta_dm_bmquery_reply(map_sta_info_t *sta, rbusMethodAsyncHandle_t *reply)
{
    dm_sta_table_t *dm_sta = NULL;

    dm_sta = get_dm_sta(sta);
    if (dm_sta == NULL) {
        log_lib_e("Failed to get dm_sta entry: %s", sta->mac_str);
        *reply = NULL;
        return -1;
    }

    *reply = dm_sta->bmquery_reply;

    return 0;
}

static int set_sta_dm_bmquery_reply(map_sta_info_t *sta, rbusMethodAsyncHandle_t reply)
{
    dm_sta_table_t *dm_sta = NULL;

    dm_sta = get_dm_sta(sta);
    if (dm_sta == NULL) {
        log_lib_e("Failed to get dm_sta entry: %s", sta->mac_str);
        return -1;
    }

    dm_sta->bmquery_reply = reply;

    return 0;
}

static int map_dm_rbus_client_steer_async_reply_set(map_sta_info_t *sta_info, rbusMethodAsyncHandle_t reply)
{
    dm_sta_payload_t *sta_payload = NULL;

    if (!sta_info) {
        return -1;
    }

    sta_payload = (dm_sta_payload_t *)sta_info->dm_payload;
    if (!sta_payload) {
        return -1;
    }

    sta_payload->rbus_steering_async_hnd = reply;

    return 0;
}

static int map_dm_rbus_client_steer_async_reply_get(map_sta_info_t *sta_info, rbusMethodAsyncHandle_t *reply)
{
    dm_sta_payload_t *sta_payload = NULL;

    if (!sta_info) {
        return -1;
    }

    sta_payload = (dm_sta_payload_t *)sta_info->dm_payload;
    if (!sta_payload) {
        return -1;
    }

    *reply = sta_payload->rbus_steering_async_hnd;

    return 0;
}

/*#######################################################################
#                       DATA HELPERS                                    #
########################################################################*/
/* Strings created in functions below must be according to tr181 */

static char *get_timestamp_str(uint64_t timestamp, char *buf, size_t buf_len)
{
#define TIME_STR_LEN    21
#define ZONE_STR_LEN    7
    char time[TIME_STR_LEN];
    char zone[ZONE_STR_LEN];
    time_t tv_sec;
    time_t tv_nsec;

    if (timestamp == 0) {
        timestamp = acu_get_epoch_nsec();
    }

    tv_sec = NSEC_TO_SEC(timestamp);
    tv_nsec = timestamp - SEC_TO_NSEC(tv_sec);
    strftime(time, sizeof(time), "%FT%T", localtime(&tv_sec));
    strftime(zone, sizeof(zone), "%z", localtime(&tv_sec));
    /* IETF RFC 3339 section 3 & 5.6 */
    snprintf(buf, buf_len, "%s.%06ld%s", time, tv_nsec / 1000, zone);

    return buf;
}

static char *get_country_code_str(uint16_t num, char *buf)
{
    buf[0] = (num & 0xff00) >> 8;
    buf[1] = (num & 0xff);

    return buf;
}

static char *get_freq_bands_str(uint16_t freq_bands, char *buf)
{
    bool first = true;

    if (freq_bands == MAP_FREQ_BANDS_ALL) {
        strcpy(buf, "All");
        return buf;
    }

    if (freq_bands & MAP_M2_BSS_RADIO2G) {
        strcpy(buf, "2.4");

        first = false;
    }

    if ((freq_bands & MAP_FREQ_BAND_5G) == MAP_FREQ_BAND_5G) {
        if (!first) {
            strcat(buf, ",");
        }
        strcat(buf, "5");

        freq_bands &= ~MAP_FREQ_BAND_5G;
        first = false;
    }
    if (freq_bands & MAP_M2_BSS_RADIO5GL) {
        if (!first) {
            strcat(buf, ",");
        }
        strcat(buf, "5_UNII_1,5_UNII_2");

        first = false;
    }
    if (freq_bands & MAP_M2_BSS_RADIO5GU) {
        if (!first) {
            strcat(buf, ",");
        }
        strcat(buf, "5_UNII_3,5_UNII_4");

        first = false;
    }

    if (freq_bands & MAP_M2_BSS_RADIO6G) {
        if (!first) {
            strcat(buf, ",");
        }
        strcat(buf, "6");
    }

    return buf;
}

static const char *get_auth_mode_str(uint16_t auth_mode)
{
    if ((auth_mode & IEEE80211_AUTH_MODE_WPA2PSK) &&
        (auth_mode & IEEE80211_AUTH_MODE_SAE)) {
        return "psk+sae";
    }

    if ((auth_mode & IEEE80211_AUTH_MODE_WPAPSK) ||
        (auth_mode & IEEE80211_AUTH_MODE_WPA2PSK)) {
        return "psk";
    }

    if (auth_mode & IEEE80211_AUTH_MODE_SAE) {
        return "sae";
    }

    return "none";
}

static char *get_ht_caps_str(map_radio_ht_capability_t *ht, char *buf, size_t buf_len)
{
    uint8_t data;

    /* Prepare data */
    data  = (ht->max_supported_tx_streams - 1) << 6;
    data |= (ht->max_supported_rx_streams - 1) << 4;
    data |=  ht->gi_support_20mhz              << 3;
    data |=  ht->gi_support_40mhz              << 2;
    data |=  ht->ht_support_40mhz              << 1;

    /* Now encode as base64 */
    if (b64_encode(&data, sizeof(data), buf, buf_len) < 0) {
        log_lib_e("b64_encode failed");
    }

    return buf;
}

static char *get_vht_caps_str(map_radio_vht_capability_t *vht, char *buf, size_t buf_len)
{
    uint8_t data[6] = {0};

    /* Prepare data */
    data[0]  =  vht->supported_tx_mcs              >> 8;
    data[1]  =  vht->supported_tx_mcs              &  0xff;
    data[2]  =  vht->supported_rx_mcs              >> 8;
    data[3]  =  vht->supported_rx_mcs              &  0xff;
    data[4]  = (vht->max_supported_tx_streams - 1) << 5;
    data[4] |= (vht->max_supported_rx_streams - 1) << 2;
    data[4] |=  vht->gi_support_80mhz              << 1;
    data[4] |=  vht->gi_support_160mhz;
    data[5]  =  vht->support_80_80_mhz             << 7;
    data[5] |=  vht->support_160mhz                << 6;
    data[5] |=  vht->su_beamformer_capable         << 5;
    data[5] |=  vht->mu_beamformer_capable         << 4;

    /* Now encode as base64 */
    if (b64_encode(&data, sizeof(data), buf, buf_len) < 0) {
        log_lib_e("b64_encode failed");
    }

    return buf;
}

static char *get_he_caps_str(map_radio_he_capability_t *he, char *buf, size_t buf_len)
{
    uint8_t data[14] = {0};
    uint8_t dp, i;

    dp = 0;
    /* Prepare data */
    for (i = 0; i < he->supported_mcs_length / 2; i++) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        data[dp++] = he->supported_tx_rx_mcs[i] &  0xff;
        data[dp++] = he->supported_tx_rx_mcs[i] >> 8;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        data[dp++] = he->supported_tx_rx_mcs[i] >> 8;
        data[dp++] = he->supported_tx_rx_mcs[i] &  0xff;
#else
#error You must specify your architecture endianess
#endif
    }
    data[dp  ]  = (he->max_supported_tx_streams - 1) << 5;
    data[dp  ] |= (he->max_supported_rx_streams - 1) << 2;
    data[dp  ] |= he->support_80_80_mhz              << 1;
    data[dp++] |= he->support_160mhz;
    data[dp  ]  = he->su_beamformer_capable          << 7;
    data[dp  ] |= he->mu_beamformer_capable          << 6;
    data[dp  ] |= he->ul_mimo_capable                << 5;
    data[dp  ] |= he->ul_mimo_ofdma_capable          << 4;
    data[dp  ] |= he->dl_mimo_ofdma_capable          << 3;
    data[dp  ] |= he->ul_ofdma_capable               << 2;
    data[dp++] |= he->dl_ofdma_capable               << 1;

    /* Now encode as base64 */
    if (b64_encode(&data, dp, buf, buf_len) < 0) {
        log_lib_e("b64_encode failed");
    }

    return buf;
}

static int get_last_sta_metrics(map_sta_info_t *sta, map_sta_ext_bss_metrics_t **ebm)
{
    map_sta_ext_bss_metrics_t *s;
    uint8_t i;

    *ebm = NULL;

    if (!sta || !sta->last_sta_ext_metrics.no_of_bss_metrics) {
        return -1;
    }

    for (i = 0; i < sta->last_sta_ext_metrics.no_of_bss_metrics; i++) {
        s = &sta->last_sta_ext_metrics.ext_bss_metrics_list[i];
        if (!maccmp(sta->bss->bssid, s->bssid)) {
            *ebm = s;
            return 0;
        }
    }

    return -1;
}

static char *get_beacon_metrics_str(array_list_t *beacon_metrics)
{
    list_iterator_t          *it;
    map_sta_beacon_metrics_t *bm;
    bool                      first_obj;
    size_t                    buffer_len;
    char                     *buffer;
    char                     *bp;

    /* Calculate buffer len needed */
    buffer_len = 0;
    it = new_list_iterator(beacon_metrics);
    while (it->iter != NULL) {
        bm = get_next_list_object(it);
        if (bm) {
            /* Ignore comma, it will replace null character */
            buffer_len += B64_ENCODE_LEN(bm->length + 2);
        }
    }

    buffer = calloc(1, buffer_len);
    bp = buffer;

    /* Fill buffer with comma sepparated base64 values */
    first_obj = true;
    reset_list_iterator(it);
    while (it->iter != NULL) {
        bm = get_next_list_object(it);
        if (bm) {
            if (!first_obj) {
                /* Don't modify buffer_len */
                *(bp++) = ',';
            }

            /* Now encode as base64 */
            if (b64_encode(bm, bm->length + 2, bp, buffer_len) < 0) {
                log_lib_e("b64_encode failed");
                free_list_iterator(it);
                free(buffer);
                return NULL;
            }
            bp += B64_ENCODE_LEN(bm->length + 2) - 1;
            buffer_len -= B64_ENCODE_LEN(bm->length + 2);

            first_obj = false;
        }
    }
    free_list_iterator(it);

    return buffer;
}

static const char *get_backhaul_link_type_str(map_ale_info_t *ale)
{
    int iface_group = INTERFACE_TYPE_GROUP_GET(ale->upstream_iface_type);

    if (is_local_agent(ale)) {
        return "None";
    } else if (iface_group == INTERFACE_TYPE_GROUP_WLAN) {
        return "Wi-Fi";
    } else if (iface_group == INTERFACE_TYPE_GROUP_ETHERNET) {
        return "Ethernet";
    } else if (iface_group == INTERFACE_TYPE_GROUP_MOCA) {
        return "MoCA";
    } else if (iface_group == INTERFACE_TYPE_GROUP_WAVELET_FFT) {
        return "HomePlug";
    } else {
        return "None"; /* Not yet known but that is no valid option */
    }
}

/*#######################################################################
#                       RBUS HELPERS                                    #
########################################################################*/
#if 0
/* Solely for debugging. rbusObject_fwrite bails if object has no property
   (rbusProperty_t) set. At least the version I have works like this. */
void rbus_dump_obj(rbusObject_t obj, int depth)
{
    int i;
    rbusObject_t child;
    rbusProperty_t prop;

    for (i = 0; i < depth; ++i) {
        fprintf(stdout, " ");
    }
    fprintf(stdout, "rbusObject name:%s\n", rbusObject_GetName(obj));

    prop = rbusObject_GetProperties(obj);
    if (prop) {
        rbusProperty_fwrite(prop, depth+1, stdout);
    }

    child = rbusObject_GetChildren(obj);
    while (child) {
        rbus_dump_obj(child, depth + 1);
        child = rbusObject_GetNext(child);
    }
}
#endif

static inline int rbus_check_obj_prop(rbusObject_t obj, const char *pname, rbusValueType_t ptype, const void *pval)
{
    rbusValueError_t rc;

    switch (ptype) {
        case RBUS_STRING: {
            const char *sval;
            int len;

            rc = rbusObject_GetPropertyString(obj, pname, &sval, &len);
            if (rc != RBUS_VALUE_ERROR_SUCCESS) {
                log_lib_e("Internal Error");
            } else {
                if (sval && strcmp(sval, (const char *)pval) == 0) {
                    return 0;
                }
            }
            break;
        }

        case RBUS_UINT8: {
            uint32_t uval;

            rc = rbusObject_GetPropertyUInt32(obj, pname, &uval);
            if (rc != RBUS_VALUE_ERROR_SUCCESS) {
                log_lib_e("Internal Error");
            } else {
                if (uval == *(const uint8_t *)pval) {
                    return 0;
                }
            }
            break;
        }

        case RBUS_UINT32: {
            uint32_t uval;

            rc = rbusObject_GetPropertyUInt32(obj, pname, &uval);
            if (rc != RBUS_VALUE_ERROR_SUCCESS) {
                log_lib_e("Internal Error");
            } else {
                if (uval == *(const uint32_t *)pval) {
                    return 0;
                }
            }
            break;
        }

        default:
            log_lib_e("Type: %d not supported", ptype);
            break;
    }

    return -1;
}

static rbusObject_t rbus_add_obj_inst(rbusObject_t obj, const char *name, const char *pname, rbusValueType_t ptype, const void *pval)
{
    rbusObject_t child;
    rbusObject_t inst;
    rbusObject_t last_inst;
    rbusValue_t value;
    const char *cname;
    char iname[4];
    unsigned int cnt;

    /* Try to find object within children */
    child = rbusObject_GetChildren(obj);
    if (child) {
        do {
            cname = rbusObject_GetName(child);
            if (cname && strcmp(cname, name) == 0) {
                break;
            }
            child = rbusObject_GetNext(child);
        } while (child);
    }

    /* Add child object if not found */
    if (!child) {
        rbusObject_InitMultiInstance(&child, name);
        rbusObject_SetParent(child, obj);
        rbusObject_SetChildren(obj, child);
        rbusObject_Release(child);
    }

    cnt = 0;
    last_inst = NULL;
    inst = rbusObject_GetChildren(child);
    if (inst) {
        do {
            if (pname) {
                /* Try to find object instance with given constraint */
                if (rbus_check_obj_prop(inst, pname, ptype, pval) == 0) {
                    return inst;
                }
            }

            ++cnt;
            last_inst = inst;
            inst = rbusObject_GetNext(inst);
        } while (inst);
    }

    /* Not found, add instance */
    snprintf(iname, sizeof(iname), "%d", cnt + 1);
    rbusObject_Init(&inst, iname);
    rbusObject_SetParent(inst, child);
    if (!last_inst) {
        rbusObject_SetChildren(child, inst);
    } else {
        rbusObject_SetNext(last_inst, inst);
    }
    rbusObject_Release(inst);

    /* Return instance if add only */
    if (!pname) {
        return inst;
    }

    /* We have also set the property */
    rbusValue_Init(&value);
    switch (ptype) {
        case RBUS_STRING:
            rbusValue_SetString(value, (const char *)pval);
            break;
        case RBUS_UINT8:
            rbusValue_SetUInt32(value, *(const uint8_t *)pval);
            break;
        case RBUS_UINT32:
            rbusValue_SetUInt32(value, *(const uint32_t *)pval);
            break;
        default:
            log_lib_e("Type: %d not supported", ptype);
            return NULL;
    }
    rbusObject_SetValue(inst, pname, value);
    rbusValue_Release(value);

    return inst;
}

static void rbus_add_prop_str(rbusObject_t obj, const char *name, const char *str)
{
    rbusProperty_t prop;
    rbusValue_t value;

    rbusValue_Init(&value);
    if (str) {
        rbusValue_SetString(value, str);
    } else {
        rbusValue_SetString(value, "");
    }
    rbusProperty_Init(&prop, name, value);
    rbusObject_SetProperty(obj, prop);
    rbusValue_Release(value);
    rbusProperty_Release(prop);
}

static void rbus_add_prop_uint32(rbusObject_t obj, const char *name, uint32_t num)
{
    rbusProperty_t prop;
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, num);
    rbusProperty_Init(&prop, name, value);
    rbusObject_SetProperty(obj, prop);
    rbusValue_Release(value);
    rbusProperty_Release(prop);
}

static size_t rbus_object_children_len(rbusObject_t obj)
{
    rbusObject_t child;
    size_t len = 0;

    for (child = rbusObject_GetChildren(obj); child != NULL; child = rbusObject_GetNext(child)) {
        len++;
    }

    return len;
}

static rbusObject_t rbus_obj_get_child_obj(rbusObject_t obj, const char *name)
{
    rbusObject_t child;

    for (child = rbusObject_GetChildren(obj); child != NULL; child = rbusObject_GetNext(child)) {
        const char *cname = rbusObject_GetName(child);
        if (cname && !strcmp(cname, name)) {
            return child;
        }
    }

    return NULL;
}

static void map_dm_create_ssids(void)
{
    map_controller_cfg_t *cfg;
    unsigned int idx;
    rbusError_t  rc;

    cfg = &map_cfg_get()->controller_cfg;
    for (idx = 1; idx <= cfg->num_profiles; idx++) {
        rc = rbusTable_registerRow(g_bus_handle,
            "Device.WiFi.DataElements.Network.SSID.", idx, NULL);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to create row[%d] for ssid", idx);
        }
    }
}

static void map_dm_remove_ssids(void)
{
    map_controller_cfg_t *cfg;
    unsigned int idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    cfg = &map_cfg_get()->controller_cfg;
    for (idx = cfg->num_profiles; idx > 0; idx--) {
        snprintf(tname, sizeof(tname),
            "Device.WiFi.DataElements.Network.SSID.%d", idx);

        rc = rbusTable_unregisterRow(g_bus_handle, tname);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to delete row[%d] for ssid", idx);
        }
    }
}

/*#######################################################################
#                       GET BASED ON IDX                                #
########################################################################*/
map_ale_info_t *map_dm_rbus_get_ale(int ale_idx)
{
    map_ale_info_t *ale;

    map_dm_foreach_agent_ale(ale) {
        if (ale->dm_idx == ale_idx) {
            return ale;
        }
    }

    return NULL;
}

map_radio_info_t *map_dm_rbus_get_radio(map_ale_info_t *ale, int radio_idx)
{
    map_radio_info_t *radio;

    map_dm_foreach_radio(ale, radio) {
        if (radio->dm_idx == radio_idx) {
            return radio;
        }
    }

    return NULL;
}

map_bss_info_t *map_dm_rbus_get_bss(map_radio_info_t *radio, int bss_idx)
{
    map_bss_info_t *bss;

    map_dm_foreach_bss(radio, bss) {
        if (bss->dm_idx == bss_idx) {
            return bss;
        }
    }

    return NULL;
}

map_sta_info_t *map_dm_rbus_get_sta(map_bss_info_t *bss, int sta_idx)
{
    map_sta_info_t *sta;

    map_dm_foreach_sta(bss, sta) {
        if (sta->dm_idx == sta_idx) {
            return sta;
        }
    }

    return NULL;
}

map_scan_result_t *map_dm_rbus_get_scanres(map_radio_info_t *radio,
    unsigned int scan_id, unsigned int opclass, unsigned int channel)
{
    list_iterator_t *it;
    map_scan_result_t *sr;

    if (0 == list_get_size(radio->scanned_bssid_list)) {
        return NULL;
    }

    if (NULL == (it = new_list_iterator(radio->scanned_bssid_list))) {
        return NULL;
    }

    while (it->iter != NULL) {
        sr = (map_scan_result_t *)get_next_list_object(it);
        if (!sr) {
            continue;
        }

        if (scan_id == (unsigned int)sr->scan_cnt &&
            opclass == sr->opclass &&
            channel == sr->channel) {
            free_list_iterator(it);
            return sr;
        }
    }
    free_list_iterator(it);

    return NULL;
}

map_channel_scan_neighbor_t *map_dm_rbus_get_nb_info(map_radio_info_t *radio,
    unsigned int scan_id, unsigned int opclass, unsigned int channel, mac_addr bssid)
{
    list_iterator_t *it;
    map_scan_result_t *sr;
    map_channel_scan_neighbor_t *ni;

    if (0 == list_get_size(radio->scanned_bssid_list)) {
        return NULL;
    }

    if (NULL == (it = new_list_iterator(radio->scanned_bssid_list))) {
        return NULL;
    }

    while (it->iter != NULL) {
        sr = (map_scan_result_t *)get_next_list_object(it);
        if (!sr) {
            continue;
        }

        ni = &sr->neighbor_info;
        if (scan_id == (unsigned int)sr->scan_cnt &&
            opclass == sr->opclass &&
            channel == sr->channel &&
            maccmp(bssid, ni->bssid) == 0) {
            free_list_iterator(it);
            return ni;
        }
    }
    free_list_iterator(it);

    return NULL;
}

static const char *get_table_alias(const char *src, char *alias, size_t max_len, bool *is_num)
{
	char *dst = alias;
	size_t len = 0;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src += 2;
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src++;
	}

	return src;
}

#define DM_DATAELEM_PREFIX  "Device.WiFi.DataElements"
#define DM_DEVICE_PREFIX    "Device.WiFi.DataElements.Network.Device"
#define DM_RADIO_PREFIX     "Radio"
#define DM_BSS_PREFIX       "BSS"
#define DM_STA_PREFIX       "STA"

static map_ale_info_t *dm_get_ale(const char *alias, bool is_num)
{
    map_ale_info_t *ale;

    if (is_num) {
        return map_dm_rbus_get_ale(atoi(alias));
    }

    map_dm_foreach_agent_ale(ale) {
        if (strcmp(alias, ale->al_mac_str) == 0) {
            return ale;
        }
    }

    return NULL;
}

static map_radio_info_t *dm_get_radio(map_ale_info_t *ale, const char *alias, bool is_num)
{
#define MAX_RUID_STR_LEN    10
    map_radio_info_t *radio;
    char radio_id[MAX_RUID_STR_LEN] = {0};

    if (is_num) {
        return map_dm_rbus_get_radio(ale, atoi(alias) - 1);
    }

    map_dm_foreach_radio(ale, radio) {
        b64_encode(radio->radio_id, sizeof(mac_addr), radio_id, sizeof(radio_id));
        if (strcmp(alias, radio_id) == 0) {
            return radio;
        }
    }

    return NULL;
}

static map_bss_info_t *dm_get_bss(map_radio_info_t *radio, const char *alias, bool is_num)
{
    map_bss_info_t *bss;

    if (is_num) {
        return map_dm_rbus_get_bss(radio, atoi(alias) - 1);
    }

    map_dm_foreach_bss(radio, bss) {
        if (strcmp(alias, bss->bssid_str) == 0) {
            return bss;
        }
    }

    return NULL;
}

static map_sta_info_t *dm_get_sta(map_bss_info_t *bss, const char *alias, bool is_num)
{
    map_sta_info_t *sta;

    if (is_num) {
        return map_dm_rbus_get_sta(bss, atoi(alias) - 1);
    }

    map_dm_foreach_sta(bss, sta) {
        if (strcmp(alias, sta->mac_str) == 0) {
            return sta;
        }
    }

    return NULL;
}

static int cmp_unassoc_sta_mac(void *unassoc_sta, void *mac)
{
    if (unassoc_sta && mac) {
        if (0 == maccmp(((map_unassociated_sta_info_t *)unassoc_sta)->mac_address, mac)) {
            return 1;
        }
    }
    return 0;
}

static int cmp_unassoc_sta_dm_idx(void *unassoc_sta, void *idx)
{
    if (unassoc_sta && idx) {
        int dm_idx = *((int *)idx);
        if (((map_unassociated_sta_info_t *)unassoc_sta)->dm_idx == dm_idx) {
            return 1;
        }
    }
    return 0;
}

static map_unassociated_sta_info_t *dm_get_unassoc_sta(map_radio_info_t *radio, const char *alias,
                                                       bool is_num)
{
    if (is_num) {
        int dm_idx = atoi(alias);
        return find_object(radio->unassoc_sta_list, &dm_idx, cmp_unassoc_sta_dm_idx);
    } else {
        mac_addr mac;
        if (mac_from_string(alias, mac) != 0) {
            log_lib_e("Can't parse mac: %s", alias);
            return NULL;
        }
        return find_object(radio->unassoc_sta_list, mac, cmp_unassoc_sta_mac);
    }

    return NULL;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network                                    #
########################################################################*/
static rbusError_t network_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    map_controller_cfg_t *cfg;
    char timestamp[MAX_TS_STR_LEN] = {0};
    mac_addr_str mac_str;

    sscanf(name, "Device.WiFi.DataElements.Network.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "ID") == 0) {
        mac_to_string(map_cfg_get()->controller_cfg.al_mac, mac_str);
        rbusValue_SetString(value, mac_str);
    } else if (strcmp(param, "TimeStamp") == 0) {
        get_timestamp_str(0, timestamp, sizeof(timestamp));
        rbusValue_SetString(value, timestamp);
    } else if (strcmp(param, "DeviceNumberOfEntries") == 0) {
        map_ale_info_t *ale;
        uint32_t ale_cnt = 0;
        map_dm_foreach_agent_ale(ale) {
            ale_cnt++;
        }
        rbusValue_SetUInt32(value, ale_cnt);
    } else if (strcmp(param, "SSIDNumberOfEntries") == 0) {
        cfg = &map_cfg_get()->controller_cfg;
        rbusValue_SetUInt32(value, cfg->num_profiles);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.SetSSID()                          #
########################################################################*/
static int parse_freq_bands(map_profile_cfg_t *profile, const char *buf)
{
    char *copy;
    char *band;
    char *sptr;
    uint16_t bands = 0;

    copy = strdup(buf);

    band = strtok_r(copy, ",", &sptr);
    for (; band; band = strtok_r(NULL, ",", &sptr)) {
        if (strcmp(band, "All") == 0) {
            bands = MAP_FREQ_BANDS_ALL;
            break;
        }
        if (strcmp(band, "2.4") == 0) {
            bands |= MAP_M2_BSS_RADIO2G;
        } else if (strcmp(band, "5") == 0) {
            bands |= MAP_FREQ_BAND_5G;
        } else if (strcmp(band, "6") == 0) {
            bands |= MAP_M2_BSS_RADIO6G;
        } else if (strcmp(band, "5_UNII_1") == 0) {
            bands |= MAP_M2_BSS_RADIO5GL;
        } else if (strcmp(band, "5_UNII_2") == 0) {
            bands |= MAP_M2_BSS_RADIO5GL;
        } else if (strcmp(band, "5_UNII_3") == 0) {
            bands |= MAP_M2_BSS_RADIO5GU;
        } else if (strcmp(band, "5_UNII_4") == 0) {
            bands |= MAP_M2_BSS_RADIO5GU;
        } else if (strcmp(band, "6_UNII_5") == 0) {
            bands |= MAP_M2_BSS_RADIO6G;
        } else if (strcmp(band, "6_UNII_6") == 0) {
            bands |= MAP_M2_BSS_RADIO6G;
        } else if (strcmp(band, "6_UNII_7") == 0) {
            bands |= MAP_M2_BSS_RADIO6G;
        } else if (strcmp(band, "6_UNII_8") == 0) {
            bands |= MAP_M2_BSS_RADIO6G;
        } else {
            free(copy);
            return -1;
        }
    }

    free(copy);

    if (bands != 0) {
        profile->bss_freq_bands = bands;
    }

    return 0;
}

static int parse_akms_allowed(map_profile_cfg_t *profile, const char *buf)
{
    if (strcmp(buf, "psk+sae") == 0) {
        profile->supported_auth_modes = IEEE80211_AUTH_MODE_WPA2PSK | IEEE80211_AUTH_MODE_SAE;
    } else if (strcmp(buf, "psk") == 0) {
        profile->supported_auth_modes = IEEE80211_AUTH_MODE_WPA2PSK;
    } else if (strcmp(buf, "sae") == 0) {
        profile->supported_auth_modes = IEEE80211_AUTH_MODE_SAE;
    } else if (strcmp(buf, "none") == 0) {
        profile->supported_auth_modes = IEEE80211_AUTH_MODE_OPEN;
    } else {
        return -1;
    }

    if (profile->supported_auth_modes == IEEE80211_AUTH_MODE_OPEN) {
        profile->supported_encryption_types = IEEE80211_ENCRYPTION_MODE_NONE;
    } else {
        profile->supported_encryption_types = IEEE80211_ENCRYPTION_MODE_AES;
    }

    return 0;
}

static rbusError_t network_setssid_rbus(rbusHandle_t handle, char const* method, rbusObject_t in, rbusObject_t out, rbusMethodAsyncHandle_t async)
{
#define MIN_PASSPHRASE_LEN  8
    (void) handle;
    (void) async;
    char param[MAX_PROP_PARAM_LEN] = {0};
    map_controller_cfg_t *cfg;
    map_profile_cfg_t profile = { /* default values */
        .enabled                    = true,
        .type                       = MAP_PROFILE_TYPE_OTHER,
        .supported_auth_modes       = IEEE80211_AUTH_MODE_OPEN,
        .supported_encryption_types = IEEE80211_ENCRYPTION_MODE_NONE,
        .bss_freq_bands             = MAP_FREQ_BANDS_ALL,
        .bss_state                  = MAP_FRONTHAUL_BSS,
        .gateway                    = true,
        .extender                   = true,
        .hide                       = false,
        .vlan_id                    = -1
    };
    unsigned int profile_count = 0;
    const char *sval;
    bool add = true;
    int vlan_id;
    int len;
    rbusValueError_t rc_value;
    rbusError_t rc;
    int ret = -1;

    rbusObject_SetName(out, "Output");

    sscanf(method, "Device.WiFi.DataElements.Network.%s", param);

    if (strcmp(param, "SetSSID()") == 0) {
        cfg = &map_cfg_get()->controller_cfg;
        profile_count = cfg->num_profiles;

        /* Mandatory arguments */
        rc_value = rbusObject_GetPropertyString(in, "SSID", &sval, &len);
        if (rc_value != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("SSID is mandatory");
            rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
            return RBUS_ERROR_INVALID_INPUT;
        }
        strncpy(profile.bss_ssid, sval, sizeof(profile.bss_ssid) - 1);

        rc_value = rbusObject_GetPropertyString(in, "AddRemove", &sval, &len);
        if (rc_value != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("AddRemove is mandatory");
            rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
            return RBUS_ERROR_INVALID_INPUT;
        }
        add = (strcmp(sval, "false") != 0);

        /* If remove operation, then other arguments are irrelevant */
        if (add == false) {
            ret = map_profile_remove(&profile);
            goto result;
        }

        /* Optional arguments */
        rc_value = rbusObject_GetPropertyString(in, "Band", &sval, &len);
        if (rc_value == RBUS_VALUE_ERROR_SUCCESS) {
            if (parse_freq_bands(&profile, sval) != 0) {
                log_lib_e("Invalid band: %s", sval);
                rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
                return RBUS_ERROR_INVALID_INPUT;
            }
        }

        rc_value = rbusObject_GetPropertyString(in, "PassPhrase", &sval, &len);
        if (rc_value == RBUS_VALUE_ERROR_SUCCESS) {
            if (len < MIN_PASSPHRASE_LEN) {
                log_lib_e("Invalid password (too short): %s", sval);
                rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
                return RBUS_ERROR_INVALID_INPUT;
            }
            strncpy(profile.wpa_key, sval, sizeof(profile.wpa_key) - 1);
        }

        rc_value = rbusObject_GetPropertyString(in, "AKMsAllowed", &sval, &len);
        if (rc_value == RBUS_VALUE_ERROR_SUCCESS) {
            if (parse_akms_allowed(&profile, sval) != 0) {
                log_lib_e("Invalid AKM: %s", sval);
                rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
                return RBUS_ERROR_INVALID_INPUT;
            }
        }

        rc_value = rbusObject_GetPropertyString(in, "Enabled", &sval, &len);
        if (rc_value == RBUS_VALUE_ERROR_SUCCESS) {
            profile.enabled = (strcmp(sval, "false") != 0);
        }

        rc_value = rbusObject_GetPropertyString(in, "AdvertisementEnabled", &sval, &len);
        if (rc_value == RBUS_VALUE_ERROR_SUCCESS) {
            profile.hide = (strcmp(sval, "true") != 0);
        }

        rc_value = rbusObject_GetPropertyString(in, "Reference", &sval, &len);
        if (rc_value == RBUS_VALUE_ERROR_SUCCESS) {
            strncpy(profile.label, sval, sizeof(profile.label) - 1);
        }

        rc_value = rbusObject_GetPropertyString(in, "Direction", &sval, &len);
        if (rc_value == RBUS_VALUE_ERROR_SUCCESS) {
            if (strcmp(sval, "Backhaul") == 0) {
                log_lib_e("Modifying backhaul is illegal");
                rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
                return RBUS_ERROR_INVALID_INPUT;
            }
        }

        rc_value = rbusObject_GetPropertyInt32(in, "X_AIRTIES_VID", &vlan_id);
        if (rc_value == RBUS_VALUE_ERROR_SUCCESS) {
            profile.vlan_id = vlan_id;
        }

        ret = map_profile_add(&profile);
    } else {
        log_lib_e("Invalid method: %s", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_METHOD;
    }

result:
    if (ret != 0) {
        rbus_add_prop_str(out, "Status", "Error_Other");
        return RBUS_ERROR_INVALID_METHOD;
    }

    if (profile_count < cfg->num_profiles) {
        rc = rbusTable_registerRow(g_bus_handle,
            "Device.WiFi.DataElements.Network.SSID.", cfg->num_profiles, NULL);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to create row[%d] for ssid", cfg->num_profiles);
        }
    } else if (profile_count > cfg->num_profiles) {
        char tname[64] = {0};

        snprintf(tname, sizeof(tname),
            "Device.WiFi.DataElements.Network.SSID.%d", profile_count);

        rc = rbusTable_unregisterRow(g_bus_handle, tname);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to delete row[%d] for ssid", profile_count);
        }
    }

    rbus_add_prop_str(out, "Status", "Success");

    return RBUS_ERROR_SUCCESS;
    //return RBUS_ERROR_ASYNC_RESPONSE;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.SSID                               #
########################################################################*/
static rbusError_t ssid_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
#define MAX_FREQ_STR_LEN    48
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    unsigned int ssid_index;
    map_controller_cfg_t *cfg;
    map_profile_cfg_t *profile;
    char buf[MAX_FREQ_STR_LEN] = {0};

    sscanf(name, "Device.WiFi.DataElements.Network.SSID.%d.%s",
        &ssid_index, param);

    cfg = &map_cfg_get()->controller_cfg;
    if (!ssid_index || ssid_index > cfg->num_profiles) {
        log_lib_e("Invalid SSID index: %d", ssid_index);
        return RBUS_ERROR_INVALID_INPUT;
    }
    profile = &cfg->profiles[ssid_index - 1];

    rbusValue_Init(&value);

    if (strcmp(param, "SSID") == 0) {
        rbusValue_SetString(value, profile->bss_ssid);
    } else if (strcmp(param, "Enabled") == 0) {
        rbusValue_SetBoolean(value, profile->enabled);
    } else if (strcmp(param, "Band") == 0) {
        rbusValue_SetString(value,
            get_freq_bands_str(profile->bss_freq_bands, buf));
    } else if (strcmp(param, "AdvertisementEnabled") == 0) {
        rbusValue_SetBoolean(value, !profile->hide);
    } else if (strcmp(param, "Passphrase") == 0) {
        rbusValue_SetString(value, profile->wpa_key);
    } else if (strcmp(param, "AKMsAllowed") == 0) {
        rbusValue_SetString(value,
            get_auth_mode_str(profile->supported_auth_modes));
    } else if (strcmp(param, "Reference") == 0) {
        rbusValue_SetString(value, profile->label);
    } else if (strcmp(param, "Direction") == 0) {
        if (profile->bss_state & MAP_FRONTHAUL_BSS) {
            rbusValue_SetString(value, "Fronthaul");
        } else if (profile->bss_state & MAP_BACKHAUL_BSS) {
            rbusValue_SetString(value, "Backhaul");
        }
    } else if (strcmp(param, "X_AIRTIES_VID") == 0) {
        rbusValue_SetInt32(value, profile->vlan_id);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device                             #
########################################################################*/
static void create_ale_mac(mac_addr mac, int *ret_idx)
{
    mac_addr_str mac_str;
    unsigned int idx;
    rbusError_t  rc;

    mac_to_string(mac, mac_str);

    log_lib_d("create ale: %s", mac_str);

    if (get_dev_dm_idx(mac_str, &idx) < 0) {
        log_lib_e("could not find free index for ale: %s", mac_str);
        return;
    }

    if (ret_idx) {
        *ret_idx = idx;
    }

    if (idx > 0) {
        rc = rbusTable_registerRow(g_bus_handle,
            "Device.WiFi.DataElements.Network.Device.", idx, mac_str);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to create row[%d] for ale: %s", idx, mac_str);
        }
    }
}

static void dm_rbus_create_ale(map_ale_info_t *ale)
{
    /* Local agent already added */
    if (is_local_agent(ale)) {
        ale->dm_idx = 0;
        return;
    }

    create_ale_mac(ale->al_mac, &ale->dm_idx);
}

static void update_dm_cac_available(map_ale_info_t *ale)
{
    unsigned int ale_idx;
    unsigned int cac_idx;
    unsigned int idx;
    unsigned int curr_count;
    unsigned int new_count;
    char         tname[256] = {0};
    rbusError_t  rc;

    ale_idx = ale->dm_idx;
    /* There is only one CACStatus at a time */
    cac_idx = 1;
    get_dev_dm_cac_avail(ale, &curr_count);
    new_count = ale->cac_status_report.available_pairs_nr;

    if (curr_count < new_count) {
        /* Add missing CAC available channels */
        snprintf(tname, sizeof(tname),
            "Device.WiFi.DataElements.Network.Device.%d.CACStatus.%d."
            "CACAvailableChannel.", ale_idx, cac_idx);

        curr_count = curr_count ? curr_count : 1;
        for (idx = curr_count; idx <= new_count; idx++) {
            rc = rbusTable_registerRow(g_bus_handle, tname, idx, NULL);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to create row[%d] for cac_avail_ch", idx);
            }
        }
    } else {
        /* Remove excess CAC available channels */
        for (idx = curr_count; idx > new_count; idx--) {
            snprintf(tname, sizeof(tname),
                "Device.WiFi.DataElements.Network.Device.%d.CACStatus.%d."
                "CACAvailableChannel.%d", ale_idx, cac_idx, idx);

            rc = rbusTable_unregisterRow(g_bus_handle, tname);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to delete row[%d] for cac_avail_ch", idx);
            }
        }
    }
    set_dev_dm_cac_avail(ale, new_count);
}

static void update_dm_cac_nonoccupancy(map_ale_info_t *ale)
{
    unsigned int ale_idx;
    unsigned int cac_idx;
    unsigned int idx;
    unsigned int curr_count;
    unsigned int new_count;
    char         tname[256] = {0};
    rbusError_t  rc;

    ale_idx = ale->dm_idx;
    /* There is only one CACStatus at a time */
    cac_idx = 1;
    get_dev_dm_cac_nonocc(ale, &curr_count);
    new_count = ale->cac_status_report.non_occupancy_pairs_nr;

    if (curr_count < new_count) {
        /* Add missing CAC non occupancy channels */
        snprintf(tname, sizeof(tname),
            "Device.WiFi.DataElements.Network.Device.%d.CACStatus.%d."
            "CACNonOccupancyChannel.", ale_idx, cac_idx);

        curr_count = curr_count ? curr_count : 1;
        for (idx = curr_count; idx <= new_count; idx++) {
            rc = rbusTable_registerRow(g_bus_handle, tname, idx, NULL);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to create row[%d] for cac_nonocc_ch", idx);
            }
        }
    } else {
        /* Remove excess CAC non occupancy channels */
        for (idx = curr_count; idx > new_count; idx--) {
            snprintf(tname, sizeof(tname),
                "Device.WiFi.DataElements.Network.Device.%d.CACStatus.%d."
                "CACNonOccupancyChannel.%d", ale_idx, cac_idx, idx);

            rc = rbusTable_unregisterRow(g_bus_handle, tname);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to delete row[%d] for cac_nonocc_ch", idx);
            }
        }
    }
    set_dev_dm_cac_nonocc(ale, new_count);
}

static void update_dm_cac_active(map_ale_info_t *ale)
{
    unsigned int ale_idx;
    unsigned int cac_idx;
    unsigned int idx;
    unsigned int curr_count;
    unsigned int new_count;
    char         tname[256] = {0};
    rbusError_t  rc;

    ale_idx = ale->dm_idx;
    /* There is only one CACStatus at a time */
    cac_idx = 1;
    get_dev_dm_cac_active(ale, &curr_count);
    new_count = ale->cac_status_report.ongoing_cac_pairs_nr;

    if (curr_count < new_count) {
        /* Add missing CAC active channels */
        snprintf(tname, sizeof(tname),
            "Device.WiFi.DataElements.Network.Device.%d.CACStatus.%d."
            "CACActiveChannel.", ale_idx, cac_idx);

        curr_count = curr_count ? curr_count : 1;
        for (idx = curr_count; idx <= new_count; idx++) {
            rc = rbusTable_registerRow(g_bus_handle, tname, idx, NULL);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to create row[%d] for cac_active_ch", idx);
            }
        }
    } else {
        /* Remove excess CAC active channels */
        for (idx = curr_count; idx > new_count; idx--) {
            snprintf(tname, sizeof(tname),
                "Device.WiFi.DataElements.Network.Device.%d.CACStatus.%d."
                "CACActiveChannel.%d", ale_idx, cac_idx, idx);

            rc = rbusTable_unregisterRow(g_bus_handle, tname);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to delete row[%d] for cac_active_ch", idx);
            }
        }
    }
    set_dev_dm_cac_active(ale, new_count);
}

static int radio_add_unassoc_sta(map_radio_info_t *radio, map_nb_unassoc_sta_metric_t *metric)
{
    int rc;
    map_unassociated_sta_info_t *info;
    map_unassociated_sta_info_t *old;
    char tname[256] = { 0 };

    snprintf(tname, sizeof(tname),
             "Device.WiFi.DataElements.Network.Device.%d.Radio.%d."
             "UnassociatedSTA.",
             radio->ale->dm_idx, radio->dm_idx + 1);

    info = calloc(1, sizeof(*info));
    if (!info) {
        return -1;
    }

    get_timestamp_str(0, info->timestamp, sizeof(info->timestamp));
    maccpy(info->mac_address, metric->mac);
    info->signal_strength = metric->rcpi_uplink;

    old = find_remove_object(radio->unassoc_sta_list, metric->mac, cmp_unassoc_sta_mac);
    if (old) {
        info->dm_idx = old->dm_idx;
        free(old);
    } else {
        info->dm_idx = radio->unassoc_sta_list_idx + 1;
        rc = rbusTable_registerRow(g_bus_handle, tname, info->dm_idx, NULL);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to create row[%d] for unassoc sta, %s", info->dm_idx, tname);
            free(info);
            return -1;
        }
        radio->unassoc_sta_list_idx++;
    }

    rc = push_object(radio->unassoc_sta_list, info);
    if (rc != 0) {
        log_lib_e("Failed to inserting unassoc sta info to list");
        free(info);
        return -1;
    }

    return 0;
}

static void radio_remove_unassoc_sta(map_radio_info_t *radio, mac_addr mac)
{
    int rc;
    map_unassociated_sta_info_t *old;
    char tname[256] = { 0 };

    old = find_remove_object(radio->unassoc_sta_list, mac, cmp_unassoc_sta_mac);
    if (old) {
        snprintf(tname, sizeof(tname),
                 "Device.WiFi.DataElements.Network.Device.%d.Radio.%d."
                 "UnassociatedSTA.%d",
                 radio->ale->dm_idx, radio->dm_idx + 1, old->dm_idx);

        rc = rbusTable_unregisterRow(g_bus_handle, tname);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to delete row[%d] for unassoc sta", old->dm_idx);
        }
        free(old);
    }
}

static void
unassoc_sta_link_metrics_update_radios(map_ale_info_t *ale,
                                       map_nb_unassoc_sta_link_metrics_response_t *metrics)
{
    int i;
    map_radio_info_t *radio;
    uint8_t band;
    int ret;

    do {
        ret = map_get_band_from_op_class(metrics->op_class, &band);
        if (ret != 0) {
            break;
        }

        map_dm_foreach_radio(ale, radio) {
            uint8_t radio_band;
            ret = map_get_band_from_op_class(radio->current_op_class, &radio_band);
            if (ret != 0) {
                log_lib_e("Can't get band from opclass: %d", radio->current_op_class);
                break;
            }

            if (radio_band != band) {
                continue;
            }

            for (i = 0; i < metrics->sta_metrics_list_len; i++) {
                (void)radio_add_unassoc_sta(radio, &metrics->sta_metrics_list[i]);
            }
        }
    } while (0);
}

static void unassoc_sta_link_metrics_response_process(map_ale_info_t *ale)
{
    int i;
    int ret;
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    map_nb_unassoc_sta_link_metrics_response_t metrics = { 0 };
    rbusMethodAsyncHandle_t async;
    rbusObject_t out;

    rbusObject_Init(&out, "Output");

    do {
        if (map_dm_get_nbapi()->unassoc_sta_link_metrics_response == NULL) {
            break;
        }

        ret = map_dm_get_nbapi()->unassoc_sta_link_metrics_response(ale, &metrics);
        if (ret != 0) {
            break;
        }

        unassoc_sta_link_metrics_update_radios(ale, &metrics);

        async = get_device_unassoc_sta_link_metrics_query_reply(ale);
        if (async == NULL) {
            break;
        }

        rbus_add_prop_str(out, "Status", "Success");
        rbus_add_prop_uint32(out, "OpClass", metrics.op_class);
        for (i = 0; i < metrics.sta_metrics_list_len; i++) {
            rbusObject_t sta;
            mac_addr_str mac_str;

            sta = rbus_add_obj_inst(out, "STA", NULL, RBUS_NONE, NULL);
            rbus_add_prop_uint32(sta, "Channel", metrics.sta_metrics_list[i].channel);
            rbus_add_prop_uint32(sta, "SignalStrength", metrics.sta_metrics_list[i].rcpi_uplink);
            rbus_add_prop_uint32(sta, "TimeDelta", metrics.sta_metrics_list[i].time_delta);
            mac_to_string(metrics.sta_metrics_list[i].mac, mac_str);
            rbus_add_prop_str(sta, "MACAddress", mac_str);
        }

        rc = rbusMethod_SendAsyncResponse(async, rc, out);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("X_AIRTIES_UnassociatedStaLinkMetricsQuery() response failed: %d", rc);
        }
    } while (0);

    rbusObject_Release(out);

    set_device_unassoc_sta_link_metrics_query_reply(ale, NULL);

    if (metrics.sta_metrics_list) {
        free(metrics.sta_metrics_list);
    }
}

static void dm_rbus_update_ale(map_ale_info_t *ale)
{
    unsigned int ale_idx;
    unsigned int cac_idx;
    unsigned int iface_idx;
    unsigned int idx;
    bool         cac_valid;
    unsigned int curr_count;
    unsigned int new_count;
    unsigned int iface_count;
    char         tname[256] = {0};
    rbusError_t  rc;

    log_lib_d("update dev[%d]: %s", ale->dm_idx, ale->al_mac_str);

    if (check_dev_dm_idx(ale) < 0) {
        log_lib_e("Invalid indexing for ale");
        return;
    }

    ale_idx = ale->dm_idx;

    get_dev_dm_cac_valid(ale, &cac_valid);
    if (ale->cac_status_report.valid) {
        if (!cac_valid) {
            snprintf(tname, sizeof(tname),
                "Device.WiFi.DataElements.Network.Device.%d."
                "CACStatus.", ale_idx);

            /* There is only one CACStatus at a time */
            cac_idx = 1;
            rc = rbusTable_registerRow(g_bus_handle, tname, cac_idx, NULL);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to create row[%d] for cac_status", cac_idx);
            }
            set_dev_dm_cac_valid(ale, true);
        }
        update_dm_cac_available(ale);
        update_dm_cac_nonoccupancy(ale);
        update_dm_cac_active(ale);
    } else {
        if (cac_valid) {
            /* There is only one CACStatus at a time */
            cac_idx = 1;
            snprintf(tname, sizeof(tname),
                "Device.WiFi.DataElements.Network.Device.%d."
                "CACStatus.%d.", ale_idx, cac_idx);

            rc = rbusTable_unregisterRow(g_bus_handle, tname);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to delete row[%d] for cac_status", cac_idx);
            }
            set_dev_dm_cac_valid(ale, false);
        }
    }

    do {
        map_emex_eth_iface_t *iface;

        if (!ale->emex.enabled) {
            break;
        }

        get_dev_dm_eth_ifaces(ale, &curr_count);
        iface_count = ale->emex.eth_iface_list.iface_nr;

        if (curr_count < iface_count) {
            /* Add missing ethernet interfaces */
            snprintf(tname, sizeof(tname),
                "Device.WiFi.DataElements.Network.Device.%d."
                "X_AIRTIES_Ethernet.Interface.", ale_idx);

            curr_count = curr_count ? curr_count : 1;
            for (idx = curr_count; idx <= iface_count; idx++) {
                rc = rbusTable_registerRow(g_bus_handle, tname, idx, NULL);
                if (rc != RBUS_ERROR_SUCCESS) {
                    log_lib_e("Failed to create row[%d] for eth_ifaces", idx);
                }
            }
        } else {
            /* Remove excess ethernet interfaces */
            for (idx = curr_count; idx > iface_count; idx--) {
                snprintf(tname, sizeof(tname),
                    "Device.WiFi.DataElements.Network.Device.%d."
                    "X_AIRTIES_Ethernet.Interface.%d", ale_idx, idx);

                rc = rbusTable_unregisterRow(g_bus_handle, tname);
                if (rc != RBUS_ERROR_SUCCESS) {
                    log_lib_e("Failed to delete row[%d] for eth_ifaces", idx);
                }
            }
        }
        set_dev_dm_eth_ifaces(ale, iface_count);

        for (iface_idx = 0; iface_idx < iface_count; iface_idx++) {
            iface = &ale->emex.eth_iface_list.ifaces[iface_idx];
            get_dev_dm_eth_devs(ale, iface_idx, &curr_count);
            new_count = iface->i1905_neighbor_macs_nr + iface->non_i1905_neighbor_macs_nr;

            if (curr_count < new_count) {
                /* Add missing ethernet devices */
                snprintf(tname, sizeof(tname),
                    "Device.WiFi.DataElements.Network.Device.%d.X_AIRTIES_Ethernet."
                    "Interface.%d.Device.", ale_idx, iface_idx + 1);

                curr_count = curr_count ? curr_count : 1;
                for (idx = curr_count; idx <= new_count; idx++) {
                    rc = rbusTable_registerRow(g_bus_handle, tname, idx, NULL);
                    if (rc != RBUS_ERROR_SUCCESS) {
                        log_lib_e("Failed to create row[%d] for eth_devs", idx);
                    }
                }
            } else {
                /* Remove excess ethernet interfaces */
                for (idx = curr_count; idx > new_count; idx--) {
                    snprintf(tname, sizeof(tname),
                        "Device.WiFi.DataElements.Network.Device.%d.X_AIRTIES_Ethernet."
                        "Interface.%d.Device.%d", ale_idx, iface_idx + 1, idx);

                    rc = rbusTable_unregisterRow(g_bus_handle, tname);
                    if (rc != RBUS_ERROR_SUCCESS) {
                        log_lib_e("Failed to delete row[%d] for eth_devs", idx);
                    }
                }
            }
            set_dev_dm_eth_devs(ale, iface_idx, new_count);
        }
    } while (0);

    if (ale->update_unassoc_sta_link_metrics) {
        unassoc_sta_link_metrics_response_process(ale);
        ale->update_unassoc_sta_link_metrics = 0;
    }
}

static void dm_rbus_remove_ale(map_ale_info_t *ale)
{
    unsigned int ale_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    log_lib_d("remove ale[%d]: %s", ale->dm_idx, ale->al_mac_str);

    if (is_local_agent(ale)) {
        return;
    }

    if (check_dev_dm_idx(ale) < 0) {
        log_lib_e("Invalid indexing for ale");
        return;
    }

    ale_idx = ale->dm_idx;

    snprintf(tname, sizeof(tname),
        "Device.WiFi.DataElements.Network.Device.%d", ale_idx);

    rc = rbusTable_unregisterRow(g_bus_handle, tname);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to delete row[%d] for ale: %s",
            ale_idx, ale->al_mac_str);
    }

    free_dev_dm_idx(ale_idx);

    if (0) {
        /* This may be enabled to shift indexes, if the data model
           automatically keeps indexing consecutive. rbus does not
           support it, tr069 forbids it */
        update_ale_idxs(ale);
    }

    /* Mark child objects are removed */
    mark_radios_removed(ale);

    return;
}

static rbusError_t device_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
#define CCODE_LEN   3
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_device_info_t *device_info;
    char country_code[CCODE_LEN] = {0};

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }
    device_info = &ale->device_info;

    sscanf(name, "%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "ID") == 0) {
        rbusValue_SetString(value, ale->al_mac_str);
    } else if (strcmp(param, "Manufacturer") == 0) {
        rbusValue_SetString(value, device_info->manufacturer_name);
    } else if (strcmp(param, "SerialNumber") == 0) {
        if (ale->inventory_exists) {
            rbusValue_SetString(value, ale->inventory.serial);
        } else {
            rbusValue_SetString(value, device_info->serial_number);
        }
    } else if (strcmp(param, "ManufacturerModel") == 0) {
        rbusValue_SetString(value, device_info->model_name);
    } else if (strcmp(param, "SoftwareVersion") == 0) {
        if (ale->inventory_exists) {
            rbusValue_SetString(value, ale->inventory.version);
        } else {
            rbusValue_SetString(value, device_info->os_version_str);
        }
    } else if (strcmp(param, "ExecutionEnv") == 0) {
        if (ale->inventory_exists) {
            rbusValue_SetString(value, ale->inventory.environment);
        } else {
            rbusValue_SetString(value, "Linux");
        }
    } else if (strcmp(param, "CountryCode") == 0) {
        get_country_code_str(ale->country_code, country_code);
        rbusValue_SetString(value, country_code);
    } else if (strcmp(param, "RadioNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, ale->radios_nr);
    } else if (strcmp(param, "MultiAPProfile") == 0) {
        rbusValue_SetUInt32(value, ale->map_profile);
    } else if (strcmp(param, "CACStatusNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, ale->cac_status_report.valid ? 1 : 0);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul      #
########################################################################*/
static rbusError_t backhaul_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "MultiAPDevice.Backhaul.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "LinkType") == 0) {
        rbusValue_SetString(value, get_backhaul_link_type_str(ale));
    } else if (strcmp(param, "BackhaulMACAddress") == 0) {
        rbusValue_SetString(value, mac_string(ale->upstream_remote_iface_mac));
    } else if (strcmp(param, "BackhaulDeviceID") == 0) {
        rbusValue_SetString(value, mac_string(ale->upstream_al_mac));
    } else if (strcmp(param, "MACAddress") == 0) {
        rbusValue_SetString(value, mac_string(ale->upstream_local_iface_mac));
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.MultiAPDevice.Backhaul.Stats          #
########################################################################*/
static rbusError_t bhstats_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_ale_info_t *us_ale;
    int8_t iface_group;
    map_sta_info_t *sta;
    map_sta_traffic_stats_t *ts;
    map_sta_link_metrics_t *lm;
    map_sta_ext_bss_metrics_t *ebm;
    char timestamp[MAX_TS_STR_LEN] = {0};

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "MultiAPDevice.Backhaul.Stats.%s", param);

    sta = NULL;
    ts = NULL;
    lm = NULL;
    iface_group = INTERFACE_TYPE_GROUP_GET(ale->upstream_iface_type);
    if (iface_group == INTERFACE_TYPE_GROUP_WLAN) {
        us_ale = map_dm_get_ale(ale->upstream_al_mac);
        if (us_ale) {
            sta = map_dm_get_sta_from_ale(us_ale, ale->upstream_local_iface_mac);
            ts = sta ? sta->traffic_stats : NULL;
            lm = (sta && sta->metrics) ? first_object(sta->metrics) : NULL;
        } else {
            log_lib_w("Upstream ale not found");
        }
    } else {
        log_lib_w("Stats not supported for %s", get_backhaul_link_type_str(ale));
    }

    rbusValue_Init(&value);

    if (strcmp(param, "BytesReceived") == 0) {
        if (iface_group == INTERFACE_TYPE_GROUP_WLAN) {
            rbusValue_SetUInt64(value, ts ? ts->rxbytes : 0);
        } else {
            rbusValue_SetUInt64(value, 0);
        }
    } else if (strcmp(param, "BytesSent") == 0) {
        if (iface_group == INTERFACE_TYPE_GROUP_WLAN) {
            rbusValue_SetUInt64(value, ts ? ts->txbytes : 0);
        } else {
            rbusValue_SetUInt64(value, 0);
        }
    } else if (strcmp(param, "PacketsReceived") == 0) {
        if (iface_group == INTERFACE_TYPE_GROUP_WLAN) {
            rbusValue_SetUInt64(value, ts ? ts->rxpkts : 0);
        } else {
            rbusValue_SetUInt64(value, 0);
        }
    } else if (strcmp(param, "PacketsSent") == 0) {
        if (iface_group == INTERFACE_TYPE_GROUP_WLAN) {
            rbusValue_SetUInt64(value, ts ? ts->txpkts : 0);
        } else {
            rbusValue_SetUInt64(value, 0);
        }
    } else if (strcmp(param, "ErrorsReceived") == 0) {
        if (iface_group == INTERFACE_TYPE_GROUP_WLAN) {
            rbusValue_SetUInt64(value, ts ? ts->rxpkterrors : 0);
        } else {
            rbusValue_SetUInt64(value, 0);
        }
    } else if (strcmp(param, "ErrorsSent") == 0) {
        if (iface_group == INTERFACE_TYPE_GROUP_WLAN) {
            rbusValue_SetUInt64(value, ts ? ts->txpkterrors : 0);
        } else {
            rbusValue_SetUInt64(value, 0);
        }
    } else if (strcmp(param, "SignalStrength") == 0) {
        /* Indeterminate other than Wi-Fi */
        rbusValue_SetUInt32(value, lm ? lm->rssi : 0);
    } else if (strcmp(param, "LastDataDownlinkRate") == 0) {
        if (get_last_sta_metrics(sta, &ebm) == 0 && ebm != NULL) {
            rbusValue_SetUInt32(value, ebm->last_data_dl_rate);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "LastDataUplinkRate") == 0) {
        if (get_last_sta_metrics(sta, &ebm) == 0 && ebm != NULL) {
            rbusValue_SetUInt32(value, ebm->last_data_ul_rate);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "TimeStamp") == 0) {
        get_timestamp_str(0, timestamp, sizeof(timestamp));
        rbusValue_SetString(value, timestamp);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.CACStatus                   #
########################################################################*/
static rbusError_t cacstatus_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int cac_idx;
    map_ale_info_t *ale;
    char timestamp[MAX_TS_STR_LEN] = {0};
    map_cac_status_report_t *csr;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "CACStatus.%d.%s", &cac_idx, param);

    /* There is only one CACStatus at a time */
    if (cac_idx != 1) {
        log_lib_e("Invalid CAC status index: %d", cac_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }
    csr = ale->cac_status_report.valid ? &ale->cac_status_report : NULL;

    rbusValue_Init(&value);

    if (strcmp(param, "TimeStamp") == 0) {
        get_timestamp_str(0, timestamp, sizeof(timestamp));
        rbusValue_SetString(value, timestamp);
    } else if (strcmp(param, "CACAvailableChannelNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, csr ? csr->available_pairs_nr : 0);
    } else if (strcmp(param, "CACNonOccupancyChannelNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, csr ? csr->non_occupancy_pairs_nr : 0);
    } else if (strcmp(param, "CACActiveChannelNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, csr ? csr->ongoing_cac_pairs_nr : 0);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.CACStatus.CACAvailableChannel         #
########################################################################*/
static rbusError_t cacavail_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int cac_idx;
    unsigned int avail_idx;
    map_ale_info_t *ale;
    map_cac_status_report_t *csr;
    map_cac_available_pair_t *avp;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "CACStatus.%d.CACAvailableChannel.%d.%s",
        &cac_idx, &avail_idx, param);

    /* There is only one CACStatus at a time */
    if (cac_idx != 1) {
        log_lib_e("Invalid CAC status index: %d", cac_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }
    csr = ale->cac_status_report.valid ? &ale->cac_status_report : NULL;

    if (csr && avail_idx > csr->available_pairs_nr) {
        log_lib_e("Invalid available channel index: %d", avail_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }
    avp = &csr->available_pairs[avail_idx - 1];

    rbusValue_Init(&value);

    if (strcmp(param, "OpClass") == 0) {
        rbusValue_SetUInt32(value, avp ? avp->op_class : 0);
    } else if (strcmp(param, "Channel") == 0) {
        rbusValue_SetUInt32(value, avp ? avp->channel : 0);
    } else if (strcmp(param, "Minutes") == 0) {
        rbusValue_SetUInt32(value, avp ? avp->minutes_since_cac_completion : 0);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.CACStatus.CACNonOccupancyChannel      #
########################################################################*/
static rbusError_t cacnonocc_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int cac_idx;
    unsigned int non_occ_idx;
    map_ale_info_t *ale;
    map_cac_status_report_t *csr;
    map_cac_non_occupancy_pair_t *nop;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "CACStatus.%d.CACNonOccupancyChannel.%d.%s",
        &cac_idx, &non_occ_idx, param);

    /* There is only one CACStatus at a time */
    if (cac_idx != 1) {
        log_lib_e("Invalid CAC status index: %d", cac_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }
    csr = ale->cac_status_report.valid ? &ale->cac_status_report : NULL;

    if (csr && non_occ_idx > csr->non_occupancy_pairs_nr) {
        log_lib_e("Invalid non occupancy channel index: %d", non_occ_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }
    nop = &csr->non_occupancy_pairs[non_occ_idx - 1];

    rbusValue_Init(&value);

    if (strcmp(param, "OpClass") == 0) {
        rbusValue_SetUInt32(value, nop ? nop->op_class : 0);
    } else if (strcmp(param, "Channel") == 0) {
        rbusValue_SetUInt32(value, nop ? nop->channel : 0);
    } else if (strcmp(param, "Seconds") == 0) {
        rbusValue_SetUInt32(value, nop ? nop->seconds_remaining_non_occupancy_duration : 0);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.CACStatus.CACActiveChannel            #
########################################################################*/
static rbusError_t cacactive_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int cac_idx;
    unsigned int active_idx;
    map_ale_info_t *ale;
    map_cac_status_report_t *csr;
    map_cac_ongoing_pair_t *onp;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "CACStatus.%d.CACActiveChannel.%d.%s",
        &cac_idx, &active_idx, param);

    /* There is only one CACStatus at a time */
    if (cac_idx != 1) {
        log_lib_e("Invalid CAC status index: %d", cac_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }
    csr = ale->cac_status_report.valid ? &ale->cac_status_report : NULL;

    if (csr && active_idx > csr->ongoing_cac_pairs_nr) {
        log_lib_e("Invalid active channel index: %d", active_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }
    onp = &csr->ongoing_cac_pairs[active_idx - 1];

    rbusValue_Init(&value);

    if (strcmp(param, "OpClass") == 0) {
        rbusValue_SetUInt32(value, onp ? onp->op_class : 0);
    } else if (strcmp(param, "Channel") == 0) {
        rbusValue_SetUInt32(value, onp ? onp->channel : 0);
    } else if (strcmp(param, "Countdown") == 0) {
        rbusValue_SetUInt32(value, onp ? onp->seconds_remaining_cac_completion : 0);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.Radio                       #
########################################################################*/
static void dm_rbus_create_radio(map_radio_info_t *radio)
{
#define MAX_RUID_STR_LEN    10
    unsigned int ale_idx;
    unsigned int radio_idx;
    unsigned int idx;
    char         radio_id[MAX_RUID_STR_LEN] = {0};
    char         tname[256] = {0};
    rbusError_t  rc;

    log_lib_d("create radio: %s", radio->radio_id_str);

    if (check_dev_dm_idx(radio->ale) < 0) {
        log_lib_e("invalid indexing for radio");
        return;
    }

    ale_idx = radio->ale->dm_idx;
    if (get_radio_dm_idx(ale_idx, radio, &radio_idx) < 0) {
        log_lib_e("could not find free index for radio: %s", radio->radio_id_str);
        return;
    }

    if (b64_encode(radio->radio_id, sizeof(mac_addr), radio_id, sizeof(radio_id)) < 0) {
        log_lib_e("b64_encode failed");
    }

    /* Register new radio to data model */
    snprintf(tname, sizeof(tname),
        "Device.WiFi.DataElements.Network.Device.%d.Radio.", ale_idx);

    rc = rbusTable_registerRow(g_bus_handle, tname, radio_idx + 1, radio_id);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for radio: %s",
            radio_idx + 1, radio->radio_id_str);
    }

    /* Register current operating class profiles to data model */
    snprintf(tname, sizeof(tname),
        "Device.WiFi.DataElements.Network.Device.%d.Radio.%d."
        "CurrentOperatingClassProfile.", ale_idx, radio_idx + 1);

    for (idx = 1; idx <= radio->curr_op_class_list.op_classes_nr; idx++) {
        rc = rbusTable_registerRow(g_bus_handle, tname, idx, NULL);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to create row[%d] for curr_op_class", idx);
        }
    }
    set_radio_dm_currops(radio, radio->curr_op_class_list.op_classes_nr);

    /* Register capable operating class profiles to data model */
    snprintf(tname, sizeof(tname),
        "Device.WiFi.DataElements.Network.Device.%d.Radio.%d."
        "Capabilities.CapableOperatingClassProfile.", ale_idx, radio_idx + 1);

    for (idx = 1; idx <= radio->cap_op_class_list.op_classes_nr; idx++) {
        rc = rbusTable_registerRow(g_bus_handle, tname, idx, NULL);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to create row[%d] for cap_op_classes", idx);
        }
    }
    set_radio_dm_capops(radio, radio->cap_op_class_list.op_classes_nr);
}

static void scan_send_results(map_radio_info_t *radio)
{
    list_iterator_t *it;
    map_scan_result_t *msr;
    map_channel_scan_neighbor_t *ni;
    rbusObject_t sri;
    rbusObject_t ocsi;
    rbusObject_t chsi;
    rbusObject_t nbi;
    mac_addr_str bssid;
    rbusMethodAsyncHandle_t async;
    rbusObject_t out;
    rbusError_t rc = RBUS_ERROR_SUCCESS;

    get_radio_dm_scan_reply(radio, &async);
    if (async == NULL) {
        /* No destination set for scan results */
        return;
    }

    rbusObject_Init(&out, "Output");

    if (0 == list_get_size(radio->scanned_bssid_list)) {
        log_lib_e("There is no scan results for this radio");
        rbus_add_prop_str(out, "Status", "Error_Timeout");
        rc = RBUS_ERROR_BUS_ERROR;
        goto fail;
    }

    if (NULL == (it = new_list_iterator(radio->scanned_bssid_list))) {
        log_lib_e("Scan result list cannot be found for this radio!");
        rbus_add_prop_str(out, "Status", "Error_Timeout");
        rc = RBUS_ERROR_BUS_ERROR;
        goto fail;
    }

    rbus_add_prop_str(out, "Status", "Success");
    /* ScanResult.{i} */
    sri = rbus_add_obj_inst(out, "ScanResult", NULL, RBUS_NONE, NULL);
    rbus_add_prop_str(sri, "TimeStamp", (char *)radio->last_scan_info.last_scan_ts);
    while (it->iter != NULL) {
        msr = (map_scan_result_t *)get_next_list_object(it);
        if (!msr || (msr->scan_cnt != radio->last_scan_info.last_scan_cnt)) {
            continue;
        }

        /* ScanResult.{i}.OpClassScan.{i} */
        ocsi = rbus_add_obj_inst(sri, "OpClassScan", "OperatingClass",
            RBUS_UINT8, &msr->opclass);
        if (!ocsi) {
            continue;
        }

        /* ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i} */
        chsi = rbus_add_obj_inst(ocsi, "ChannelScan", "Channel",
            RBUS_UINT8, &msr->channel);
        if (!chsi) {
            continue;
        }
        rbus_add_prop_str(chsi, "TimeStamp", (char *)msr->channel_scan_ts);

        /* ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i} */
        ni = &msr->neighbor_info;
        mac_to_string(ni->bssid, bssid);
        nbi = rbus_add_obj_inst(chsi, "NeighborBSS", "BSSID", RBUS_STRING, &bssid);
        if (!nbi) {
            continue;
        }
        rbus_add_prop_str(nbi, "SSID", (char *)ni->ssid);
        rbus_add_prop_uint32(nbi, "SignalStrength", ni->rcpi);
        rbus_add_prop_str(nbi, "ChannelBandwidth", (char *)ni->ch_bw);
        if (msr->neighbor_info.bss_load_elem_present == 1) {
            rbus_add_prop_uint32(nbi, "ChannelUtilization", ni->channel_utilization);
            rbus_add_prop_uint32(nbi, "StationCount", ni->stas_nr);
        }
    }
    free_list_iterator(it);

fail:
    rc = rbusMethod_SendAsyncResponse(async, rc, out);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Channel scan response failed: %d", rc);
    }

    rbusObject_Release(out);

    set_radio_dm_scan_reply(radio, NULL);
}

static dm_nbss_table_t *dm_rbus_create_nbss(
    unsigned int didx, unsigned int ridx, unsigned int sidx,
    unsigned int oidx, unsigned int cidx, mac_addr bssid)
{
    dm_radio_table_t *dm_radio;
    dm_scan_table_t  *dm_scan;
    dm_opcl_table_t  *dm_opcl;
    dm_chan_table_t  *dm_chan;
    dm_nbss_table_t  *dm_nbss;
    unsigned int      nbss_idx;
    char              tname[256] = {0};
    rbusError_t       rc;

    dm_radio = &g_dm_dev_table[didx].dm_radio[ridx];
    dm_scan = get_dm_radio_scan(dm_radio, sidx);
    if (dm_scan == NULL) {
        return NULL;
    }
    dm_opcl = get_dm_scan_opcl(dm_scan, oidx);
    if (dm_opcl == NULL) {
        return NULL;
    }
    dm_chan = get_dm_opcl_chan(dm_opcl, cidx);
    if (dm_chan == NULL) {
        return NULL;
    }

    /* Check if dm_nbss exist with given bssid */
    list_for_each_entry(dm_nbss, &dm_chan->nbss_list, list) {
        if (maccmp(bssid, dm_nbss->id) == 0) {
            return dm_nbss;
        }
    }

    /* New neighbour info for channel */
    dm_nbss = calloc(1, sizeof(dm_nbss_table_t));
    if (dm_nbss == NULL) {
        return NULL;
    }

    dm_nbss->dm_chan = dm_chan;
    dm_nbss->idx = nbss_idx = ++dm_chan->nbss_idx;
    maccpy(dm_nbss->id, bssid);

    snprintf(tname, sizeof(tname), "Device.WiFi.DataElements.Network."
        "Device.%d.Radio.%d.ScanResult.%d.OpClassScan.%d."
        "ChannelScan.%d.NeighborBSS.",
        didx, ridx + 1, sidx, oidx, cidx);

    rc = rbusTable_registerRow(g_bus_handle, tname, nbss_idx, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for neigh_bss", nbss_idx);
        free(dm_nbss);
        return NULL;
    }

    INIT_LIST_HEAD(&dm_nbss->list);

    /* Add to linked list */
    dm_chan->nbss_cnt++;
    list_add_tail(&dm_nbss->list, &dm_chan->nbss_list);

    return dm_nbss;
}

static int dm_rbus_remove_nbss(dm_nbss_table_t *dm_nbss, bool rm_row, unsigned int didx, unsigned int ridx)
{
    if (rm_row) {
        unsigned int nidx = dm_nbss->idx;
        unsigned int cidx = dm_nbss->dm_chan->idx;
        unsigned int oidx = dm_nbss->dm_chan->dm_opcl->idx;
        unsigned int sidx = dm_nbss->dm_chan->dm_opcl->dm_scan->idx;
        char         tname[256] = {0};
        rbusError_t  rc;

        /* Delete neighborbss row with index */
        snprintf(tname, sizeof(tname), "Device.WiFi.DataElements.Network."
            "Device.%d.Radio.%d.ScanResult.%d.OpClassScan.%d."
            "ChannelScan.%d.NeighborBSS.%d",
            didx, ridx + 1, sidx, oidx, cidx, nidx);

        rc = rbusTable_unregisterRow(g_bus_handle, tname);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to delete row[%d] for nbss", nidx);
        }
    }

    /* Unlink */
    list_del(&dm_nbss->list);

    free(dm_nbss);

    return 0;
}

static dm_chan_table_t *dm_rbus_create_chan(
    unsigned int didx, unsigned int ridx, unsigned int sidx,
    unsigned int oidx, unsigned int channel)
{
    dm_radio_table_t *dm_radio;
    dm_scan_table_t  *dm_scan;
    dm_opcl_table_t  *dm_opcl;
    dm_chan_table_t  *dm_chan;
    unsigned int      chan_idx;
    char              tname[256] = {0};
    rbusError_t       rc;

    dm_radio = &g_dm_dev_table[didx].dm_radio[ridx];
    dm_scan = get_dm_radio_scan(dm_radio, sidx);
    if (dm_scan == NULL) {
        return NULL;
    }
    dm_opcl = get_dm_scan_opcl(dm_scan, oidx);
    if (dm_opcl == NULL) {
        return NULL;
    }

    /* Check if dm_chan exist with given channel */
    list_for_each_entry(dm_chan, &dm_opcl->chan_list, list) {
        if (channel == dm_chan->id) {
            return dm_chan;
        }
    }

    /* New channel for op class */
    dm_chan = calloc(1, sizeof(dm_chan_table_t));
    if (dm_scan == NULL) {
        return NULL;
    }

    dm_chan->dm_opcl = dm_opcl;
    dm_chan->idx = chan_idx = ++dm_opcl->chan_idx;
    dm_chan->id = channel;

    snprintf(tname, sizeof(tname), "Device.WiFi.DataElements.Network."
        "Device.%d.Radio.%d.ScanResult.%d.OpClassScan.%d.ChannelScan.",
        didx, ridx + 1, sidx, oidx);

    rc = rbusTable_registerRow(g_bus_handle, tname, chan_idx, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for chan_scan", chan_idx);
        free(dm_chan);
        return NULL;
    }

    INIT_LIST_HEAD(&dm_chan->list);
    INIT_LIST_HEAD(&dm_chan->nbss_list);

    /* Add to linked list */
    dm_opcl->chan_cnt++;
    list_add_tail(&dm_chan->list, &dm_opcl->chan_list);

    return dm_chan;
}

static int dm_rbus_remove_chan(dm_chan_table_t *dm_chan, bool rm_row, unsigned int didx, unsigned int ridx)
{
    dm_nbss_table_t *dm_nbss, *next;

    if (rm_row) {
        unsigned int cidx = dm_chan->idx;
        unsigned int oidx = dm_chan->dm_opcl->idx;
        unsigned int sidx = dm_chan->dm_opcl->dm_scan->idx;
        char         tname[256] = {0};
        rbusError_t  rc;

        /* Delete channelscan row with index */
        snprintf(tname, sizeof(tname), "Device.WiFi.DataElements.Network."
            "Device.%d.Radio.%d.ScanResult.%d.OpClassScan.%d.ChannelScan.%d",
            didx, ridx + 1, sidx, oidx, cidx);

        rc = rbusTable_unregisterRow(g_bus_handle, tname);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to delete row[%d] for channel", cidx);
        }
    }

    /* Cleanup dm_nbss nodes under the chan */
    list_for_each_entry_safe(dm_nbss, next, &dm_chan->nbss_list, list) {
        dm_rbus_remove_nbss(dm_nbss, false, didx, ridx);
        dm_chan->nbss_cnt--;
    }

    /* Unlink */
    list_del(&dm_chan->list);

    free(dm_chan);

    return 0;
}

static dm_opcl_table_t *dm_rbus_create_opcl(
    unsigned int didx, unsigned int ridx, unsigned int sidx,
    unsigned int opclass)
{
    dm_radio_table_t *dm_radio;
    dm_scan_table_t  *dm_scan;
    dm_opcl_table_t  *dm_opcl;
    unsigned int      opcl_idx;
    char              tname[256] = {0};
    rbusError_t       rc;

    dm_radio = &g_dm_dev_table[didx].dm_radio[ridx];
    dm_scan = get_dm_radio_scan(dm_radio, sidx);
    if (dm_scan == NULL) {
        return NULL;
    }

    /* Check if dm_opcl exist with given op class */
    list_for_each_entry(dm_opcl, &dm_scan->opcl_list, list) {
        if (opclass == dm_opcl->id) {
            return dm_opcl;
        }
    }

    /* New op class for scan results */
    dm_opcl = calloc(1, sizeof(dm_opcl_table_t));
    if (dm_opcl == NULL) {
        return NULL;
    }

    dm_opcl->dm_scan = dm_scan;
    dm_opcl->idx = opcl_idx = ++dm_scan->opcl_idx;
    dm_opcl->id = opclass;

    snprintf(tname, sizeof(tname), "Device.WiFi.DataElements.Network."
        "Device.%d.Radio.%d.ScanResult.%d.OpClassScan.", didx, ridx + 1, sidx);

    rc = rbusTable_registerRow(g_bus_handle, tname, opcl_idx, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for opcl_scan", opcl_idx);
        free(dm_opcl);
        return NULL;
    }

    INIT_LIST_HEAD(&dm_opcl->list);
    INIT_LIST_HEAD(&dm_opcl->chan_list);

    /* Add to linked list */
    dm_scan->opcl_cnt++;
    list_add_tail(&dm_opcl->list, &dm_scan->opcl_list);

    return dm_opcl;
}

static int dm_rbus_remove_opcl(dm_opcl_table_t *dm_opcl, bool rm_row, unsigned int didx, unsigned int ridx)
{
    dm_chan_table_t *dm_chan, *next;

    if (rm_row) {
        unsigned int oidx = dm_opcl->idx;
        unsigned int sidx = dm_opcl->dm_scan->idx;
        char         tname[256] = {0};
        rbusError_t  rc;

        /* Delete opclassscan row with index */
        snprintf(tname, sizeof(tname), "Device.WiFi.DataElements.Network."
            "Device.%d.Radio.%d.ScanResult.%d.OpClassScan.%d",
            didx, ridx + 1, sidx, oidx);

        rc = rbusTable_unregisterRow(g_bus_handle, tname);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to delete row[%d] for opclass", oidx);
        }
    }

    /* Cleanup dm_chan nodes under the opcl */
    list_for_each_entry_safe(dm_chan, next, &dm_opcl->chan_list, list) {
        dm_rbus_remove_chan(dm_chan, false, didx, ridx);
        dm_opcl->chan_cnt--;
    }

    /* Unlink */
    list_del(&dm_opcl->list);

    free(dm_opcl);

    return 0;
}

static dm_scan_table_t *dm_rbus_create_scan(
    unsigned int didx, unsigned int ridx, map_scan_info_t *scan)
{
    dm_radio_table_t *dm_radio;
    dm_scan_table_t  *dm_scan;
    unsigned int      scan_idx;
    char              tname[256] = {0};
    rbusError_t       rc;

    dm_radio = &g_dm_dev_table[didx].dm_radio[ridx];

    /* Check if dm_scan exist with given scan id */
    list_for_each_entry(dm_scan, &dm_radio->scan_list, list) {
        if ((unsigned int)scan->last_scan_cnt == dm_scan->id) {
            return dm_scan;
        }
    }

    /* New scan result for radio */
    dm_scan = calloc(1, sizeof(dm_scan_table_t));
    if (dm_scan == NULL) {
        return NULL;
    }

    dm_scan->dm_radio = dm_radio;
    dm_scan->idx = scan_idx = ++dm_radio->scan_idx;
    dm_scan->id = scan->last_scan_cnt;

    snprintf(tname, sizeof(tname), "Device.WiFi.DataElements.Network."
        "Device.%d.Radio.%d.ScanResult.", didx, ridx + 1);

    rc = rbusTable_registerRow(g_bus_handle, tname, scan_idx, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for scan_results", scan_idx);
        free(dm_scan);
        return NULL;
    }

    INIT_LIST_HEAD(&dm_scan->list);
    INIT_LIST_HEAD(&dm_scan->opcl_list);

    /* Add to linked list */
    dm_radio->scan_cnt++;
    list_add_tail(&dm_scan->list, &dm_radio->scan_list);

    return dm_scan;
}

static int dm_rbus_remove_scan(dm_scan_table_t *dm_scan, bool rm_row, unsigned int didx, unsigned int ridx)
{
    dm_opcl_table_t *dm_opcl, *next;

    if (rm_row) {
        unsigned int sidx = dm_scan->idx;
        char         tname[256] = {0};
        rbusError_t  rc;

        /* Delete scanres row with index */
        snprintf(tname, sizeof(tname), "Device.WiFi.DataElements.Network."
            "Device.%d.Radio.%d.ScanResult.%d", didx, ridx + 1, sidx);

        rc = rbusTable_unregisterRow(g_bus_handle, tname);
        if (rc != RBUS_ERROR_SUCCESS) {
            log_lib_e("Failed to delete row[%d] for scanres", sidx);
        }
    }

    /* Cleanup dm_opcl nodes under the scan */
    list_for_each_entry_safe(dm_opcl, next, &dm_scan->opcl_list, list) {
        dm_rbus_remove_opcl(dm_opcl, false, didx, ridx);
        dm_scan->opcl_cnt--;
    }

    /* Unlink */
    list_del(&dm_scan->list);

    free(dm_scan);

    return 0;
}

static void scan_update_results(map_radio_info_t *radio)
{
    unsigned int ale_idx;
    unsigned int radio_idx;
    list_iterator_t *it;
    map_scan_result_t *sr;
    dm_radio_table_t *dm_radio;
    dm_scan_table_t *dm_scan;
    dm_opcl_table_t *dm_opcl;
    dm_chan_table_t *dm_chan;
    dm_nbss_table_t *dm_nbss;
    unsigned int nbss_cnt;

    dm_radio = &g_dm_dev_table[radio->ale->dm_idx].dm_radio[radio->dm_idx];

    if (0 == list_get_size(radio->scanned_bssid_list)) {
        /* There is no scan results for this radio at all */
        return;
    }

    if (NULL == (it = new_list_iterator(radio->scanned_bssid_list))) {
        /* Scan result list cannot be found for this radio */
        return;
    }

    radio_idx = radio->dm_idx;
    ale_idx   = radio->ale->dm_idx;

    /* ScanResult.{i} */
    dm_scan = dm_rbus_create_scan(ale_idx, radio_idx, &radio->last_scan_info);
    if (dm_scan == NULL) {
        return;
    }

    nbss_cnt = 0;
    while (it->iter != NULL) {
        sr = (map_scan_result_t *)get_next_list_object(it);
        if (!sr || (sr->scan_cnt != radio->last_scan_info.last_scan_cnt)) {
            continue;
        }

        /* ScanResult.{i}.OpClassScan.{i} */
        dm_opcl = dm_rbus_create_opcl(ale_idx, radio_idx, dm_scan->idx, sr->opclass);
        if (!dm_opcl) {
            continue;
        }

        /* ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i} */
        dm_chan = dm_rbus_create_chan(ale_idx, radio_idx, dm_scan->idx,
            dm_opcl->idx, sr->channel);
        if (!dm_chan) {
            continue;
        }

        /* ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i} */
        dm_nbss = dm_rbus_create_nbss(ale_idx, radio_idx, dm_scan->idx,
            dm_opcl->idx, dm_chan->idx, sr->neighbor_info.bssid);
        if (!dm_nbss) {
            continue;
        }

        ++nbss_cnt;
    }
    free_list_iterator(it);

    if (nbss_cnt == 0) {
        /* Empty scan result, remove here and decrease index */
        dm_rbus_remove_scan(dm_scan, true, ale_idx, radio_idx);
        dm_radio->scan_cnt--;
        dm_radio->scan_idx--;
    }
}

static void scan_remove_results(map_radio_info_t *radio)
{
    list_iterator_t *it;
    dm_radio_table_t *dm_radio;
    dm_scan_table_t *dm_scan, *scan_next;
    dm_opcl_table_t *dm_opcl, *opcl_next;
    dm_chan_table_t *dm_chan, *chan_next;
    dm_nbss_table_t *dm_nbss, *nbss_next;
    map_scan_result_t *sr;
    unsigned int didx;
    unsigned int ridx;
    int found;

    ridx = radio->dm_idx;
    didx = radio->ale->dm_idx;
    dm_radio = &g_dm_dev_table[didx].dm_radio[ridx];

    if (NULL == (it = new_list_iterator(radio->scanned_bssid_list))) {
        return;
    }

    list_for_each_entry_safe(dm_scan, scan_next, &dm_radio->scan_list, list) {
        found = 0;
        reset_list_iterator(it);
        while (it->iter != NULL) {
            sr = (map_scan_result_t *)get_next_list_object(it);
            if (!sr) {
                continue;
            }

            if (dm_scan->id == (unsigned int)sr->scan_cnt) {
                found = 1;
                break;
            }
        }
        if (!found) {
            dm_rbus_remove_scan(dm_scan, true, didx, ridx);
            dm_radio->scan_cnt--;
            continue;
        }

        list_for_each_entry_safe(dm_opcl, opcl_next, &dm_scan->opcl_list, list) {
            found = 0;
            reset_list_iterator(it);
            while (it->iter != NULL) {
                sr = (map_scan_result_t *)get_next_list_object(it);
                if (!sr) {
                    continue;
                }

                if (dm_scan->id == (unsigned int)sr->scan_cnt &&
                    dm_opcl->id == sr->opclass) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                dm_rbus_remove_opcl(dm_opcl, true, didx, ridx);
                dm_scan->opcl_cnt--;
                continue;
            }

            list_for_each_entry_safe(dm_chan, chan_next, &dm_opcl->chan_list, list) {
                found = 0;
                reset_list_iterator(it);
                while (it->iter != NULL) {
                    sr = (map_scan_result_t *)get_next_list_object(it);
                    if (!sr) {
                        continue;
                    }

                    if (dm_scan->id == (unsigned int)sr->scan_cnt &&
                        dm_opcl->id == sr->opclass &&
                        dm_chan->id == sr->channel) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    dm_rbus_remove_chan(dm_chan, true, didx, ridx);
                    dm_opcl->chan_cnt--;
                    continue;
                }

                list_for_each_entry_safe(dm_nbss, nbss_next, &dm_chan->nbss_list, list) {
                    found = 0;
                    reset_list_iterator(it);
                    while (it->iter != NULL) {
                        sr = (map_scan_result_t *)get_next_list_object(it);
                        if (!sr) {
                            continue;
                        }

                        if (dm_scan->id == (unsigned int)sr->scan_cnt &&
                            dm_opcl->id == sr->opclass &&
                            dm_chan->id == sr->channel &&
                            maccmp(dm_nbss->id, sr->neighbor_info.bssid) == 0) {
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        dm_rbus_remove_nbss(dm_nbss, true, didx, ridx);
                        dm_chan->nbss_cnt--;
                        continue;
                    }
                }
            }
        }
    }
    free_list_iterator(it);
}

static void dm_rbus_update_radio(map_radio_info_t *radio)
{
    unsigned int ale_idx;
    unsigned int radio_idx;
    unsigned int idx;
    unsigned int curr_count;
    unsigned int new_count;
    char         tname[256] = {0};
    rbusError_t  rc;

    log_lib_d("update radio[%d]: %s", radio->dm_idx, radio->radio_id_str);

    if (check_radio_dm_idx(radio) < 0) {
        log_lib_e("Invalid indexing for radio");
        return;
    }

    radio_idx = radio->dm_idx;
    ale_idx   = radio->ale->dm_idx;

    get_radio_dm_currops(radio, &curr_count);
    new_count = radio->curr_op_class_list.op_classes_nr;
    if (curr_count < new_count) {
        /* Add missing current operating class profiles */
        snprintf(tname, sizeof(tname),
            "Device.WiFi.DataElements.Network.Device.%d.Radio.%d."
            "CurrentOperatingClassProfile.", ale_idx, radio_idx + 1);

        curr_count = curr_count ? curr_count : 1;
        for (idx = curr_count; idx <= new_count; idx++) {
            rc = rbusTable_registerRow(g_bus_handle, tname, idx, NULL);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to create row[%d] for curr_op_class", idx);
            }
        }
    } else {
        /* Remove excess current operating class profiles */
        for (idx = curr_count; idx > new_count; idx--) {
            snprintf(tname, sizeof(tname),
                "Device.WiFi.DataElements.Network.Device.%d.Radio.%d."
                "CurrentOperatingClassProfile.%d", ale_idx, radio_idx + 1, idx);

            rc = rbusTable_unregisterRow(g_bus_handle, tname);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to delete row[%d] for curr_op_class", idx);
            }
        }
    }
    set_radio_dm_currops(radio, new_count);

    get_radio_dm_capops(radio, &curr_count);
    new_count = radio->cap_op_class_list.op_classes_nr;
    if (curr_count < new_count) {
        /* Add missing capable operating class profiles */
        snprintf(tname, sizeof(tname),
            "Device.WiFi.DataElements.Network.Device.%d.Radio.%d."
            "Capabilities.CapableOperatingClassProfile.", ale_idx, radio_idx + 1);

        curr_count = curr_count ? curr_count : 1;
        for (idx = curr_count; idx <= new_count; idx++) {
            rc = rbusTable_registerRow(g_bus_handle, tname, idx, NULL);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to create row[%d] for cap_op_class", idx);
            }
        }
    } else {
        /* Remove excess capable operating class profiles */
        for (idx = curr_count; idx > new_count; idx--) {
            snprintf(tname, sizeof(tname),
                "Device.WiFi.DataElements.Network.Device.%d.Radio.%d."
                "Capabilities.CapableOperatingClassProfile.%d",
                ale_idx, radio_idx + 1, idx);

            rc = rbusTable_unregisterRow(g_bus_handle, tname);
            if (rc != RBUS_ERROR_SUCCESS) {
                log_lib_e("Failed to delete row[%d] for cap_op_class", idx);
            }
        }
    }
    set_radio_dm_capops(radio, new_count);

    if (radio->update_scan_results) {
        scan_send_results(radio);
        scan_update_results(radio);
        scan_remove_results(radio);
        radio->update_scan_results = 0;
    }
}

static void dm_rbus_remove_radio(map_radio_info_t *radio)
{
    unsigned int ale_idx;
    unsigned int radio_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    log_lib_d("remove radio[%d]: %s", radio->dm_idx, radio->radio_id_str);

    if (radio->dm_removed) {
        return;
    }

    if (check_radio_dm_idx(radio) < 0) {
        log_lib_e("Invalid indexing for radio");
        return;
    }

    radio_idx = radio->dm_idx;
    ale_idx   = radio->ale->dm_idx;

    /* Delete radio row with index */
    snprintf(tname, sizeof(tname),
        "Device.WiFi.DataElements.Network.Device.%d.Radio.%d",
        ale_idx, radio_idx + 1);

    rc = rbusTable_unregisterRow(g_bus_handle, tname);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to delete row[%d] for radio: %s",
            radio_idx + 1, radio->radio_id_str);
    }

    /* TODO: Does unregister row also clears leftover reply handles?
             I doubt it */

    free_radio_dm_idx(ale_idx, radio_idx);

    if (0) {
        /* This may be enabled to shift indexes, if the data model
           automatically keeps indexing consecutive. rbus does not support
           it, tr069 forbids it */
        update_radio_idxs(radio->ale, radio);
    }

    /* Mark child objects are removed */
    mark_bsss_removed(radio);
}

static rbusError_t radio_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
#define MAX_RUID_STR_LEN    10
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_bss_info_t *bss;
    map_emex_t *emex;
    map_emex_radio_info_t *info = NULL;
    char buf[MAX_RUID_STR_LEN] = {0};
    bool bss_metrics_valid;
    uint8_t i;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }
    emex = &ale->emex;

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "ID") == 0) {
        if (b64_encode(radio->radio_id, sizeof(mac_addr), buf, sizeof(buf)) < 0) {
            log_lib_e("b64_encode failed");
        }
        rbusValue_SetString(value, buf);
    } else if (strcmp(param, "Enabled") == 0) {
        rbusValue_SetBoolean(value, is_radio_on(radio->state) ? true : false);
    } else if (strcmp(param, "Noise") == 0) {
        if (radio->radio_metrics.valid) {
            rbusValue_SetUInt32(value, radio->radio_metrics.noise);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "Utilization") == 0) {
        bss_metrics_valid = false;
        map_dm_foreach_bss(radio, bss) {
            if (bss->metrics.valid) {
                bss_metrics_valid = true;
                break;
            }
        }
        if (bss_metrics_valid) {
            rbusValue_SetUInt32(value, bss->metrics.channel_utilization);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "Transmit") == 0) {
        if (radio->radio_metrics.valid) {
            rbusValue_SetUInt32(value, radio->radio_metrics.transmit);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "ReceiveSelf") == 0) {
        if (radio->radio_metrics.valid) {
            rbusValue_SetUInt32(value, radio->radio_metrics.receive_self);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "ReceiveOther") == 0) {
        if (radio->radio_metrics.valid) {
            rbusValue_SetUInt32(value, radio->radio_metrics.receive_other);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "X_AIRTIES_Temperature") == 0) {
        if (emex->enabled) {
            for (i = 0; i < emex->radios.count; i++) {
                if (!maccmp(radio->radio_id, emex->radios.info[i].id)) {
                    info = &emex->radios.info[i];
                    break;
                }
            }
            rbusValue_SetUInt32(value, info ? info->temp : 0);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "BSSNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, radio->bsss_nr);
    } else if (strcmp(param, "CurrentOperatingClassProfileNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, radio->curr_op_class_list.op_classes_nr);
    } else if (strcmp(param, "ScanResultNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, radio->last_scan_info.last_scan_cnt);
    } else if (strcmp(param, "UnassociatedSTANumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, list_get_size(radio->unassoc_sta_list));
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.Radio.ChannelScanRequest()            #
#   ..DataElements.Network.Device.Radio.MultiAPRadio.ChannelScan()      #
#   ..DataElements.Network.Device.Radio.MultiAPRadio.FullScan()         #
########################################################################*/
static int chscan_parse_classes(rbusObject_t in, map_nb_ch_scan_param_t *payload)
{
    rbusObject_t ocl;
    rbusObject_t ocli;
    rbusObject_t och;
    rbusObject_t ochi;
    map_op_class_t *op_class;
    uint32_t op_class_cnt;
    uint32_t class;
    uint32_t channel;
    uint16_t  bw;
    rbusValueError_t rc;

    /* Input.OpClass */
    ocl = rbusObject_GetChildren(in);
    if (!ocl) {
        log_lib_e("OpClass is mandatory");
        return -1;
    }
    /* Input.OpClass.{i} */
    ocli = rbusObject_GetChildren(ocl);
    if (!ocli) {
        log_lib_e("OpClass instance is mandatory");
        return -1;
    }

    op_class_cnt = 0;
    do {
        /* Input.OpClass.{i}.OperatingClass */
        rc = rbusObject_GetPropertyUInt32(ocli, "OperatingClass", &class);
        if (rc != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("OperatingClass is mandatory");
            return -1;
        }
        /* Only 20MHz op classes are valid */
        if (0 != map_get_bw_from_op_class(class, &bw) || 20 != bw) {
            log_lib_e("OperatingClass is not 20MHz");
            return -1;
        }

        ++op_class_cnt;
        op_class = &payload->op_classes[op_class_cnt - 1];
        op_class->op_class = class;

        /* Input.OpClass.{i}.Channel */
        och = rbusObject_GetChildren(ocli);
        if (!och) {
            log_lib_e("Channel is mandatory");
            return -1;
        }
        /* Input.OpClass.{i}.Channel.{i} */
        ochi = rbusObject_GetChildren(och);
        if (!och) {
            log_lib_e("Channel instance is mandatory");
            return -1;
        }

        do {
            /* Input.OpClass.{i}.Channel.{i}.Channel */
            rc = rbusObject_GetPropertyUInt32(ochi, "Channel", &channel);
            if (rc != RBUS_VALUE_ERROR_SUCCESS) {
                log_lib_e("OperatingClass is mandatory");
                return -1;
            }
            map_cs_set(&op_class->channels, channel);

            ochi = rbusObject_GetNext(ochi);
        } while (ochi);

        ocli = rbusObject_GetNext(ocli);
    } while (ocli) ;
    payload->op_classes_nr = op_class_cnt;

    return 0;
}

static void parse_channel_list(const char *buffer, unsigned int blen, map_channel_set_t *channels)
{
    uint8_t pos;
    char chbuf[4] = {0};
    uint32_t channel;

    pos = 0;
    while (blen) {
        if (*buffer >= '0' && *buffer <= '9') {
            if (pos >= 4) {
                /* Invalid input */
                memset(chbuf, 0, pos);
                pos = 0;
            }
            chbuf[pos++] = *buffer;
        } else {
            if (pos) {
                channel = atoi(chbuf);
                map_cs_set(channels, channel);
                memset(chbuf, 0, pos);
            }
            pos = 0;
        }
        ++buffer;
        --blen;
    }
    if (pos) {
        channel = atoi(chbuf);
        map_cs_set(channels, channel);
    }
}

void chscan_fill_classes(map_radio_info_t *radio, map_nb_ch_scan_param_t *payload)
{
    int i;

    /* Add all 20MHz op classes from scan cap tlv */
    for (i = 0; i < radio->scan_caps.op_class_list.op_classes_nr &&
                payload->op_classes_nr < MAX_OP_CLASS; i++) {
        map_op_class_t *src = &radio->scan_caps.op_class_list.op_classes[i];
        map_op_class_t *dst = &payload->op_classes[payload->op_classes_nr];
        uint16_t        bw;

        if (0 != map_get_bw_from_op_class(src->op_class, &bw) || 20 != bw) {
            continue;
        }

        /* Start with what we received from channel scan capabilities */
        dst->op_class = src->op_class;
        map_cs_copy(&dst->channels, &src->channels);

        /* If 0 channels then add all supported channels in op_class */
        if (map_cs_nr(&dst->channels) == 0) {
            if (0 != map_get_channel_set_from_op_class(src->op_class, &dst->channels)) {
                continue;
            }
            map_cs_and(&dst->channels, &radio->ctl_channels);
        }

        /* Skip op_class if no channels set */
        if (map_cs_nr(&dst->channels) == 0) {
            continue;
        }

        payload->op_classes_nr++;
    }
}

static rbusError_t radio_chscan_rbus(rbusHandle_t handle, char const* method, rbusObject_t in, rbusObject_t out, rbusMethodAsyncHandle_t async)
{
    (void) handle;
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_nb_ch_scan_param_t payload = {0};
    uint32_t dtime;
    uint32_t dfs_dtime;
    uint32_t htime;
    const char *ssid;
    uint32_t class;
    const char *channels;
    rbusValueError_t rc;
    int len;

    rbusObject_SetName(out, "Output");

    method += sizeof(DM_DEVICE_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        goto bail;
    }

    method += sizeof(DM_RADIO_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        goto bail;
    }
    maccpy(payload.radio_id, radio->radio_id);

    sscanf(method, "%s", param);

    if (!is_radio_initial_scan_results_received(radio->state)) {
        log_lib_e("Radio not ready yet");
        rbus_add_prop_str(out, "Status", "Error_Not_Ready");
        return RBUS_ERROR_INVALID_METHOD;
    }

    /* Check for ongoing scan, reply with not ready if necessary */

    if (strcmp(param, "MultiAPRadio.FullScan()") == 0 ||
        strcmp(param, "MultiAPRadio.ChannelScan()") == 0) {
        rc = rbusObject_GetPropertyUInt32(in, "DwellTime", &dtime);
        if (rc != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("DwellTime is mandatory");
            goto bail;
        }
        payload.dwell_time = dtime;

        rc = rbusObject_GetPropertyUInt32(in, "DFSDwellTime", &dfs_dtime);
        if (rc != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("DFSDwellTime is mandatory");
            goto bail;
        }
        payload.dfs_dwell_time = dfs_dtime;

        rc = rbusObject_GetPropertyUInt32(in, "HomeTime", &htime);
        if (rc == RBUS_VALUE_ERROR_SUCCESS) {
            payload.home_time = htime;
        }

        rc = rbusObject_GetPropertyString(in, "SSID", &ssid, &len);
        if (rc == RBUS_VALUE_ERROR_SUCCESS) {
            len = len > (MAX_SSID_LEN - 1) ? (MAX_SSID_LEN - 1) : len;
            strncpy(payload.ssid, ssid, len);
        }

        if (strcmp(param, "MultiAPRadio.ChannelScan()") == 0) {
            if (chscan_parse_classes(in, &payload)) {
                goto bail;
            }
        } else {
            chscan_fill_classes(radio, &payload);
        }
    } else if (strcmp(param, "ChannelScanRequest()") == 0) {
        payload.op_classes_nr = 1;
        rc = rbusObject_GetPropertyUInt32(in, "OpClass", &class);
        if (rc != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("OpClass is mandatory");
            goto bail;
        }
        payload.op_classes[0].op_class = class;

        rc = rbusObject_GetPropertyString(in, "ChannelList", &channels, &len);
        if (rc != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("ChannelList is mandatory");
            goto bail;
        }
        parse_channel_list(channels, len, &payload.op_classes[0].channels);
    } else {
        log_lib_e("Invalid param: %s", param);
        goto bail;
    }

    /* Perform scan */
    if (map_dm_get_nbapi()->channel_scan != NULL) {
        map_dm_get_nbapi()->channel_scan(ale, &payload);
        set_radio_dm_scan_reply(radio, async);
    } else {
        log_lib_e("Channel scan is not available");
        rbus_add_prop_str(out, "Status", "Error_Not_Ready");
        return RBUS_ERROR_INVALID_METHOD;
    }

#if 0 //Do we still need to set a timer for timeout?
    /* Prepare response timer */
    reply = calloc(1, sizeof(method_chscan_async_t));
    if (!reply) {
        rbus_add_prop_str(out, "Status", "Error_Other");
        return RBUS_ERROR_OUT_OF_RESOURCES;
    }
    reply->ale_idx = ale->dm_idx;
    reply->radio_idx = radio->dm_idx;
    reply->async = async;
    map_timer_register_callback(CHSAN_RESPONSE_TIMEOUT,
        CHSAN_RESPONSE_TIMER_ID, reply, chscan_async_cb);
#endif

    return RBUS_ERROR_ASYNC_RESPONSE;

bail:
    rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
    return RBUS_ERROR_INVALID_INPUT;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.Radio.BackhaulSta           #
########################################################################*/
static rbusError_t bhsta_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_backhaul_sta_iface_t *iface;
    uint8_t i;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "BackhaulSta.%s", param);

    iface = NULL;
    for (i = 0; i < ale->backhaul_sta_iface_count; i++) {
        if (!maccmp(radio->radio_id, ale->backhaul_sta_iface_list[i].radio_id)) {
            iface = &ale->backhaul_sta_iface_list[i];
            break;
        }
    }

    rbusValue_Init(&value);

    if (strcmp(param, "MACAddress") == 0) {
        if (iface /* && iface->active */) {
            rbusValue_SetString(value, mac_string(iface->mac_address));
        } else {
            rbusValue_SetString(value, "00:00:00:00:00:00");
        }
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.Radio.Capabilities          #
########################################################################*/
static rbusError_t caps_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
#define MAX_CAPS_STR_LEN    32
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    char caps_str[MAX_CAPS_STR_LEN] = {0};

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "Capabilities.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "HTCapabilities") == 0) {
        if (radio->ht_caps) {
            get_ht_caps_str(radio->ht_caps, caps_str, sizeof(caps_str));
            rbusValue_SetString(value, caps_str);
        } else {
            rbusValue_SetString(value, "");
        }
    } else if (strcmp(param, "VHTCapabilities") == 0) {
        if (radio->vht_caps) {
            get_vht_caps_str(radio->vht_caps, caps_str, sizeof(caps_str));
            rbusValue_SetString(value, caps_str);
        } else {
            rbusValue_SetString(value, "");
        }
    } else if (strcmp(param, "HECapabilities") == 0) {
        if (radio->he_caps) {
            get_he_caps_str(radio->he_caps, caps_str, sizeof(caps_str));
            rbusValue_SetString(value, caps_str);
        } else {
            rbusValue_SetString(value, "");
        }
    } else if (strcmp(param, "CapableOperatingClassProfileNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, radio->cap_op_class_list.op_classes_nr);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..Network.Device.Radio.Capabilities.CapableOperatingClassProfile    #
########################################################################*/
static rbusError_t capop_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int cap_op_idx;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_op_class_t *op_class;
    char nonoper_str[MAP_CS_BUF_LEN] = {0};

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "Capabilities.CapableOperatingClassProfile.%d.%s",
        &cap_op_idx, param);

    if (cap_op_idx > (unsigned int)(radio->cap_op_class_list.op_classes_nr + 1)) {
        log_lib_e("Invalid capable operating class index: %d", cap_op_idx - 1);
        return RBUS_ERROR_INVALID_INPUT;
    }
    op_class = &radio->cap_op_class_list.op_classes[cap_op_idx - 1];

    rbusValue_Init(&value);

    if (strcmp(param, "Class") == 0) {
        rbusValue_SetUInt32(value, op_class->op_class);
    } else if (strcmp(param, "MaxTxPower") == 0) {
        rbusValue_SetInt32(value, op_class->eirp);
    } else if (strcmp(param, "NonOperable") == 0) {
        map_cs_to_string(&op_class->channels, ',', nonoper_str, sizeof(nonoper_str));
        rbusValue_SetString(value, nonoper_str);
    } else if (strcmp(param, "NumberOfNonOperChan") == 0) {
        rbusValue_SetUInt32(value, op_class->channels.nr);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.Radio.CurrentOperatingClassProfile    #
########################################################################*/
static rbusError_t currop_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
#define MAX_CH_STR_LEN  6
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int curr_op_idx;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_op_class_t *op_class;
    char ch_str[MAX_CH_STR_LEN] = {0};
    char timestamp[MAX_TS_STR_LEN] = {0};

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "CurrentOperatingClassProfile.%d.%s", &curr_op_idx, param);

    if (curr_op_idx > (unsigned int)(radio->curr_op_class_list.op_classes_nr + 1)) {
        log_lib_e("Invalid current operating class index: %d", curr_op_idx - 1);
        return RBUS_ERROR_INVALID_INPUT;
    }
    op_class = &radio->curr_op_class_list.op_classes[curr_op_idx - 1];

    rbusValue_Init(&value);

    if (strcmp(param, "Class") == 0) {
        rbusValue_SetUInt32(value, op_class->op_class);
    } else if (strcmp(param, "Channel") == 0) {
        if (op_class->channels.nr == 1) {
            map_cs_to_string(&op_class->channels, ',', ch_str, sizeof(ch_str));
            rbusValue_SetUInt32(value, atoi(ch_str));
        } else {
            log_lib_w("Internal error");
            rbusValue_SetUInt32(value, radio->current_op_channel);
        }
    } else if (strcmp(param, "TxPower") == 0) {
        rbusValue_SetInt32(value, op_class->eirp);
    } else if (strcmp(param, "TimeStamp") == 0) {
        get_timestamp_str(0, timestamp, sizeof(timestamp));
        rbusValue_SetString(value, timestamp);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.Radio.ScanResult            #
########################################################################*/
static rbusError_t scanres_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int scan_idx;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_scan_info_t *si;
    dm_scan_table_t *dm_scan;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "ScanResult.%d.%s", &scan_idx, param);

    dm_scan = get_radio_dm_scan(radio, scan_idx);
    if (dm_scan == NULL) {
        log_lib_e("Invalid scan index: %d", scan_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    si = &radio->last_scan_info;

    rbusValue_Init(&value);

    if (strcmp(param, "TimeStamp") == 0) {
        /* Copy ts to dm_scan */
        rbusValue_SetString(value, (char *)si->last_scan_ts);
    } else if (strcmp(param, "OpClassScanNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, dm_scan->opcl_cnt);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.Radio.ScanResult.OpClassScan          #
########################################################################*/
static rbusError_t opclscan_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int scan_idx;
    unsigned int opcl_idx;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    dm_scan_table_t *dm_scan;
    dm_opcl_table_t *dm_opcl;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "ScanResult.%d.OpClassScan.%d.%s",
        &scan_idx, &opcl_idx, param);

    dm_scan = get_radio_dm_scan(radio, scan_idx);
    if (dm_scan == NULL) {
        log_lib_e("Invalid scan index: %d", scan_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    dm_opcl = get_dm_scan_opcl(dm_scan, opcl_idx);
    if (dm_opcl == NULL) {
        log_lib_e("Invalid op class index: %d", opcl_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);

    if (strcmp(param, "OperatingClass") == 0) {
        rbusValue_SetUInt32(value, dm_opcl->id);
    } else if (strcmp(param, "ChannelScanNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, dm_opcl->chan_cnt);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..Network.Device.Radio.ScanResult.OpClassScan.ChannelScan           #
########################################################################*/
static rbusError_t chscan_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int scan_idx;
    unsigned int opcl_idx;
    unsigned int chan_idx;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    dm_scan_table_t *dm_scan;
    dm_opcl_table_t *dm_opcl;
    dm_chan_table_t *dm_chan;
    map_scan_result_t *sr;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "ScanResult.%d.OpClassScan.%d.ChannelScan.%d.%s",
        &scan_idx, &opcl_idx, &chan_idx, param);

    dm_scan = get_radio_dm_scan(radio, scan_idx);
    if (dm_scan == NULL) {
        log_lib_e("Invalid scan index: %d", scan_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    dm_opcl = get_dm_scan_opcl(dm_scan, opcl_idx);
    if (dm_opcl == NULL) {
        log_lib_e("Invalid op class index: %d", opcl_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    dm_chan = get_dm_opcl_chan(dm_opcl, chan_idx);
    if (dm_chan == NULL) {
        log_lib_e("Invalid channel index: %d", chan_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sr = map_dm_rbus_get_scanres(radio, dm_scan->id, dm_opcl->id, dm_chan->id);
    if (sr == NULL) {
        log_lib_e("Invalid scan id");
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);

    if (strcmp(param, "Channel") == 0) {
        rbusValue_SetUInt32(value, dm_chan->id);
    } else if (strcmp(param, "TimeStamp") == 0) {
        rbusValue_SetString(value, (char *)sr->channel_scan_ts);
    } else if (strcmp(param, "Utilization") == 0) {
        rbusValue_SetUInt32(value, 0);
    } else if (strcmp(param, "Noise") == 0) {
        rbusValue_SetInt32(value, 0);
    } else if (strcmp(param, "NeighborBSSNumberOfEntries") == 0) {
        rbusValue_SetInt32(value, dm_chan->nbss_cnt);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..Device.Radio.ScanResult.OpClassScan.ChannelScan.NeighborBSS       #
########################################################################*/
static rbusError_t nbss_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int scan_idx;
    unsigned int opcl_idx;
    unsigned int chan_idx;
    unsigned int nbss_idx;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    dm_scan_table_t *dm_scan;
    dm_opcl_table_t *dm_opcl;
    dm_chan_table_t *dm_chan;
    dm_nbss_table_t *dm_nbss;
    map_channel_scan_neighbor_t *ni;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "ScanResult.%d.OpClassScan.%d.ChannelScan.%d.NeighborBSS.%d.%s",
        &scan_idx, &opcl_idx, &chan_idx, &nbss_idx, param);

    dm_scan = get_radio_dm_scan(radio, scan_idx);
    if (dm_scan == NULL) {
        log_lib_e("Invalid scan index: %d", scan_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    dm_opcl = get_dm_scan_opcl(dm_scan, opcl_idx);
    if (dm_opcl == NULL) {
        log_lib_e("Invalid op class index: %d", opcl_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    dm_chan = get_dm_opcl_chan(dm_opcl, chan_idx);
    if (dm_chan == NULL) {
        log_lib_e("Invalid channel index: %d", chan_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    dm_nbss = get_dm_chan_nbss(dm_chan, nbss_idx);
    if (dm_nbss == NULL) {
        log_lib_e("Invalid neighbour info index: %d", nbss_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    ni = map_dm_rbus_get_nb_info(radio, dm_scan->id, dm_opcl->id,
        dm_chan->id, dm_nbss->id);
    if (ni == NULL) {
        log_lib_e("Invalid scan credentials");
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);

    if (strcmp(param, "BSSID") == 0) {
        rbusValue_SetString(value, mac_string(ni->bssid));
    } else if (strcmp(param, "SSID") == 0) {
        rbusValue_SetString(value, (char *)ni->ssid);
    } else if (strcmp(param, "SignalStre") == 0) {
        rbusValue_SetInt32(value, ni->rcpi);
    } else if (strcmp(param, "ChannelBan") == 0) {
        rbusValue_SetString(value, (char *)ni->ch_bw);
    } else if (strcmp(param, "ChannelUti") == 0) {
        if (ni->bss_load_elem_present == 1) {
            rbusValue_SetUInt32(value, ni->channel_utilization);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "StationCou") == 0) {
        if (ni->bss_load_elem_present == 1) {
            rbusValue_SetUInt32(value, ni->stas_nr);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.Radio.BSS                   #
########################################################################*/
static void dm_rbus_create_bss(map_bss_info_t *bss)
{
    unsigned int ale_idx;
    unsigned int radio_idx;
    unsigned int bss_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    log_lib_d("create bss: %s", bss->bssid_str);

    if (check_radio_dm_idx(bss->radio) < 0) {
        log_lib_e("Invalid indexing for bss");
        return;
    }

    radio_idx = bss->radio->dm_idx;
    ale_idx   = bss->radio->ale->dm_idx;
    if (get_bss_dm_idx(ale_idx, radio_idx, bss, &bss_idx) < 0) {
        log_lib_e("No free index for bss: %s", bss->bssid_str);
        return;
    }

    snprintf(tname, sizeof(tname) - 1,
        "Device.WiFi.DataElements.Network.Device.%d.Radio.%d.BSS.",
        ale_idx, radio_idx + 1);

    rc = rbusTable_registerRow(g_bus_handle, tname, bss_idx + 1, bss->bssid_str);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for bss: %s",
            bss_idx + 1, bss->bssid_str);
    }

    return;
}

static void dm_rbus_update_bss(map_bss_info_t *bss)
{
    log_lib_d("update bss[%d]: %s", bss->dm_idx, bss->bssid_str);

    if (check_bss_dm_idx(bss) < 0) {
        log_lib_e("Invalid indexing for bss");
    }
}

static void dm_rbus_remove_bss(map_bss_info_t *bss)
{
    unsigned int ale_idx;
    unsigned int radio_idx;
    unsigned int bss_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    log_lib_d("remove bss[%d]: %s", bss->dm_idx, bss->bssid_str);

    if (bss->dm_removed) {
        return;
    }

    if (check_bss_dm_idx(bss) < 0) {
        log_lib_e("Invalid indexing for bss");
        return;
    }

    bss_idx   = bss->dm_idx;
    radio_idx = bss->radio->dm_idx;
    ale_idx   = bss->radio->ale->dm_idx;

    snprintf(tname, sizeof(tname) - 1,
        "Device.WiFi.DataElements.Network.Device.%d.Radio.%d.BSS.%d",
        ale_idx, radio_idx + 1, bss_idx + 1);

    rc = rbusTable_unregisterRow(g_bus_handle, tname);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to delete row[%d] for bss: %s",
            bss_idx + 1, bss->bssid_str);
    }

    free_bss_dm_idx(ale_idx, radio_idx, bss_idx);

    if (0) {
        /* This may be enabled to shift indexes, if the data model
           automatically keeps indexing consecutive. rbus does not
           support it, tr069 forbids it */
        update_bss_idxs(bss->radio, bss);
    }

    /* Mark child objects are removed */
    mark_stas_removed(bss);
}

static rbusError_t bss_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_bss_info_t *bss;
    uint32_t last_change;
    char timestamp[MAX_TS_STR_LEN] = {0};
    map_profile_cfg_t *profile = NULL;
    map_controller_cfg_t *cfg;
    unsigned int i;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_BSS_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    bss = dm_get_bss(radio, param, is_num);
    if (bss == NULL) {
        log_lib_e("Invalid bss %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "BSSID") == 0) {
        rbusValue_SetString(value, bss->bssid_str);
    } else if (strcmp(param, "SSID") == 0) {
        rbusValue_SetString(value, bss->ssid);
    } else if (strcmp(param, "Enabled") == 0) {
        rbusValue_SetBoolean(value, is_bss_active(bss->state) ? true : false);
    } else if (strcmp(param, "LastChange") == 0) {
        last_change = acu_get_timestamp_sec() - bss->change_ts;
        rbusValue_SetUInt32(value, last_change);
    } else if (strcmp(param, "TimeStamp") == 0) {
        get_timestamp_str(0, timestamp, sizeof(timestamp));
        rbusValue_SetString(value, timestamp);
    } else if (strcmp(param, "UnicastBytesReceived") == 0) {
        rbusValue_SetUInt64(value, bss->extended_metrics.ucast_bytes_rx);
    } else if (strcmp(param, "UnicastBytesSent") == 0) {
        rbusValue_SetUInt64(value, bss->extended_metrics.ucast_bytes_tx);
    } else if (strcmp(param, "MulticastBytesReceived") == 0) {
        rbusValue_SetUInt64(value, bss->extended_metrics.mcast_bytes_rx);
    } else if (strcmp(param, "MulticastBytesSent") == 0) {
        rbusValue_SetUInt64(value, bss->extended_metrics.mcast_bytes_tx);
    } else if (strcmp(param, "BroadcastBytesReceived") == 0) {
        rbusValue_SetUInt64(value, bss->extended_metrics.bcast_bytes_rx);
    } else if (strcmp(param, "BroadcastBytesSent") == 0) {
        rbusValue_SetUInt64(value, bss->extended_metrics.bcast_bytes_tx);
    } else if (strcmp(param, "BackhaulUse") == 0) {
        rbusValue_SetBoolean(value, (bss->type & MAP_BACKHAUL_BSS) ? true : false);
    } else if (strcmp(param, "FronthaulUse") == 0) {
        rbusValue_SetBoolean(value, (bss->type & MAP_FRONTHAUL_BSS) ? true : false);
    } else if (strcmp(param, "FronthaulAKMsAllowed") == 0) {
        cfg = &map_cfg_get()->controller_cfg;
        for (i = 0; i < cfg->num_profiles; i++) {
            if (strcmp(bss->ssid, cfg->profiles[i].bss_ssid) == 0) {
                profile = &cfg->profiles[i];
                break;
            }
        }
        if (profile && (profile->bss_state & MAP_FRONTHAUL_BSS)) {
            rbusValue_SetString(value,
                get_auth_mode_str(profile->supported_auth_modes));
        } else {
            rbusValue_SetString(value, "none");
        }
    } else if (strcmp(param, "BackhaulAKMsAllowed") == 0) {
        cfg = &map_cfg_get()->controller_cfg;
        for (i = 0; i < cfg->num_profiles; i++) {
            if (strcmp(bss->ssid, cfg->profiles[i].bss_ssid) == 0) {
                profile = &cfg->profiles[i];
                break;
            }
        }
        if (profile && (profile->bss_state & MAP_BACKHAUL_BSS)) {
            rbusValue_SetString(value,
                get_auth_mode_str(profile->supported_auth_modes));
        } else {
            rbusValue_SetString(value, "none");
        }
    } else if (strcmp(param, "STANumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, bss->stas_nr);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

static rbusError_t rbus_method_client_assoc_control(rbusHandle_t handle, char const* method, rbusObject_t in, rbusObject_t out, rbusMethodAsyncHandle_t async)
{
    (void) handle;
    (void) async;
    rbusError_t ret;
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_bss_info_t *bss;
    map_nb_assoc_control_params_t payload = {0};
    const char *sta_mac_list;
    rbusValueError_t rc;
    int len;
    bool block;
    uint32_t period;

    rbusObject_SetName(out, "Output");

    method += sizeof(DM_DEVICE_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        ret = RBUS_ERROR_INVALID_INPUT;
        goto bail;
    }

    method += sizeof(DM_RADIO_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        ret = RBUS_ERROR_INVALID_INPUT;
        goto bail;
    }

    method += sizeof(DM_BSS_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    bss = dm_get_bss(radio, param, is_num);
    if (bss == NULL) {
        log_lib_e("Invalid bss %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        ret = RBUS_ERROR_INVALID_INPUT;
        goto bail;
    }
    maccpy(payload.bssid, bss->bssid);

    sscanf(method, "%s", param);
    rc = rbusObject_GetPropertyString(in, "StationsList", &sta_mac_list, &len);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("StationsList is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        ret = RBUS_ERROR_INVALID_INPUT;
        goto bail;
    }
    else {
        char *token = NULL;
        uint32_t num_sta_mac = 0;
        uint32_t i = 0;
        char *list, *tofree;

        tofree = list = strdup(sta_mac_list);
        if ( !list ) {
            log_lib_e("Can't create a copy of StationsList parameter!");
            rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
            ret = RBUS_ERROR_INVALID_INPUT;
            goto bail;
        }

        while ( (token = strsep(&list, ",")) ) {
            mac_addr mac = {0};
            if (mac_from_string(token, mac) == 0) {
                num_sta_mac++;
            }
            else {
                num_sta_mac = 0;
                break;
            }
        }
        free(tofree);

        if (num_sta_mac && num_sta_mac <= MAX_STATION_PER_BSS) {
            payload.sta_mac_list = calloc(num_sta_mac, sizeof(mac_addr));
            if (!payload.sta_mac_list) {
                log_lib_e("No Memory!");
                rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
                return RBUS_ERROR_INVALID_INPUT;
            }
            payload.num_sta_mac = num_sta_mac;

            i = 0;
            tofree = list = strdup(sta_mac_list);
            if ( !list ) {
                log_lib_e("Can't create a copy of StationsList parameter!");
                rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
                ret = RBUS_ERROR_INVALID_INPUT;
                goto bail;
            }

            while ( (token = strsep(&list, ",")) ) {
                mac_from_string(token, payload.sta_mac_list[i]);
                i++;
            }
            free(tofree);
        }
        else {
            log_lib_e("StationsList is not valid MAC address list");
            rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
            ret = RBUS_ERROR_INVALID_INPUT;
            goto bail;
        }
    }

    rc = rbusObject_GetPropertyBoolean(in, "Block", &block);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("Block is mandatory");
        ret = RBUS_ERROR_INVALID_INPUT;
        goto bail;
    }
    payload.block = block;

    if (payload.block) {
        rc = rbusObject_GetPropertyUInt32(in, "Period", &period);
        if (rc != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("Period is mandatory");
            ret = RBUS_ERROR_INVALID_INPUT;
            goto bail;
        }
        payload.period = period;
    }

    if (map_dm_get_nbapi()->assoc_control != NULL) {
        map_dm_get_nbapi()->assoc_control(ale, &payload);

        rbus_add_prop_str(out, "Status", "Success");
        ret = RBUS_ERROR_SUCCESS;
    } else {
        log_lib_e("ClientAssocControl method is not implemented yet");
        rbus_add_prop_str(out, "Status", "Error_Not_Ready");
        ret = RBUS_ERROR_INVALID_INPUT;
        goto bail;
    }

bail:
    SFREE(payload.sta_mac_list);

    return ret;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.Radio.BSS.STA               #
########################################################################*/
static void map_dm_rbus_steering_history_add(map_sta_info_t *sta, uint32_t row_index)
{
    unsigned int ale_idx;
    unsigned int radio_idx;
    unsigned int bss_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    log_lib_d("Add SteeringHistory row for: %s", sta->mac_str);

    if (check_bss_dm_idx(sta->bss) < 0) {
        log_lib_e("Invalid indexing for sta");
        return;
    }

    bss_idx   = sta->bss->dm_idx;
    radio_idx = sta->bss->radio->dm_idx;
    ale_idx   = sta->bss->radio->ale->dm_idx;

    snprintf(tname, sizeof(tname) - 1,
        "Device.WiFi.DataElements.Network.Device.%d.Radio.%d.BSS.%d.STA.%d.MultiAPSTA.SteeringHistory.",
        ale_idx, radio_idx + 1, bss_idx + 1, sta->dm_idx + 1);

    rc = rbusTable_registerRow(g_bus_handle, tname, row_index, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row %s %d rowindex: %d", tname, rc, row_index);
        return;
    }

    log_lib_d("Added a row %s%d", tname, row_index);
}

static void map_dm_rbus_steering_history_update(map_sta_info_t *sta)
{
    uint32_t index = 0;

    if (sta->steering_history_size_delta == 0) {
        return;
    }

    index = list_get_size(sta->steering_history) - sta->steering_history_size_delta + 1; // wrong
    while (sta->steering_history_size_delta) {
        map_dm_rbus_steering_history_add(sta, index);
        index++;
        sta->steering_history_size_delta--;
    }
}

static void map_dm_rbus_steering_history_reinit(map_sta_info_t *sta)
{
    uint32_t index = 1;
    uint32_t list_size = list_get_size(sta->steering_history);

    while (list_size) {
        map_dm_rbus_steering_history_add(sta, index);
        index++;
        list_size--;
    }
}

static void map_dm_rbus_client_steer_send_result(map_sta_info_t *sta_info)
{
    mac_addr_str target_bssid;
    rbusMethodAsyncHandle_t async = NULL;
    rbusObject_t out;
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    map_sta_steering_history_t *steering_history = NULL;

    map_dm_rbus_client_steer_async_reply_get(sta_info, &async);
    if (async == NULL) {
        log_lib_e("Can't find async handle!");
        return;
    }

    rbusObject_Init(&out, "Output");

     steering_history = last_object(sta_info->steering_history);
     if (!steering_history) {
        rbus_add_prop_str(out, "Status", "Error_Other");
        goto bail;
     }

    rbus_add_prop_str(out, "Status",
        (steering_history->btm_response == IEEE80211_BTM_STATUS_ACCEPT) ? "Success" : "Error_Other");
    rbus_add_prop_uint32(out, "BTMStatusCode", steering_history->btm_response);
    mac_to_string(steering_history->ap_dest, target_bssid);
    rbus_add_prop_str(out, "TargetBSSID", target_bssid);

 bail:
    rc = rbusMethod_SendAsyncResponse(async, rc, out);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("ClientSteer() response failed: %d", rc);
    }

    rbusObject_Release(out);

    map_dm_rbus_client_steer_async_reply_set(sta_info, NULL);
}

static void dm_rbus_create_sta(map_sta_info_t *sta)
{
    unsigned int ale_idx;
    unsigned int radio_idx;
    unsigned int bss_idx;
    unsigned int sta_idx;
    char         tname[256] = {0};
    rbusError_t  rc;
    map_radio_info_t *radio = sta->bss->radio;

    log_lib_d("create sta: %s", sta->mac_str);

    if (check_bss_dm_idx(sta->bss) < 0) {
        log_lib_e("Invalid indexing for sta");
        return;
    }

    bss_idx   = sta->bss->dm_idx;
    radio_idx = sta->bss->radio->dm_idx;
    ale_idx   = sta->bss->radio->ale->dm_idx;
    if (get_sta_dm_idx(ale_idx, radio_idx, bss_idx, sta, &sta_idx) < 0) {
        log_lib_e("No free index for sta: %s", sta->mac_str);
        return;
    }

    snprintf(tname, sizeof(tname) - 1,
        "Device.WiFi.DataElements.Network.Device.%d.Radio.%d.BSS.%d.STA.",
        ale_idx, radio_idx + 1, bss_idx + 1);

    log_lib_d("Create row[%d] at %s", sta_idx + 1, tname);

    rc = rbusTable_registerRow(g_bus_handle, tname, sta_idx + 1, sta->mac_str);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for sta: %s",
            sta_idx + 1, sta->mac_str);
    }

    map_dm_rbus_steering_history_reinit(sta);

    if (!sta->dm_payload) {
        sta->dm_payload = calloc(1, sizeof(dm_sta_payload_t));
    }

    map_dm_rbus_client_steer_send_result(sta);

    radio_remove_unassoc_sta(radio, sta->mac);
}

static void bmquery_send_result(map_sta_info_t *sta)
{
    rbusMethodAsyncHandle_t async = NULL;
    rbusObject_t out;
    char *report_str;
    uint32_t report_cnt;
    rbusError_t rc = RBUS_ERROR_SUCCESS;

    get_sta_dm_bmquery_reply(sta, &async);
    if (async == NULL) {
        log_lib_i("No ongoing measurement");
        return;
    }

    report_cnt = list_get_size(sta->beacon_metrics);
    if (report_cnt == 0 && sta->bmquery_status == 0) {
        log_lib_i("Measurement in progress");
        return;
    }

    rbusObject_Init(&out, "Output");

    if (report_cnt == 0 || sta->bmquery_status != 0) {
        log_lib_w("Measurement complete with no report");
        rbus_add_prop_str(out, "Status", "Error_Other");
        goto reply;
    }

    report_str = get_beacon_metrics_str(sta->beacon_metrics);

    rbus_add_prop_str(out, "Status", "Success");
    rbus_add_prop_uint32(out, "NumberOfMeasureReports", report_cnt);
    rbus_add_prop_str(out, "MeasurementReport", report_str);

    free(report_str);

reply:
    rc = rbusMethod_SendAsyncResponse(async, rc, out);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("BeaconMetricsQuery() response failed: %d", rc);
    }

    rbusObject_Release(out);

    set_sta_dm_bmquery_reply(sta, NULL);
}

static void dm_rbus_update_sta(map_sta_info_t *sta)
{
    log_lib_d("update sta[%d]: %s", sta->dm_idx, sta->mac_str);

    if (check_sta_dm_idx(sta) < 0) {
        log_lib_e("Invalid indexing for sta");
    }

    map_dm_rbus_steering_history_update(sta);

    /* Not proper, need a way to distinguish */
    bmquery_send_result(sta);

    map_dm_rbus_client_steer_send_result(sta);
}

static void dm_rbus_remove_sta(map_sta_info_t *sta)
{
    unsigned int ale_idx;
    unsigned int radio_idx;
    unsigned int bss_idx;
    unsigned int sta_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    log_lib_d("remove sta[%d]: %s", sta->dm_idx, sta->mac_str);

    if (sta->dm_removed) {
        return;
    }

    if (check_sta_dm_idx(sta) < 0) {
        log_lib_e("Invalid indexing for sta");
        return;
    }

    sta_idx   = sta->dm_idx;
    bss_idx   = sta->bss->dm_idx;
    radio_idx = sta->bss->radio->dm_idx;
    ale_idx   = sta->bss->radio->ale->dm_idx;

    snprintf(tname, sizeof(tname) - 1,
        "Device.WiFi.DataElements.Network.Device.%d.Radio.%d.BSS.%d.STA.%d",
        ale_idx, radio_idx + 1, bss_idx + 1, sta_idx + 1);

    log_lib_d("Delete row %s", tname);

    rc = rbusTable_unregisterRow(g_bus_handle, tname);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to delete row[%d], path %s for sta: %s",
            sta_idx, tname, sta->mac_str);
    }

    /* TODO: Does unregister row also clears leftover reply handles?
             I doubt it */

    free_sta_dm_idx(ale_idx, radio_idx, bss_idx, sta_idx);

    if (0) {
        /* This may be enabled to shift indexes, if the data model
           automatically keeps indexing consecutive. rbus does not
           support it, tr069 forbids it */
        update_sta_idxs(sta->bss, sta);
    }
}

static rbusError_t sta_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_bss_info_t *bss;
    map_sta_info_t *sta;
    char timestamp[MAX_TS_STR_LEN] = {0};
    uint32_t last_connect;
    map_sta_ext_bss_metrics_t *ebm;
    map_sta_link_metrics_t *lm;
    map_sta_traffic_stats_t *ts;
    char *beacon_str;
    char caps_str[MAX_CAPS_STR_LEN] = {0};

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_BSS_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    bss = dm_get_bss(radio, param, is_num);
    if (bss == NULL) {
        log_lib_e("Invalid bss %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_STA_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    sta = dm_get_sta(bss, param, is_num);
    if (sta == NULL) {
        log_lib_e("Invalid sta %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }
    ts = sta->traffic_stats;
    lm = sta->metrics ? first_object(sta->metrics) : NULL;

    sscanf(name, "%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "MACAddress") == 0) {
        rbusValue_SetString(value, sta->mac_str);
    } else if (strcmp(param, "TimeStamp") == 0) {
        get_timestamp_str(0, timestamp, sizeof(timestamp));
        rbusValue_SetString(value, timestamp);
    } else if (strcmp(param, "HTCapabilities") == 0) {
        if (sta->sta_caps.ht_support) {
            get_ht_caps_str(&sta->sta_caps.ht_caps, caps_str, sizeof(caps_str));
            rbusValue_SetString(value, caps_str);
        } else {
            rbusValue_SetString(value, "");
        }
    } else if (strcmp(param, "VHTCapabilities") == 0) {
        if (sta->sta_caps.vht_support) {
            get_vht_caps_str(&sta->sta_caps.vht_caps, caps_str, sizeof(caps_str));
            rbusValue_SetString(value, caps_str);
        } else {
            rbusValue_SetString(value, "");
        }
    } else if (strcmp(param, "HECapabilities") == 0) {
        if (sta->sta_caps.he_support) {
            get_he_caps_str(&sta->sta_caps.he_caps, caps_str, sizeof(caps_str));
            rbusValue_SetString(value, caps_str);
        } else {
            rbusValue_SetString(value, "");
        }
    } else if (strcmp(param, "ClientCapabilities") == 0) {
        uint32_t blen = 4 * ((sta->assoc_frame_len + 4) / 3) + 1;
        char *buf = calloc(blen, sizeof(char));
        if (b64_encode(sta->assoc_frame, sta->assoc_frame_len, buf, blen) < 0) {
            log_lib_e("b64_encode failed");
        }
        rbusValue_SetString(value, buf);
        free(buf);
    } else if (strcmp(param, "LastDataDownlinkRate") == 0) {
        if (get_last_sta_metrics(sta, &ebm) == 0 && ebm != NULL) {
            rbusValue_SetUInt32(value, ebm->last_data_dl_rate);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "LastDataUplinkRate") == 0) {
        if (get_last_sta_metrics(sta, &ebm) == 0 && ebm != NULL) {
            rbusValue_SetUInt32(value, ebm->last_data_ul_rate);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "UtilizationReceive") == 0) {
        if (get_last_sta_metrics(sta, &ebm) == 0 && ebm != NULL) {
            rbusValue_SetUInt32(value, ebm->utilization_rx);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "UtilizationTransmit") == 0) {
        if (get_last_sta_metrics(sta, &ebm) == 0 && ebm != NULL) {
            rbusValue_SetUInt32(value, ebm->utilization_tx);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "EstMACDataRateDownlink") == 0) {
        rbusValue_SetUInt32(value, lm ? lm->dl_mac_datarate : 0);
    } else if (strcmp(param, "EstMACDataRateUplink") == 0) {
        rbusValue_SetUInt32(value, lm ? lm->ul_mac_datarate : 0);
    } else if (strcmp(param, "SignalStrength") == 0) {
        rbusValue_SetUInt32(value, lm ? lm->rssi : 0);
    } else if (strcmp(param, "LastConnectTime") == 0) {
        last_connect = map_dm_get_sta_assoc_ts_delta(sta->assoc_ts);
        rbusValue_SetUInt32(value, last_connect);
    } else if (strcmp(param, "BytesReceived") == 0) {
        rbusValue_SetUInt64(value, ts ? ts->rxbytes : 0);
    } else if (strcmp(param, "BytesSent") == 0) {
        rbusValue_SetUInt64(value, ts ? ts->txbytes : 0);
    } else if (strcmp(param, "PacketsReceived") == 0) {
        rbusValue_SetUInt64(value, ts ? ts->rxpkts : 0);
    } else if (strcmp(param, "PacketsSent") == 0) {
        rbusValue_SetUInt64(value, ts ? ts->txpkts : 0);
    } else if (strcmp(param, "ErrorsReceived") == 0) {
        rbusValue_SetUInt64(value, ts ? ts->rxpkterrors : 0);
    } else if (strcmp(param, "ErrorsSent") == 0) {
        rbusValue_SetUInt64(value, ts ? ts->txpkterrors : 0);
    } else if (strcmp(param, "RetransCount") == 0) {
        rbusValue_SetUInt64(value, ts ? ts->retransmission_cnt : 0);
    } else if (strcmp(param, "MeasurementReport") == 0) {
        if (list_get_size(sta->beacon_metrics)) {
            beacon_str = get_beacon_metrics_str(sta->beacon_metrics);
            rbusValue_SetString(value, beacon_str);
            free(beacon_str);
        } else {
            rbusValue_SetString(value, "");
        }
    } else if (strcmp(param, "NumberOfMeasureReports") == 0) {
        rbusValue_SetUInt32(value, list_get_size(sta->beacon_metrics));
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..Network.Device.Radio.BSS.STA.X_AIRTIES_BeaconMetricsQuery()       #
########################################################################*/
static int bmquery_parse_chan_reports(rbusObject_t in, map_nb_bmquery_param_t *payload)
{
    rbusObject_t ocr;
    rbusObject_t ocri;
    rbusObject_t och;
    rbusObject_t ochi;
    map_op_class_t *ap_chan_rep;
    uint32_t ap_chan_rep_cnt;
    uint32_t class;
    uint32_t channel;
    rbusValueError_t rc;

    /* Input.APChannelReport */
    ocr = rbusObject_GetChildren(in);
    if (payload->channel != 255) {
        if (ocr) {
            log_lib_i("APChannelReport is ignored");
        }
        return 0;
    }
    if (!ocr) {
        log_lib_e("APChannelReport object is mandatory");
        return -1;
    }
    /* Input.APChannelReport.{i} */
    ocri = rbusObject_GetChildren(ocr);
    if (!ocri) {
        log_lib_e("APChannelReport instance is mandatory");
        return -1;
    }

    ap_chan_rep_cnt = 0;
    do {
        /* Input.APChannelReport.{i}.OperatingClass */
        rc = rbusObject_GetPropertyUInt32(ocri, "OperatingClass", &class);
        if (rc != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("OperatingClass is mandatory");
            return -1;
        }

        ++ap_chan_rep_cnt;
        ap_chan_rep = &payload->ap_chan_reports[ap_chan_rep_cnt - 1];
        ap_chan_rep->op_class = class;

        /* Input.APChannelReport.{i}.Channel */
        och = rbusObject_GetChildren(ocri);
        if (!och) {
            log_lib_e("Channel object is mandatory");
            return -1;
        }
        /* Input.APChannelReport.{i}.Channel.{i} */
        ochi = rbusObject_GetChildren(och);
        if (!och) {
            log_lib_e("Channel instance is mandatory");
            return -1;
        }

        do {
            /* Input.APChannelReport.{i}.Channel.{i}.Channel */
            rc = rbusObject_GetPropertyUInt32(ochi, "Channel", &channel);
            if (rc != RBUS_VALUE_ERROR_SUCCESS) {
                log_lib_e("Channel is mandatory");
                return -1;
            }
            map_cs_set(&ap_chan_rep->channels, channel);

            ochi = rbusObject_GetNext(ochi);
        } while (ochi);

        ocri = rbusObject_GetNext(ocri);
    } while (ocri) ;
    payload->ap_chan_reports_nr = ap_chan_rep_cnt;

    return 0;
}

static int bmquery_parse_elementid_list(rbusObject_t in, map_nb_bmquery_param_t *payload)
{
    const char *sval;
    char buf[4] = {0};
    uint8_t pos;
    int len;
    rbusValueError_t rc;

    rc = rbusObject_GetPropertyString(in, "ElementIDList", &sval, &len);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        return 0;
    }
    if (payload->reporting_detail != 2/*MAP_BEACON_REPORT_DETAIL_ALL*/) {
        log_lib_i("ElementIDList is ignored");
        return 0;
    }

    pos = 0;
    payload->element_ids_nr = 0;
    while (len) {
        if (*sval >= '0' && *sval <= '9') {
            if (pos >= 4) {
                /* Invalid input */
                memset(buf, 0, pos);
                pos = 0;
            }
            buf[pos++] = *sval;
        } else {
            if (pos) {
                payload->element_ids[payload->element_ids_nr++] = atoi(buf);
                if (payload->element_ids_nr == 255) {
                    return 0;
                }
                memset(buf, 0, pos);
            }
            pos = 0;
        }
        ++sval;
        --len;
    }
    if (pos) {
        payload->element_ids[payload->element_ids_nr++] = atoi(buf);
    }

    return 0;
}

static rbusError_t sta_bmquery_rbus(rbusHandle_t handle, char const* method, rbusObject_t in, rbusObject_t out, rbusMethodAsyncHandle_t async)
{
    (void) handle;
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_bss_info_t *bss;
    map_sta_info_t *sta;
    rbusMethodAsyncHandle_t prev;
    map_nb_bmquery_param_t payload = {0};
    rbusValueError_t rc;
    const char *sval;
    uint32_t uval;
    int len;

    rbusObject_SetName(out, "Output");

    method += sizeof(DM_DEVICE_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        goto bail;
    }

    method += sizeof(DM_RADIO_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        goto bail;
    }

    method += sizeof(DM_BSS_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    bss = dm_get_bss(radio, param, is_num);
    if (bss == NULL) {
        log_lib_e("Invalid bss %s: %s", is_num ? "index" : "alias", param);
        goto bail;
    }

    method += sizeof(DM_STA_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    sta = dm_get_sta(bss, param, is_num);
    if (sta == NULL) {
        log_lib_e("Invalid sta %s: %s", is_num ? "index" : "alias", param);
        goto bail;
    }
    maccpy(payload.sta_mac, sta->mac);

    get_sta_dm_bmquery_reply(sta, &prev);
    if (prev) {
        log_lib_e("BeaconMetricsQuery is not finished yet");
        rbus_add_prop_str(out, "Status", "Error_Not_Ready");
        return RBUS_ERROR_INVALID_METHOD;
    }

    rc = rbusObject_GetPropertyUInt32(in, "OperatingClass", &uval);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("OperatingClass is mandatory");
        goto bail;
    }
    if (uval > 255) {
        log_lib_e("Invalid OperatingClass: %d", uval);
        goto bail;
    }
    payload.op_class = uval;

    rc = rbusObject_GetPropertyUInt32(in, "Channel", &uval);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("Channel is mandatory");
        goto bail;
    }
    if (uval > 255) {
        log_lib_e("Invalid Channel: %d", uval);
        goto bail;
    }
    payload.channel = uval;

    rc = rbusObject_GetPropertyString(in, "SSID", &sval, &len);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("SSID is mandatory");
        goto bail;
    }
    len = len > (MAX_SSID_LEN - 1) ? (MAX_SSID_LEN - 1) : len;
    strncpy(payload.ssid, sval, len);

    /* Optional arguments */
    rc = rbusObject_GetPropertyString(in, "BSSID", &sval, &len);
    if (rc == RBUS_VALUE_ERROR_SUCCESS) {
        if (mac_from_string(sval, payload.bssid) < 0) {
            log_lib_e("Invalid BSSID: %s", sval);
            goto bail;
        }
    } else {
        mac_from_string("ff:ff:ff:ff:ff:ff", payload.bssid);
    }

    rc = rbusObject_GetPropertyUInt32(in, "ReportingDetail", &uval);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        payload.reporting_detail = 1/*MAP_BEACON_REPORT_DETAIL_REQUESTED*/;
    } else {
        if (uval > 2/*MAP_BEACON_REPORT_DETAIL_ALL*/) {
            log_lib_e("Invalid ReportingDetail: %d", uval);
            goto bail;
        }
        payload.reporting_detail = uval;
    }

    if (bmquery_parse_chan_reports(in, &payload)) {
        goto bail;
    }

    if (bmquery_parse_elementid_list(in, &payload)) {
        goto bail;
    }

    /* Everything is fine, clear previous reports */
    if (sta->beacon_metrics != NULL) {
        while (list_get_size(sta->beacon_metrics) > 0) {
            free(remove_last_object(sta->beacon_metrics));
        }
    }
    sta->bmquery_status = 0;

    if (map_dm_get_nbapi()->beacon_metrics_query != NULL) {
        map_dm_get_nbapi()->beacon_metrics_query(ale, &payload);

        set_sta_dm_bmquery_reply(sta, async);
    } else {
        log_lib_e("BeaconMetricsQuery is not implemented yet");
        rbus_add_prop_str(out, "Status", "Error_Not_Ready");
        return RBUS_ERROR_INVALID_METHOD;
    }

    return RBUS_ERROR_ASYNC_RESPONSE;

bail:
    rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
    return RBUS_ERROR_INVALID_INPUT;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.Radio.BSS.STA.ClientSteer() #
########################################################################*/
static rbusError_t sta_client_steer(rbusHandle_t handle, char const* method, rbusObject_t in, rbusObject_t out, rbusMethodAsyncHandle_t async)
{
    (void) handle;
    rbusError_t ret = RBUS_ERROR_BUS_ERROR;
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_bss_info_t *bss;
    map_sta_info_t *sta;
    map_nb_client_steer_params_t payload = {0};
    const char *targetBSS;
    const char *requestMode;
    rbusValueError_t rc;
    int len;
    bool BTMDisassociationImminent;
    bool BTMAbridged;
    bool LinkRemovalImminent;
    uint32_t steeringOpportunityWindow;
    uint32_t TargetBSSChannel;
    uint32_t BTMDisassociationTimer;
    uint32_t TargetBSSOperatingClass;
    uint32_t reasonCode;
    map_sta_steering_history_t *steering_history = NULL;

    rbusObject_SetName(out, "Output");

    method += sizeof(DM_DEVICE_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }

    method += sizeof(DM_RADIO_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }

    method += sizeof(DM_BSS_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    bss = dm_get_bss(radio, param, is_num);
    if (bss == NULL) {
        log_lib_e("Invalid bss %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }

    method += sizeof(DM_STA_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    sta = dm_get_sta(bss, param, is_num);
    if (sta == NULL) {
        log_lib_e("Invalid sta %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    maccpy(payload.target.sta_mac, sta->mac);
    maccpy(payload.bssid, bss->bssid);

    sscanf(method, "%s", param);
    rc = rbusObject_GetPropertyString(in, "TargetBSS", &targetBSS, &len);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("TargetBSS is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    mac_from_string(targetBSS, payload.target.bssid);

    rc = rbusObject_GetPropertyString(in, "RequestMode", &requestMode, &len);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("RequestMode is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    if (strcasecmp(requestMode, "Steering_Mandate") == 0) {
        payload.flags |= NB_STEERING_REQUEST_FLAG_MANDATE;
    }
    else if (strcasecmp(requestMode, "Steering_Opportunity") == 0){
        rc = rbusObject_GetPropertyUInt32(in, "SteeringOpportunityWindow", &steeringOpportunityWindow);
        if (rc != RBUS_VALUE_ERROR_SUCCESS) {
            log_lib_e("SteeringOpportunityWindow is mandatory");
            rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
            return RBUS_ERROR_INVALID_INPUT;
        }
        payload.opportunity_wnd = steeringOpportunityWindow;
    }
    else {
        log_lib_e("SteeringOpportunityWindow value is not valid");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }

    rc = rbusObject_GetPropertyBoolean(in, "BTMDisassociationImminent", &BTMDisassociationImminent);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("RequestMode is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    payload.flags |= BTMDisassociationImminent ? NB_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT : 0;

    rc = rbusObject_GetPropertyBoolean(in, "BTMAbridged", &BTMAbridged);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("BTMAbridged is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    payload.flags |= BTMAbridged ? NB_STEERING_REQUEST_FLAG_BTM_ABRIDGED : 0;

    rc = rbusObject_GetPropertyBoolean(in, "LinkRemovalImminent", &LinkRemovalImminent);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("LinkRemovalImminent is optional, skipping");
    }

    rc = rbusObject_GetPropertyUInt32(in, "BTMDisassociationTimer", &BTMDisassociationTimer);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("BTMDisassociationTimer is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    // Check BTMDisassociationTimer is in limits
    payload.disassociation_timer = BTMDisassociationTimer;

    rc = rbusObject_GetPropertyUInt32(in, "TargetBSSOperatingClass", &TargetBSSOperatingClass);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("TargetBSSOperatingClass is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    // Check TargetBSSOperatingClass is valid
    payload.target.op_class = TargetBSSOperatingClass;

    rc = rbusObject_GetPropertyUInt32(in, "TargetBSSChannel", &TargetBSSChannel);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("TargetBSSChannel is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    payload.target.channel = TargetBSSChannel;

    rc = rbusObject_GetPropertyUInt32(in, "ReasonCode", &reasonCode);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("ReasonCode is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    payload.target.reason = reasonCode;

    steering_history = (map_sta_steering_history_t *)calloc(1, sizeof(map_sta_steering_history_t));
    if (steering_history == NULL) {
        log_lib_e("Can't allocate memory for steering history");
        ret = RBUS_ERROR_OUT_OF_RESOURCES;
        goto bail;
    }

    insert_last_object(sta->steering_history, steering_history);
    sta->steering_history_size_delta++; // This is not nice here, should be created in datamodel code.

    if (map_dm_get_nbapi()->client_steer != NULL) {
        map_dm_get_nbapi()->client_steer(ale, &payload);

        if (ale->last_sta_steered) {
            log_lib_e("There is another active station being steered! Will override!");
        }
        ale->last_sta_steered = sta;

        steering_history->start_time = acu_get_epoch_nsec();
        maccpy(steering_history->ap_origin, bss->bssid);
        steering_history->steering_approach = MAP_STEERING_APPROACH_BTM_REQUEST;
        steering_history->trigger_event = MAP_STEERING_TRIGGER_EVENT_WIFI_LINK_QUALITY;

        sta->steering_stats.btm_attempts++;

        map_dm_rbus_client_steer_async_reply_set(sta, async);
    } else {
        log_lib_e("ClientSteer is not implemented yet");
        rbus_add_prop_str(out, "Status", "Error_Not_Ready");
        return RBUS_ERROR_INVALID_METHOD;
    }

    return RBUS_ERROR_ASYNC_RESPONSE;

bail:
    return ret;
}

/*#######################################################################
#   ..Network.Device.Radio.BSS.STA.MultiAPSTA.Disassociate()            #
########################################################################*/
static rbusError_t mapsta_disassociate(rbusHandle_t handle, char const* method, rbusObject_t in, rbusObject_t out, rbusMethodAsyncHandle_t async)
{
    (void) handle;
    (void) async;
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_bss_info_t *bss;
    map_sta_info_t *sta;
    map_nb_sta_disassociate_params_t payload = {0};
    rbusValueError_t rc;
    uint32_t disassociation_timer;
    uint32_t reason_code;
    bool silent;

    rbusObject_SetName(out, "Output");

    method += sizeof(DM_DEVICE_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }

    method += sizeof(DM_RADIO_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }

    method += sizeof(DM_BSS_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    bss = dm_get_bss(radio, param, is_num);
    if (bss == NULL) {
        log_lib_e("Invalid bss %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    maccpy(payload.bssid, bss->bssid);

    method += sizeof(DM_STA_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    sta = dm_get_sta(bss, param, is_num);
    if (sta == NULL) {
        log_lib_e("Invalid sta %s: %s", is_num ? "index" : "alias", param);
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    maccpy(payload.sta_mac, sta->mac);

    sscanf(method, "%s", param);

    rc = rbusObject_GetPropertyUInt32(in, "DisassociationTimer", &disassociation_timer);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("DisassociationTimer is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    payload.disassociation_timer = disassociation_timer; // todo diassociation timer is not actively used

    rc = rbusObject_GetPropertyUInt32(in, "ReasonCode", &reason_code);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("ReasonCode is mandatory");
        rbus_add_prop_str(out, "Status", "Error_Invalid_Input");
        return RBUS_ERROR_INVALID_INPUT;
    }
    payload.reason_code = reason_code;

    rc = rbusObject_GetPropertyBoolean(in, "Silent", &silent);
    if (rc != RBUS_VALUE_ERROR_SUCCESS) {
        log_lib_e("Silent is optional, skipping");
    }
    else
        payload.silent = silent; // todo: silent is not used

    /* Perform scan */
    if (map_dm_get_nbapi()->mapsta_disassociate != NULL) {
        map_dm_get_nbapi()->mapsta_disassociate(ale, &payload);
        rbus_add_prop_str(out, "Status", "Success");
        // todo: process async reply
    } else {
        log_lib_e("Disassociate is not implemented yet");
        rbus_add_prop_str(out, "Status", "Error_Not_Ready");
        return RBUS_ERROR_INVALID_METHOD;
    }

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..Network.Device.Radio.BSS.STA.MultiAPSTA.SteeringSummaryStats      #
########################################################################*/
static rbusError_t steering_sum_stats_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_bss_info_t *bss;
    map_sta_info_t *sta;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_BSS_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    bss = dm_get_bss(radio, param, is_num);
    if (bss == NULL) {
        log_lib_e("Invalid bss %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_STA_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    sta = dm_get_sta(bss, param, is_num);
    if (sta == NULL) {
        log_lib_e("Invalid sta %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    log_lib_e("Address sta %p", (void *)sta);

    sscanf(name, "MultiAPSTA.SteeringSummaryStats.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "NoCandidateAPFailures") == 0) {
        rbusValue_SetUInt64(value, sta->steering_stats.no_candidate_apfailures);
    } else if (strcmp(param, "BlacklistAttempts") == 0) {
        rbusValue_SetUInt64(value, sta->steering_stats.blacklist_attempts);
    } else if (strcmp(param, "BlacklistSuccesses") == 0) {
        rbusValue_SetUInt64(value, sta->steering_stats.blacklist_successes);
    } else if (strcmp(param, "BlacklistFailures") == 0) {
        rbusValue_SetUInt64(value, sta->steering_stats.blacklist_failures);
    } else if (strcmp(param, "BTMAttempts") == 0) {
        rbusValue_SetUInt64(value, sta->steering_stats.btm_attempts);
    } else if (strcmp(param, "BTMSuccesses") == 0) {
        rbusValue_SetUInt64(value, sta->steering_stats.btm_successes);
    } else if (strcmp(param, "BTMFailures") == 0) {
        rbusValue_SetUInt64(value, sta->steering_stats.btm_failures);
    } else if (strcmp(param, "BTMQueryResponses") == 0) {
        rbusValue_SetUInt64(value, sta->steering_stats.btm_query_responses);
    } else if (strcmp(param, "LastSteerTime") == 0) {
        rbusValue_SetUInt32(value, sta->steering_stats.last_steer_time);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..Network.Device.Radio.UnassociatedSTA                              #
########################################################################*/
static rbusError_t unassoc_sta_get_rbus(rbusHandle_t handle, rbusProperty_t property,
                                        rbusGetHandlerOptions_t *opts)
{
    (void)handle;
    (void)opts;
    rbusValue_t value;
    char const *name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = { 0 };
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_unassociated_sta_info_t *unassoc_sta;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof("UnassociatedSTA");
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    unassoc_sta = dm_get_unassoc_sta(radio, param, is_num);
    if (unassoc_sta == NULL) {
        log_lib_e("Invalid unassoc sta %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "MACAddress") == 0) {
        mac_addr_str mac_str;
        mac_to_string(unassoc_sta->mac_address, mac_str);
        rbusValue_SetString(value, mac_str);
    } else if (strcmp(param, "SignalStrength") == 0) {
        rbusValue_SetUInt32(value, unassoc_sta->signal_strength);
    } else if (strcmp(param, "TimeStamp") == 0) {
        rbusValue_SetString(value, unassoc_sta->timestamp);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#      ..STA.{i}.MultiAPSTA.SteeringHistory.{i}.                        #
########################################################################*/
static const char* map_dm_steering_history_trigger_event_str(map_steering_history_trigger_event_t te)
{
    switch (te) {
        case MAP_STEERING_TRIGGER_EVENT_UNKNOWN:
            return "Unknown";
        case MAP_STEERING_TRIGGER_EVENT_WIFI_CHANNEL_UTILIZATION:
            return "Wi-Fi Utilization";
        case MAP_STEERING_TRIGGER_EVENT_WIFI_LINK_QUALITY:
            return "Wi-Fi Link Quality";
        case MAP_STEERING_TRIGGER_EVENT_BACKHAUL_LINK_UTILIZATION:
            return "Backhaul Link Utilization";
        default:
            return NULL;
    }
}

static const char* map_dm_steering_history_approach_str(map_steering_approach_t a)
{
    switch (a) {
        case MAP_STEERING_APPROACH_BLACKLIST:
            return "Blacklist";
        case MAP_STEERING_APPROACH_BTM_REQUEST:
            return "BTM Request";
        case MAP_STEERING_APPROACH_ASYNC_BTM_QUERY:
            return "BTM Query";
        default:
            return NULL;
    }
}

static rbusError_t steering_history_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_radio_info_t *radio;
    map_bss_info_t *bss;
    map_sta_info_t *sta;
    uint32_t steering_history_index = 0;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_RADIO_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    radio = dm_get_radio(ale, param, is_num);
    if (radio == NULL) {
        log_lib_e("Invalid radio %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_BSS_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    bss = dm_get_bss(radio, param, is_num);
    if (bss == NULL) {
        log_lib_e("Invalid bss %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    name += sizeof(DM_STA_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    sta = dm_get_sta(bss, param, is_num);
    if (sta == NULL) {
        log_lib_e("Invalid sta %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "MultiAPSTA.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "SteeringHistoryNumberOfEntries") == 0)
    {
        rbusValue_SetUInt64(value, list_get_size(sta->steering_history));
    }
    else
    {
        map_sta_steering_history_t *steering_history = NULL;

        if (sscanf(name, "MultiAPSTA.SteeringHistory.%d.%s", &steering_history_index,param) != 2) {
            log_lib_e("Invalid path: %s, can't scan.", name);
            goto invalid_input;
        }

        steering_history = object_at_index(sta->steering_history, steering_history_index - 1);
        if (!steering_history) {
            log_lib_e("Invalid index for SteeringHistory : %u", steering_history_index);
            goto invalid_input;
        }

        if (strcmp(param, "Time") == 0) {
            char timestamp[MAX_TS_STR_LEN] = {0};

            get_timestamp_str(steering_history->start_time, timestamp, sizeof(timestamp));
            rbusValue_SetString(value, timestamp);
        }
        else if (strcmp(param, "APOrigin") == 0) {
            rbusValue_SetString(value, mac_string(steering_history->ap_origin));
        }
        else if (strcmp(param, "APDestination") == 0) {
            rbusValue_SetString(value,
                                maccmp(steering_history->ap_dest, g_zero_mac) ? mac_string(steering_history->ap_dest) : "");
        }
        else if (strcmp(param, "TriggerEvent") == 0) {
            rbusValue_SetString(value, map_dm_steering_history_trigger_event_str(steering_history->trigger_event));
        }
        else if (strcmp(param, "SteeringApproach") == 0) {
            rbusValue_SetString(value, map_dm_steering_history_approach_str(steering_history->steering_approach));
        }
        else if (strcmp(param, "SteeringDuration") == 0) {
            rbusValue_SetUInt64(value, steering_history->steering_duration);
        }
        else {
            log_lib_e("Invalid param: %s", param);
            goto invalid_input;
        }
    }
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;

invalid_input:
    rbusValue_Release(value);
    return RBUS_ERROR_INVALID_INPUT;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.X_AIRTIES_Ethernet          #
########################################################################*/
static rbusError_t ethernet_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "X_AIRTIES_Ethernet.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "InterfaceNumberOfEntries") == 0) {
        if (ale->emex.enabled) {
            rbusValue_SetUInt32(value, ale->emex.eth_iface_list.iface_nr);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.X_AIRTIES_Ethernet.Interface          #
########################################################################*/
static rbusError_t ethiface_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int iface_idx;
    map_ale_info_t *ale;
    map_emex_eth_iface_t *iface;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "X_AIRTIES_Ethernet.Interface.%d.%s", &iface_idx, param);

    iface = NULL;
    if (ale->emex.enabled) {
        if (!iface_idx || iface_idx > ale->emex.eth_iface_list.iface_nr) {
            log_lib_e("Invalid interface index: %d", iface_idx);
            return RBUS_ERROR_INVALID_INPUT;
        }
        iface = &ale->emex.eth_iface_list.ifaces[iface_idx - 1];
    }

    rbusValue_Init(&value);

    if (strcmp(param, "MACAddress") == 0) {
        if (iface) {
            rbusValue_SetString(value, mac_string(iface->mac));
        } else {
            rbusValue_SetString(value, "00:00:00:00:00:00");
        }
    } else if (strcmp(param, "DeviceNumberOfEntries") == 0) {
        if (iface) {
            rbusValue_SetUInt32(value, iface->i1905_neighbor_macs_nr +
                iface->non_i1905_neighbor_macs_nr);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.X_AIRTIES_Ethernet.Interface.Device   #
########################################################################*/
static rbusError_t ethdevice_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    unsigned int iface_idx;
    unsigned int dev_idx;
    unsigned int dev_count;
    map_ale_info_t *ale;
    map_emex_eth_iface_t *iface;
    mac_addr dev_mac = {0};

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "X_AIRTIES_Ethernet.Interface.%d.Device.%d.%s",
        &iface_idx, &dev_idx, param);

    iface = NULL;
    if (ale->emex.enabled) {
        if (!iface_idx || iface_idx > ale->emex.eth_iface_list.iface_nr) {
            log_lib_e("Invalid interface index: %d", iface_idx);
            return RBUS_ERROR_INVALID_INPUT;
        }
        iface = &ale->emex.eth_iface_list.ifaces[iface_idx - 1];
    }

    if (iface) {
        dev_count = iface->i1905_neighbor_macs_nr + iface->non_i1905_neighbor_macs_nr;
        if (!dev_idx || dev_idx > dev_count) {
            log_lib_e("Invalid device index: %d", dev_idx);
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (dev_idx > iface->i1905_neighbor_macs_nr) {
            dev_idx -= iface->i1905_neighbor_macs_nr;
            if (dev_idx > iface->non_i1905_neighbor_macs_nr) {
                log_lib_e("Invalid device index");
                return RBUS_ERROR_INVALID_INPUT;
            }
            maccpy(&dev_mac, &iface->non_i1905_neighbor_macs[dev_idx - 1]);
        } else {
            maccpy(&dev_mac, &iface->i1905_neighbor_macs[dev_idx - 1]);
        }
    }

    rbusValue_Init(&value);

    if (strcmp(param, "MACAddress") == 0) {
        rbusValue_SetString(value, mac_string(dev_mac));
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.Network.Device.X_AIRTIES_DeviceInfo        #
########################################################################*/
static rbusError_t devinfo_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_emex_t *emex;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }
    emex = &ale->emex;

    sscanf(name, "X_AIRTIES_DeviceInfo.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "Uptime") == 0) {
        if (emex->enabled) {
            rbusValue_SetUInt32(value, emex->device_metrics.uptime);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.X_AIRTIES_DeviceInfo.MemoryStatus     #
########################################################################*/
static rbusError_t memstat_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_emex_t *emex;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }
    emex = &ale->emex;

    sscanf(name, "X_AIRTIES_DeviceInfo.MemoryStatus.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "Total") == 0) {
        if (emex->enabled) {
            rbusValue_SetUInt32(value, emex->device_metrics.mem_total);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "Free") == 0) {
        if (emex->enabled) {
            rbusValue_SetUInt32(value, emex->device_metrics.mem_free);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "Cached") == 0) {
        if (emex->enabled) {
            rbusValue_SetUInt32(value, emex->device_metrics.mem_cached);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   ..DataElements.Network.Device.X_AIRTIES_DeviceInfo.ProcessStatus    #
########################################################################*/
static rbusError_t procstat_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    bool is_num;
    map_ale_info_t *ale;
    map_emex_t *emex;

    name += sizeof(DM_DEVICE_PREFIX);
    name = get_table_alias(name, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        return RBUS_ERROR_INVALID_INPUT;
    }
    emex = &ale->emex;

    sscanf(name, "X_AIRTIES_DeviceInfo.ProcessStatus.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "CPUUsage") == 0) {
        if (emex->enabled) {
            rbusValue_SetUInt32(value, emex->device_metrics.cpu_load);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else if (strcmp(param, "CPUTemperature") == 0) {
        if (emex->enabled) {
            rbusValue_SetUInt32(value, emex->device_metrics.cpu_temp);
        } else {
            rbusValue_SetUInt32(value, 0);
        }
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.AssociationEvent                           #
########################################################################*/
static rbusError_t assocevt_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};

    name += sizeof(DM_DATAELEM_PREFIX);

    sscanf(name, "AssociationEvent.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "AssociationEventDataNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, map_dm_get_events()->assoc_cnt);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.AssociationEvent.Associated!               #
########################################################################*/
static int event_pub_assoc(map_assoc_data_t *assoc)
{
    char timestamp[MAX_TS_STR_LEN] = {0};
    rbusValue_t value;
    rbusObject_t data;
    rbusEvent_t event = {0};
    rbusError_t rc;

    rbusObject_Init(&data, NULL);

    rbusValue_Init(&value);
    rbusValue_SetString(value, mac_string(assoc->mac));
    rbusObject_SetValue(data, "MACAddress", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, mac_string(assoc->bssid));
    rbusObject_SetValue(data, "BSSID", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, assoc->status_code);
    rbusObject_SetValue(data, "StatusCode", value);
    rbusValue_Release(value);

    get_timestamp_str(assoc->timestamp, timestamp, sizeof(timestamp));
    rbusValue_Init(&value);
    rbusValue_SetString(value, timestamp);
    rbusObject_SetValue(data, "TimeStamp", value);
    rbusValue_Release(value);

    event.name = "Device.WiFi.DataElements.AssociationEvent.Associated!";
    event.data = data;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(g_bus_handle, &event);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Association event publish failed");
    }

    rbusObject_Release(data);

    return 0;
}

/*#######################################################################
#   ..DataElements.AssociationEvent.AssociationEventData.               #
########################################################################*/
static map_assoc_data_t *dm_get_assoc(uint16_t dm_idx)
{
    map_assoc_data_t *assoc;

    list_for_each_entry(assoc, &map_dm_get_events()->assoc_list, list) {
        if (assoc->dm_idx == dm_idx) {
            return assoc;
        }
    }

    return NULL;
}

static void dm_rbus_create_assoc(map_assoc_data_t *assoc)
{
    uint16_t     dm_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    dm_idx = g_dm_evt_table.assoc_idx + 1;

    snprintf(tname, sizeof(tname) - 1, "Device.WiFi.DataElements."
        "AssociationEvent.AssociationEventData.");

    rc = rbusTable_registerRow(g_bus_handle, tname, dm_idx, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for assoc", dm_idx);
        return;
    }

    assoc->dm_idx = g_dm_evt_table.assoc_idx = dm_idx;

    if (g_dm_evt_table.assoc_sub_cnt) {
        event_pub_assoc(assoc);
    }
}

static void dm_rbus_remove_assoc(map_assoc_data_t *assoc)
{
    uint16_t     dm_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    dm_idx = assoc->dm_idx;

    snprintf(tname, sizeof(tname) - 1, "Device.WiFi.DataElements."
        "AssociationEvent.AssociationEventData.%d", dm_idx);

    rc = rbusTable_unregisterRow(g_bus_handle, tname);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to delete row[%d] for assoc", dm_idx);
    }
}

static rbusError_t assocdta_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    uint32_t data_idx;
    map_assoc_data_t *assoc;
    char timestamp[MAX_TS_STR_LEN] = {0};

    name += sizeof(DM_DATAELEM_PREFIX);
    sscanf(name, "AssociationEvent.AssociationEventData.%d.%s",
        &data_idx, param);

    assoc = dm_get_assoc(data_idx);
    if (assoc == NULL) {
        log_lib_e("Invalid failed connection data index: %d", data_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);

    if (strcmp(param, "MACAddress") == 0) {
        rbusValue_SetString(value, mac_string(assoc->mac));
    } else if (strcmp(param, "BSSID") == 0) {
        rbusValue_SetString(value, mac_string(assoc->bssid));
    } else if (strcmp(param, "StatusCode") == 0) {
        rbusValue_SetUInt32(value, assoc->status_code);
    } else if (strcmp(param, "TimeStamp") == 0) {
        get_timestamp_str(assoc->timestamp, timestamp, sizeof(timestamp));
        rbusValue_SetString(value, timestamp);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.DisassociationEvent                        #
########################################################################*/
static rbusError_t disassocevt_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};

    name += sizeof(DM_DATAELEM_PREFIX);

    sscanf(name, "DisassociationEvent.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "DisassociationEventDataNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, map_dm_get_events()->disassoc_cnt);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.DisassociationEvent.Disassociated!         #
########################################################################*/
static int event_pub_disassoc(map_disassoc_data_t *disassoc)
{
    char timestamp[MAX_TS_STR_LEN] = {0};
    rbusValue_t value;
    rbusObject_t data;
    rbusEvent_t event = {0};
    rbusError_t rc;

    rbusObject_Init(&data, NULL);

    rbusValue_Init(&value);
    rbusValue_SetString(value, mac_string(disassoc->mac));
    rbusObject_SetValue(data, "MACAddress", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, mac_string(disassoc->bssid));
    rbusObject_SetValue(data, "BSSID", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, disassoc->reason_code);
    rbusObject_SetValue(data, "ReasonCode", value);
    rbusValue_Release(value);

    get_timestamp_str(disassoc->timestamp, timestamp, sizeof(timestamp));
    rbusValue_Init(&value);
    rbusValue_SetString(value, timestamp);
    rbusObject_SetValue(data, "TimeStamp", value);
    rbusValue_Release(value);

    event.name = "Device.WiFi.DataElements.DisassociationEvent.Disassociated!";
    event.data = data;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(g_bus_handle, &event);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Disassociation event publish failed");
    }

    rbusObject_Release(data);

    return 0;
}

/*#######################################################################
#   ..DataElements.DisassociationEvent.DisassociationEventData          #
########################################################################*/
static map_disassoc_data_t *dm_get_disassoc(uint16_t dm_idx)
{
    map_disassoc_data_t *disassoc;

    list_for_each_entry(disassoc, &map_dm_get_events()->disassoc_list, list) {
        if (disassoc->dm_idx == dm_idx) {
            return disassoc;
        }
    }

    return NULL;
}

static void dm_rbus_create_disassoc(map_disassoc_data_t *disassoc)
{
    uint16_t     dm_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    dm_idx = g_dm_evt_table.disassoc_idx + 1;

    snprintf(tname, sizeof(tname) - 1, "Device.WiFi.DataElements."
        "DisassociationEvent.DisassociationEventData.");

    rc = rbusTable_registerRow(g_bus_handle, tname, dm_idx, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for disassoc", dm_idx);
        return;
    }

    disassoc->dm_idx = g_dm_evt_table.disassoc_idx = dm_idx;

    if (g_dm_evt_table.disassoc_sub_cnt) {
        event_pub_disassoc(disassoc);
    }
}

static void dm_rbus_remove_disassoc(map_disassoc_data_t *disassoc)
{
    uint16_t     dm_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    dm_idx = disassoc->dm_idx;

    snprintf(tname, sizeof(tname) - 1, "Device.WiFi.DataElements."
        "DisassociationEvent.DisassociationEventData.%d", dm_idx);

    rc = rbusTable_unregisterRow(g_bus_handle, tname);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to delete row[%d] for disassoc", dm_idx);
    }
}

static rbusError_t disassocdta_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    uint32_t data_idx;
    map_disassoc_data_t *disassoc;
    char timestamp[MAX_TS_STR_LEN] = {0};

    name += sizeof(DM_DATAELEM_PREFIX);
    sscanf(name, "DisassociationEvent.DisassociationEventData.%d.%s",
        &data_idx, param);

    disassoc = dm_get_disassoc(data_idx);
    if (disassoc == NULL) {
        log_lib_e("Invalid failed connection data index: %d", data_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);

    if (strcmp(param, "MACAddress") == 0) {
        rbusValue_SetString(value, mac_string(disassoc->mac));
    } else if (strcmp(param, "BSSID") == 0) {
        rbusValue_SetString(value, mac_string(disassoc->bssid));
    } else if (strcmp(param, "ReasonCode") == 0) {
        rbusValue_SetUInt32(value, disassoc->reason_code);
    } else if (strcmp(param, "TimeStamp") == 0) {
        get_timestamp_str(disassoc->timestamp, timestamp, sizeof(timestamp));
        rbusValue_SetString(value, timestamp);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.FailedConnectionEvent                      #
########################################################################*/
static rbusError_t failconnevt_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};

    name += sizeof(DM_DATAELEM_PREFIX);

    sscanf(name, "FailedConnectionEvent.%s", param);

    rbusValue_Init(&value);

    if (strcmp(param, "FailedConnectionEventDataNumberOfEntries") == 0) {
        rbusValue_SetUInt32(value, map_dm_get_events()->failconn_cnt);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

/*#######################################################################
#   Device.WiFi.DataElements.FailedConnectionEvent.FailedConnection!    #
########################################################################*/
static int event_pub_failconn(map_failconn_data_t *failconn)
{
    char timestamp[MAX_TS_STR_LEN] = {0};
    rbusValue_t value;
    rbusObject_t data;
    rbusEvent_t event = {0};
    rbusError_t rc;

    rbusObject_Init(&data, NULL);

    rbusValue_Init(&value);
    rbusValue_SetString(value, mac_string(failconn->mac));
    rbusObject_SetValue(data, "MACAddress", value);
    rbusValue_Release(value);

    if (failconn->bssid[0] != '\0') {
        rbusValue_Init(&value);
        rbusValue_SetString(value, mac_string(failconn->bssid));
        rbusObject_SetValue(data, "BSSID", value);
        rbusValue_Release(value);
    }

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, failconn->status_code);
    rbusObject_SetValue(data, "StatusCode", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, failconn->reason_code);
    rbusObject_SetValue(data, "ReasonCode", value);
    rbusValue_Release(value);

    get_timestamp_str(failconn->timestamp, timestamp, sizeof(timestamp));
    rbusValue_Init(&value);
    rbusValue_SetString(value, timestamp);
    rbusObject_SetValue(data, "TimeStamp", value);
    rbusValue_Release(value);

    event.name = "Device.WiFi.DataElements.FailedConnectionEvent.FailedConnection!";
    event.data = data;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(g_bus_handle, &event);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("FailedConnection event publish failed");
    }

    rbusObject_Release(data);

    return 0;
}

/*#######################################################################
#   ..DataElements.FailedConnectionEvent.FailedConnectionEventData      #
########################################################################*/
static map_failconn_data_t *dm_get_failconn(uint16_t dm_idx)
{
    map_failconn_data_t *failconn;

    list_for_each_entry(failconn, &map_dm_get_events()->failconn_list, list) {
        if (failconn->dm_idx == dm_idx) {
            return failconn;
        }
    }

    return NULL;
}

static void dm_rbus_create_failconn(map_failconn_data_t *failconn)
{
    uint16_t     dm_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    dm_idx = g_dm_evt_table.failconn_idx + 1;

    snprintf(tname, sizeof(tname) - 1, "Device.WiFi.DataElements."
        "FailedConnectionEvent.FailedConnectionEventData.");

    rc = rbusTable_registerRow(g_bus_handle, tname, dm_idx, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to create row[%d] for failconn", dm_idx);
        return;
    }

    failconn->dm_idx = g_dm_evt_table.failconn_idx = dm_idx;

    if (g_dm_evt_table.failconn_sub_cnt) {
        event_pub_failconn(failconn);
    }
}

static void dm_rbus_remove_failconn(map_failconn_data_t *failconn)
{
    uint16_t     dm_idx;
    char         tname[256] = {0};
    rbusError_t  rc;

    dm_idx = failconn->dm_idx;

    snprintf(tname, sizeof(tname) - 1, "Device.WiFi.DataElements."
        "FailedConnectionEvent.FailedConnectionEventData.%d", dm_idx);

    rc = rbusTable_unregisterRow(g_bus_handle, tname);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("Failed to delete row[%d] for failconn", dm_idx);
    }
}

static rbusError_t failconndta_get_rbus(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    rbusValue_t value;
    char const* name = rbusProperty_GetName(property);
    char param[MAX_PROP_PARAM_LEN] = {0};
    uint32_t data_idx;
    map_failconn_data_t *failconn;
    char timestamp[MAX_TS_STR_LEN] = {0};

    name += sizeof(DM_DATAELEM_PREFIX);
    sscanf(name, "FailedConnectionEvent.FailedConnectionEventData.%d.%s",
        &data_idx, param);

    failconn = dm_get_failconn(data_idx);
    if (failconn == NULL) {
        log_lib_e("Invalid failed connection data index: %d", data_idx);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);

    if (strcmp(param, "MACAddress") == 0) {
        rbusValue_SetString(value, mac_string(failconn->mac));
    } else if (strcmp(param, "BSSID") == 0) {
        rbusValue_SetString(value, mac_string(failconn->bssid));
    } else if (strcmp(param, "StatusCode") == 0) {
        rbusValue_SetUInt32(value, failconn->status_code);
    } else if (strcmp(param, "ReasonCode") == 0) {
        rbusValue_SetUInt32(value, failconn->reason_code);
    } else if (strcmp(param, "TimeStamp") == 0) {
        get_timestamp_str(failconn->timestamp, timestamp, sizeof(timestamp));
        rbusValue_SetString(value, timestamp);
    } else {
        log_lib_e("Invalid param: %s", param);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_subevent_rbus(rbusHandle_t handle, rbusEventSubAction_t action, const char* name, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    (void) handle;
    (void) filter;
    (void) interval;
    (void) autoPublish;

    name += sizeof(DM_DATAELEM_PREFIX);

    if (strcmp(name, "AssociationEvent.Associated!") == 0) {
        if (action == RBUS_EVENT_ACTION_SUBSCRIBE) {
            ++g_dm_evt_table.assoc_sub_cnt;
        } else {
            if (g_dm_evt_table.assoc_sub_cnt) {
                --g_dm_evt_table.assoc_sub_cnt;
            }
        }
    } else if (strcmp(name, "DisassociationEvent.Disassociated!") == 0) {
        if (action == RBUS_EVENT_ACTION_SUBSCRIBE) {
            ++g_dm_evt_table.disassoc_sub_cnt;
        } else {
            if (g_dm_evt_table.disassoc_sub_cnt) {
                --g_dm_evt_table.disassoc_sub_cnt;
            }
       }
    } else if (strcmp(name, "FailedConnectionEvent.FailedConnection!") == 0) {
        if (action == RBUS_EVENT_ACTION_SUBSCRIBE) {
            ++g_dm_evt_table.failconn_sub_cnt;
        } else {
            if (g_dm_evt_table.failconn_sub_cnt) {
                --g_dm_evt_table.failconn_sub_cnt;
            }
        }
    } else {
        log_lib_e("Invalid event: %s", name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    return RBUS_ERROR_SUCCESS;
}

static rbusMethodAsyncHandle_t get_device_unassoc_sta_link_metrics_query_reply(map_ale_info_t *ale)
{
    return g_dm_dev_table[ale->dm_idx].unassoc_sta_link_metrics_query_handle;
}

static void set_device_unassoc_sta_link_metrics_query_reply(map_ale_info_t *ale,
                                                            rbusMethodAsyncHandle_t async_handle)
{
    g_dm_dev_table[ale->dm_idx].unassoc_sta_link_metrics_query_handle = async_handle;
}

static rbusError_t unassoc_sta_link_metrics_query(rbusHandle_t handle, char const *method,
                                                  rbusObject_t in, rbusObject_t out_obj,
                                                  rbusMethodAsyncHandle_t async)
{
    char param[MAX_PROP_PARAM_LEN] = { 0 };
    bool is_num;
    map_ale_info_t *ale;
    map_nb_unassoc_sta_link_metrics_query_params_t payload = { 0 };
    rbusError_t rc = RBUS_ERROR_ASYNC_RESPONSE;
    rbusObject_t channel_rbus;
    rbusObject_t channel_list_rbus = NULL;
    uint32_t class;
    int child_len;

    (void)handle;

    rbusObject_SetName(out_obj, "Output");

    method += sizeof(DM_DEVICE_PREFIX);
    method = get_table_alias(method, param, MAX_PROP_PARAM_LEN, &is_num);
    ale = dm_get_ale(param, is_num);
    if (ale == NULL) {
        log_lib_e("Invalid device %s: %s", is_num ? "index" : "alias", param);
        rc = RBUS_ERROR_INVALID_INPUT;
        goto out;
    }

    if (get_device_unassoc_sta_link_metrics_query_reply(ale) != NULL) {
        log_lib_e("Ongoing unassoc sta query");
        rc = RBUS_ERROR_DESTINATION_NOT_REACHABLE;
        goto out;
    }

    sscanf(method, "%s", param);

    if (rbusObject_GetPropertyUInt32(in, "OpClass", &class) != RBUS_VALUE_ERROR_SUCCESS) {
        rc = RBUS_ERROR_INVALID_INPUT;
        goto out;
    }
    payload.op_class = class;

    channel_list_rbus = rbus_obj_get_child_obj(in, "Channel");
    if (!channel_list_rbus) {
        log_lib_e("Channel object not found");
        rc = RBUS_ERROR_INVALID_INPUT;
        goto out;
    }

    child_len = rbus_object_children_len(channel_list_rbus);
    if (child_len == 0) {
        log_lib_e("Channel list empty");
        rc = RBUS_ERROR_INVALID_INPUT;
        goto out;
    }

    payload.chan_list = calloc(child_len, sizeof(*payload.chan_list));
    if (!payload.chan_list) {
        rc = RBUS_ERROR_OUT_OF_RESOURCES;
        goto out;
    }

    for (channel_rbus = rbusObject_GetChildren(channel_list_rbus); channel_rbus != NULL;
         channel_rbus = rbusObject_GetNext(channel_rbus)) {
        uint32_t channel;
        const char *sta_mac;
        rbusObject_t sta_list_rbus = NULL;
        rbusObject_t sta_rbus = NULL;
        map_nb_unassoc_sta_query_chan_t *chan = &payload.chan_list[payload.chan_list_len];
        payload.chan_list_len++;

        if (rbusObject_GetPropertyUInt32(channel_rbus, "Channel", &channel) !=
            RBUS_VALUE_ERROR_SUCCESS) {
            rc = RBUS_ERROR_INVALID_INPUT;
            goto out;
        }
        chan->channel = channel;

        sta_list_rbus = rbus_obj_get_child_obj(channel_rbus, "STA");
        child_len = rbus_object_children_len(sta_list_rbus);
        if (child_len == 0) {
            log_lib_e("STA list empty");
            rc = RBUS_ERROR_INVALID_INPUT;
            goto out;
        }

        chan->mac_list = calloc(child_len, sizeof(*chan->mac_list));
        if (!chan->mac_list) {
            rc = RBUS_ERROR_OUT_OF_RESOURCES;
            goto out;
        }

        for (sta_rbus = rbusObject_GetChildren(sta_list_rbus); sta_rbus != NULL;
             sta_rbus = rbusObject_GetNext(sta_rbus)) {
            int ret;
            int len;
            if (rbusObject_GetPropertyString(sta_rbus, "MAC", &sta_mac, &len) !=
                RBUS_VALUE_ERROR_SUCCESS) {
                rc = RBUS_ERROR_INVALID_INPUT;
                goto out;
            }
            ret = mac_from_string(sta_mac, chan->mac_list[chan->mac_list_len]);
            if (ret != 0) {
                rc = RBUS_ERROR_INVALID_INPUT;
                goto out;
            }
            chan->mac_list_len++;
        }
    }

    if (map_dm_get_nbapi()->unassoc_sta_link_metrics_query != NULL) {
        int ret = map_dm_get_nbapi()->unassoc_sta_link_metrics_query(ale, &payload);
        if (ret != 0) {
            rc = RBUS_ERROR_INVALID_INPUT;
            goto out;
        }
    } else {
        rc = RBUS_ERROR_INVALID_METHOD;
        goto out;
    }

out:
    if (payload.chan_list) {
        size_t i;
        for (i = 0; i < payload.chan_list_len; i++) {
            if (payload.chan_list[i].mac_list) {
                free(payload.chan_list[i].mac_list);
            }
        }
        free(payload.chan_list);
    }

    if (rc == RBUS_ERROR_ASYNC_RESPONSE) {
        set_device_unassoc_sta_link_metrics_query_reply(ale, async);
    } else if (rc == RBUS_ERROR_INVALID_INPUT) {
        rbus_add_prop_str(out_obj, "Status", "Error_Invalid_Input");
    } else if (rc == RBUS_ERROR_DESTINATION_NOT_FOUND) {
        rbus_add_prop_str(out_obj, "Status", "Error_Not_Ready");
    } else {
        rbus_add_prop_str(out_obj, "Status", "Error_Other");
    }

    return rc;
}

/* Data type added function names */
#define network_get_string      network_get_rbus
#define network_get_ulong       network_get_rbus
#define ssid_get_string         ssid_get_rbus
#define ssid_get_boolean        ssid_get_rbus
#define ssid_get_int            ssid_get_rbus
#define device_get_string       device_get_rbus
#define device_get_ulong        device_get_rbus
#define radio_get_boolean       radio_get_rbus
#define radio_get_string        radio_get_rbus
#define radio_get_ulong         radio_get_rbus
#define caps_get_string         caps_get_rbus
#define caps_get_ulong          caps_get_rbus
#define capop_get_ulong         capop_get_rbus
#define capop_get_int           capop_get_rbus
#define capop_get_string        capop_get_rbus
#define bss_get_boolean         bss_get_rbus
#define bss_get_string          bss_get_rbus
#define bss_get_ulong           bss_get_rbus
#define sta_get_string          sta_get_rbus
#define sta_get_ulong           sta_get_rbus
#define scanres_get_string      scanres_get_rbus
#define scanres_get_ulong       scanres_get_rbus
#define opclscan_get_ulong      opclscan_get_rbus
#define chscan_get_int          chscan_get_rbus
#define chscan_get_string       chscan_get_rbus
#define chscan_get_ulong        chscan_get_rbus
#define nbss_get_int            nbss_get_rbus
#define nbss_get_string         nbss_get_rbus
#define nbss_get_ulong          nbss_get_rbus
#define currop_get_ulong        currop_get_rbus
#define currop_get_int          currop_get_rbus
#define currop_get_string       currop_get_rbus
#define bhsta_get_string        bhsta_get_rbus
#define backhaul_get_string     backhaul_get_rbus
#define bhstats_get_string      bhstats_get_rbus
#define bhstats_get_ulong       bhstats_get_rbus
#define cacstatus_get_string    cacstatus_get_rbus
#define cacstatus_get_ulong     cacstatus_get_rbus
#define cacavail_get_ulong      cacavail_get_rbus
#define cacnonocc_get_ulong     cacnonocc_get_rbus
#define cacactive_get_ulong     cacactive_get_rbus
#define ethernet_get_ulong      ethernet_get_rbus
#define ethiface_get_string     ethiface_get_rbus
#define ethiface_get_ulong      ethiface_get_rbus
#define ethdevice_get_string    ethdevice_get_rbus
#define devinfo_get_ulong       devinfo_get_rbus
#define memstat_get_ulong       memstat_get_rbus
#define procstat_get_ulong      procstat_get_rbus
#define assocevt_get_ulong      assocevt_get_rbus
#define assocdta_get_string     assocdta_get_rbus
#define assocdta_get_ulong      assocdta_get_rbus
#define disassocevt_get_ulong   disassocevt_get_rbus
#define disassocdta_get_string  disassocdta_get_rbus
#define disassocdta_get_ulong   disassocdta_get_rbus
#define failconnevt_get_ulong   failconnevt_get_rbus
#define failconndta_get_string  failconndta_get_rbus
#define failconndta_get_ulong   failconndta_get_rbus

static rbusError_t register_data_elements(rbusHandle_t handle)
{
    uint32_t cnt;
    rbusError_t rc;
    static rbusDataElement_t elements[] = {
        {DM_NETWORK_ID,             RBUS_ELEMENT_TYPE_PROPERTY, {network_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_NETWORK_TSTAMP,         RBUS_ELEMENT_TYPE_PROPERTY, {network_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_NETWORK_DEVNOE,         RBUS_ELEMENT_TYPE_PROPERTY, {network_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_NETWORK_SSIDNOE,        RBUS_ELEMENT_TYPE_PROPERTY, {network_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_NETWORK_SETSSID,        RBUS_ELEMENT_TYPE_METHOD,   {NULL, NULL, NULL, NULL, NULL, network_setssid_rbus}},
        {DM_SSID_TBL,               RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_SSID_SSID,              RBUS_ELEMENT_TYPE_PROPERTY, {ssid_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_SSID_ENABLED,           RBUS_ELEMENT_TYPE_PROPERTY, {ssid_get_boolean, NULL, NULL, NULL, NULL, NULL}},
        {DM_SSID_BAND,              RBUS_ELEMENT_TYPE_PROPERTY, {ssid_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_SSID_ADVENABLED,        RBUS_ELEMENT_TYPE_PROPERTY, {ssid_get_boolean, NULL, NULL, NULL, NULL, NULL}},
        {DM_SSID_PASSPHRASE,        RBUS_ELEMENT_TYPE_PROPERTY, {ssid_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_SSID_AKMSALLOWED,       RBUS_ELEMENT_TYPE_PROPERTY, {ssid_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_SSID_REFERENCE,         RBUS_ELEMENT_TYPE_PROPERTY, {ssid_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_SSID_DIRECTION,         RBUS_ELEMENT_TYPE_PROPERTY, {ssid_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_SSID_VID,               RBUS_ELEMENT_TYPE_PROPERTY, {ssid_get_int, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_TBL,             RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_ID,              RBUS_ELEMENT_TYPE_PROPERTY, {device_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_MANU,            RBUS_ELEMENT_TYPE_PROPERTY, {device_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_SERNO,           RBUS_ELEMENT_TYPE_PROPERTY, {device_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_MODEL,           RBUS_ELEMENT_TYPE_PROPERTY, {device_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_SWVER,           RBUS_ELEMENT_TYPE_PROPERTY, {device_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_EXECENV,         RBUS_ELEMENT_TYPE_PROPERTY, {device_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_CCODE,           RBUS_ELEMENT_TYPE_PROPERTY, {device_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_MAPPROFILE,      RBUS_ELEMENT_TYPE_PROPERTY, {device_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_RADIONOE,        RBUS_ELEMENT_TYPE_PROPERTY, {device_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_CACSTATUSNOE,    RBUS_ELEMENT_TYPE_PROPERTY, {device_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVICE_UNASSOC_STA_QUERY,RBUS_ELEMENT_TYPE_METHOD,  {NULL, NULL, NULL, NULL, NULL, unassoc_sta_link_metrics_query}},
        {DM_BACKHAUL_LINKTYPE,      RBUS_ELEMENT_TYPE_PROPERTY, {backhaul_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BACKHAUL_BHMACADDR,     RBUS_ELEMENT_TYPE_PROPERTY, {backhaul_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BACKHAUL_BHDEVICEID,    RBUS_ELEMENT_TYPE_PROPERTY, {backhaul_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BACKHAUL_MACADDRESS,    RBUS_ELEMENT_TYPE_PROPERTY, {backhaul_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_BYTESRCVD,      RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_BYTESSENT,      RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_PACKETSRCVD,    RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_PACKETSSENT,    RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_ERRORSRCVD,     RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_ERRORSSENT,     RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_SIGNALSTR,      RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_LASTDTADLR,     RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_LASTDTAULR,     RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BHSTATS_TSTAMP,         RBUS_ELEMENT_TYPE_PROPERTY, {bhstats_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACSTATUS_TBL,          RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACSTATUS_TSTAMP,       RBUS_ELEMENT_TYPE_PROPERTY, {cacstatus_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACSTATUS_AVAILNOE,     RBUS_ELEMENT_TYPE_PROPERTY, {cacstatus_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACSTATUS_NONOCCNOE,    RBUS_ELEMENT_TYPE_PROPERTY, {cacstatus_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACSTATUS_ACTIVENOE,    RBUS_ELEMENT_TYPE_PROPERTY, {cacstatus_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACAVAIL_TBL,           RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACAVAIL_OPCLASS,       RBUS_ELEMENT_TYPE_PROPERTY, {cacavail_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACAVAIL_CHANNEL,       RBUS_ELEMENT_TYPE_PROPERTY, {cacavail_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACAVAIL_MINUTES,       RBUS_ELEMENT_TYPE_PROPERTY, {cacavail_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACNONOCC_TBL,          RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACNONOCC_OPCLASS,      RBUS_ELEMENT_TYPE_PROPERTY, {cacnonocc_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACNONOCC_CHANNEL,      RBUS_ELEMENT_TYPE_PROPERTY, {cacnonocc_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACNONOCC_SECONDS,      RBUS_ELEMENT_TYPE_PROPERTY, {cacnonocc_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACACTIVE_TBL,          RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACACTIVE_OPCLASS,      RBUS_ELEMENT_TYPE_PROPERTY, {cacactive_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACACTIVE_CHANNEL,      RBUS_ELEMENT_TYPE_PROPERTY, {cacactive_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CACACTIVE_COUNTDOWN,    RBUS_ELEMENT_TYPE_PROPERTY, {cacactive_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_TBL,              RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_ID,               RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_ENABLED,          RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_boolean, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_NOISE,            RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_UTILIZATION,      RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_TRANSMIT,         RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_RCVSELF,          RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_RCVOTHER,         RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_TEMPERATURE,      RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_BSSNOE,           RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_CURROPCLASSNOE,   RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_SCANRESULTNOE,    RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_UNASSOC_NOE,      RBUS_ELEMENT_TYPE_PROPERTY, {radio_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_RADIO_CHSCANREQUEST,    RBUS_ELEMENT_TYPE_METHOD,   {NULL, NULL, NULL, NULL, NULL, radio_chscan_rbus}},
        {DM_MULTIAPRAD_CHSCAN,      RBUS_ELEMENT_TYPE_METHOD,   {NULL, NULL, NULL, NULL, NULL, radio_chscan_rbus}},
        {DM_MULTIAPRAD_FULLSCAN,    RBUS_ELEMENT_TYPE_METHOD,   {NULL, NULL, NULL, NULL, NULL, radio_chscan_rbus}},
        {DM_BACKHAULSTA_MACADDR,    RBUS_ELEMENT_TYPE_PROPERTY, {bhsta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_CAPS_HTCAPS,            RBUS_ELEMENT_TYPE_PROPERTY, {caps_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_CAPS_VHTCAPS,           RBUS_ELEMENT_TYPE_PROPERTY, {caps_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_CAPS_HECAPS,            RBUS_ELEMENT_TYPE_PROPERTY, {caps_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_CAPS_CAPOPCLASSNOE,     RBUS_ELEMENT_TYPE_PROPERTY, {caps_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CAPOPCLASS_TBL,         RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_CAPOPCLASS_CLASS,       RBUS_ELEMENT_TYPE_PROPERTY, {capop_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CAPOPCLASS_MAXTSPOW,    RBUS_ELEMENT_TYPE_PROPERTY, {capop_get_int, NULL, NULL, NULL, NULL, NULL}},
        {DM_CAPOPCLASS_NONOPER,     RBUS_ELEMENT_TYPE_PROPERTY, {capop_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_CAPOPCLASS_NONONOPER,   RBUS_ELEMENT_TYPE_PROPERTY, {capop_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CURROPCLASS_TBL,        RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_CURROPCLASS_CLASS,      RBUS_ELEMENT_TYPE_PROPERTY, {currop_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CURROPCLASS_CHANNEL,    RBUS_ELEMENT_TYPE_PROPERTY, {currop_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CURROPCLASS_TXPOWER,    RBUS_ELEMENT_TYPE_PROPERTY, {currop_get_int, NULL, NULL, NULL, NULL, NULL}},
        {DM_CURROPCLASS_TSTAMP,     RBUS_ELEMENT_TYPE_PROPERTY, {currop_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_SCANRES_TBL,            RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_SCANRES_TSTAMP,         RBUS_ELEMENT_TYPE_PROPERTY, {scanres_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_SCANRES_OPCLASSNOE,     RBUS_ELEMENT_TYPE_PROPERTY, {scanres_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_OPCLSCAN_TBL,           RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_OPCLSCAN_OPCLASS,       RBUS_ELEMENT_TYPE_PROPERTY, {opclscan_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_OPCLSCAN_CHANNELNOE,    RBUS_ELEMENT_TYPE_PROPERTY, {opclscan_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CHSCAN_TBL,             RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_CHSCAN_CHANNEL,         RBUS_ELEMENT_TYPE_PROPERTY, {chscan_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CHSCAN_TSTAMP,          RBUS_ELEMENT_TYPE_PROPERTY, {chscan_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_CHSCAN_UTILIZATION,     RBUS_ELEMENT_TYPE_PROPERTY, {chscan_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_CHSCAN_NOISE,           RBUS_ELEMENT_TYPE_PROPERTY, {chscan_get_int, NULL, NULL, NULL, NULL, NULL}},
        {DM_CHSCAN_NEIGHBSSNOE,     RBUS_ELEMENT_TYPE_PROPERTY, {chscan_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_NEIGHBSS_TBL,           RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_NEIGHBSS_BSSID,         RBUS_ELEMENT_TYPE_PROPERTY, {nbss_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_NEIGHBSS_SSID,          RBUS_ELEMENT_TYPE_PROPERTY, {nbss_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_NEIGHBSS_SIGNALSTR,     RBUS_ELEMENT_TYPE_PROPERTY, {nbss_get_int, NULL, NULL, NULL, NULL, NULL}},
        {DM_NEIGHBSS_CHANBW,        RBUS_ELEMENT_TYPE_PROPERTY, {nbss_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_NEIGHBSS_CHANUTIL,      RBUS_ELEMENT_TYPE_PROPERTY, {nbss_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_NEIGHBSS_STACOUNT,      RBUS_ELEMENT_TYPE_PROPERTY, {nbss_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_TBL,                RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_BSSID,              RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_SSID,               RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_ENABLED,            RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_boolean, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_LASTCHANGE,         RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_TSTAMP,             RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_UCASTBYTESRCVD,     RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_UCASTBYTESSENT,     RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_MCASTBYTESRCVD,     RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_MCASTBYTESSENT,     RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_BCASTBYTESRCVD,     RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_BCASTBYTESSENT,     RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_BACKHAULUSE,        RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_boolean, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_FRONTHAULUSE,       RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_boolean, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_FHAKMSALLOWED,      RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_BHAKMSALLOWED,      RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_STANOE,             RBUS_ELEMENT_TYPE_PROPERTY, {bss_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_BSS_CLIASSOCCTRL,       RBUS_ELEMENT_TYPE_METHOD,   {NULL, NULL, NULL, NULL, NULL, rbus_method_client_assoc_control}},
        {DM_STA_TBL,                RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_MACADDRESS,         RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_TSTAMP,             RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_HTCAPS,             RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_VHTCAPS,            RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_HECAPS,             RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_CLIENTCAPS,         RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_LASTDTADLINKR,      RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_LASTDTAULINKR,      RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_UTILIZATIONRX,      RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_UTILIZATIONTX,      RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_ESTMACDRDL,         RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_ESTMACDRUL,         RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_SIGNALSTRENGTH,     RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_LASTCONTIME,        RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_BYTESRCVD,          RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_BYTESSENT,          RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_PACKETSRCVD,        RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_PACKETSSENT,        RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_ERRORSRCVD,         RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_ERRORSSENT,         RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_RETRANSCNT,         RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_MEASUREREP,         RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_NOMEASUREREP,       RBUS_ELEMENT_TYPE_PROPERTY, {sta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_STA_BEACNMETRCSQUERY,   RBUS_ELEMENT_TYPE_METHOD,   {NULL, NULL, NULL, NULL, NULL, sta_bmquery_rbus}},
        {DM_STA_CLIENTSTEER,        RBUS_ELEMENT_TYPE_METHOD,   {NULL, NULL, NULL, NULL, NULL, sta_client_steer}},
        {DM_MULTIAPSTA_STEHISNOE,   RBUS_ELEMENT_TYPE_PROPERTY, {steering_history_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_MULTIAPSTA_DISASSOC,    RBUS_ELEMENT_TYPE_METHOD,   {NULL, NULL, NULL, NULL, NULL, mapsta_disassociate}},
        {DM_STEERHIST_TBL,          RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERHIST_TIME,         RBUS_ELEMENT_TYPE_PROPERTY, {steering_history_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERHIST_APORIGIN,     RBUS_ELEMENT_TYPE_PROPERTY, {steering_history_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERHIST_TRIGGEREVE,   RBUS_ELEMENT_TYPE_PROPERTY, {steering_history_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERHIST_STEERAPP,     RBUS_ELEMENT_TYPE_PROPERTY, {steering_history_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERHIST_APDEST,       RBUS_ELEMENT_TYPE_PROPERTY, {steering_history_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERHIST_STEERDUR,     RBUS_ELEMENT_TYPE_PROPERTY, {steering_history_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERSUM_NOCANDFAIL,    RBUS_ELEMENT_TYPE_PROPERTY, {steering_sum_stats_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERSUM_BLCKLSTATT,    RBUS_ELEMENT_TYPE_PROPERTY, {steering_sum_stats_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERSUM_BLCKLSTSUCC,   RBUS_ELEMENT_TYPE_PROPERTY, {steering_sum_stats_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERSUM_BLCKLSTFAIL,   RBUS_ELEMENT_TYPE_PROPERTY, {steering_sum_stats_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERSUM_BTMATTEMPT,    RBUS_ELEMENT_TYPE_PROPERTY, {steering_sum_stats_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERSUM_BTMSUCCESS,    RBUS_ELEMENT_TYPE_PROPERTY, {steering_sum_stats_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERSUM_BTMFAILURE,    RBUS_ELEMENT_TYPE_PROPERTY, {steering_sum_stats_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERSUM_BTMQUERYRSP,   RBUS_ELEMENT_TYPE_PROPERTY, {steering_sum_stats_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_STEERSUM_LASTSTEERTM,   RBUS_ELEMENT_TYPE_PROPERTY, {steering_sum_stats_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_UNASSOC_TBL,            RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_UNASSOC_MAC,            RBUS_ELEMENT_TYPE_PROPERTY, {unassoc_sta_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_UNASSOC_SIGNALSTRENGTH, RBUS_ELEMENT_TYPE_PROPERTY, {unassoc_sta_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_UNASSOC_TIMESTAMP,      RBUS_ELEMENT_TYPE_PROPERTY, {unassoc_sta_get_rbus, NULL, NULL, NULL, NULL, NULL}},
        {DM_ETHERNET_IFACENOE,      RBUS_ELEMENT_TYPE_PROPERTY, {ethernet_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_ETHIFACE_TBL,           RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_ETHIFACE_MACADDR,       RBUS_ELEMENT_TYPE_PROPERTY, {ethiface_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_ETHIFACE_DEVICENOE,     RBUS_ELEMENT_TYPE_PROPERTY, {ethiface_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_ETHDEVICE_TBL,          RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_ETHDEVICE_MACADDR,      RBUS_ELEMENT_TYPE_PROPERTY, {ethdevice_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DEVINFO_UPTIME,         RBUS_ELEMENT_TYPE_PROPERTY, {devinfo_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_MEMSTATUS_TOTAL,        RBUS_ELEMENT_TYPE_PROPERTY, {memstat_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_MEMSTATUS_FREE,         RBUS_ELEMENT_TYPE_PROPERTY, {memstat_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_MEMSTATUS_CACHED,       RBUS_ELEMENT_TYPE_PROPERTY, {memstat_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_PROCSTATUS_CPUUSAGE,    RBUS_ELEMENT_TYPE_PROPERTY, {procstat_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_PROCSTATUS_CPUTEMP,     RBUS_ELEMENT_TYPE_PROPERTY, {procstat_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_ASSOCEVT_DATANOE,       RBUS_ELEMENT_TYPE_PROPERTY, {assocevt_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_ASSOCEVT_ASSOCIATED,    RBUS_ELEMENT_TYPE_EVENT,    {NULL, NULL, NULL, NULL, de_subevent_rbus, NULL}},
        {DM_ASSOCDTA_TBL,           RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_ASSOCDTA_MACADDR,       RBUS_ELEMENT_TYPE_PROPERTY, {assocdta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_ASSOCDTA_BSSID,         RBUS_ELEMENT_TYPE_PROPERTY, {assocdta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_ASSOCDTA_STATUS,        RBUS_ELEMENT_TYPE_PROPERTY, {assocdta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_ASSOCDTA_TSTAMP,        RBUS_ELEMENT_TYPE_PROPERTY, {assocdta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DISASSEVT_DATANOE,      RBUS_ELEMENT_TYPE_PROPERTY, {disassocevt_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_DISASSEVT_DISASSOCED,   RBUS_ELEMENT_TYPE_EVENT,    {NULL, NULL, NULL, NULL, de_subevent_rbus, NULL}},
        {DM_DISASSDTA_TBL,          RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_DISASSDTA_MACADDR,      RBUS_ELEMENT_TYPE_PROPERTY, {disassocdta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DISASSDTA_BSSID,        RBUS_ELEMENT_TYPE_PROPERTY, {disassocdta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_DISASSDTA_REASON,       RBUS_ELEMENT_TYPE_PROPERTY, {disassocdta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_DISASSDTA_TSTAMP,       RBUS_ELEMENT_TYPE_PROPERTY, {disassocdta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_FAILCONNEVT_DATANOE,    RBUS_ELEMENT_TYPE_PROPERTY, {failconnevt_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_FAILCONNEVT_FAILCONN,   RBUS_ELEMENT_TYPE_EVENT,    {NULL, NULL, NULL, NULL, de_subevent_rbus, NULL}},
        {DM_FAILCONNDTA_TBL,        RBUS_ELEMENT_TYPE_TABLE,    {NULL, NULL, NULL, NULL, NULL, NULL}},
        {DM_FAILCONNDTA_MACADDR,    RBUS_ELEMENT_TYPE_PROPERTY, {failconndta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_FAILCONNDTA_BSSID,      RBUS_ELEMENT_TYPE_PROPERTY, {failconndta_get_string, NULL, NULL, NULL, NULL, NULL}},
        {DM_FAILCONNDTA_STATUS,     RBUS_ELEMENT_TYPE_PROPERTY, {failconndta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_FAILCONNDTA_REASON,     RBUS_ELEMENT_TYPE_PROPERTY, {failconndta_get_ulong, NULL, NULL, NULL, NULL, NULL}},
        {DM_FAILCONNDTA_TSTAMP,     RBUS_ELEMENT_TYPE_PROPERTY, {failconndta_get_string, NULL, NULL, NULL, NULL, NULL}}
    };

    cnt = sizeof(elements) / sizeof(rbusDataElement_t);
    rc = rbus_regDataElements(handle, cnt, elements);
    if (rc != RBUS_ERROR_SUCCESS) {
        log_lib_e("rbus_regDataElements failed");
    }

    return rc;
}

/*#######################################################################
#                       Init                                            #
########################################################################*/
static map_dm_cbs_t g_dm_cbs = {
    .ale_create_cb = dm_rbus_create_ale,
    .ale_update_cb = dm_rbus_update_ale,
    .ale_remove_cb = dm_rbus_remove_ale,

    .radio_create_cb = dm_rbus_create_radio,
    .radio_update_cb = dm_rbus_update_radio,
    .radio_remove_cb = dm_rbus_remove_radio,

    .bss_create_cb = dm_rbus_create_bss,
    .bss_update_cb = dm_rbus_update_bss,
    .bss_remove_cb = dm_rbus_remove_bss,

    .sta_create_cb = dm_rbus_create_sta,
    .sta_update_cb = dm_rbus_update_sta,
    .sta_remove_cb = dm_rbus_remove_sta,

    .assoc_create_cb = dm_rbus_create_assoc,
    .assoc_remove_cb = dm_rbus_remove_assoc,

    .disassoc_create_cb = dm_rbus_create_disassoc,
    .disassoc_remove_cb = dm_rbus_remove_disassoc,

    .failconn_create_cb = dm_rbus_create_failconn,
    .failconn_remove_cb = dm_rbus_remove_failconn
};

int map_dm_rbus_init(void)
{
    rbusError_t rc;
    rbusHandle_t handle;
    uint8_t* mac = map_cfg_get()->controller_cfg.local_agent_al_mac;

    remove_all_ap_device();

    rc = rbus_open(&handle, DM_RBUS_COMPONENT_ID);
    if (rc != RBUS_ERROR_SUCCESS) {
        return rc;
    }
    rc = register_data_elements(handle);
    if (rc != RBUS_ERROR_SUCCESS) {
        rbus_close(handle);
        return rc;
    }
    g_bus_handle = handle;

    /* Create local agent so it gets index 0 */
    if (maccmp(mac, g_zero_mac) && maccmp(mac, g_wildcard_mac)) {
        create_ale_mac(mac, NULL);
    }

    /* Register dm callbacks */
    map_dm_register_cbs(&g_dm_cbs);

    /* Create ssid rows */
    map_dm_create_ssids();

    return 0;
}

void map_dm_rbus_fini(void)
{
    /* Destroy ssid rows */
    map_dm_remove_ssids();

    map_dm_unregister_cbs(&g_dm_cbs);

    if (g_bus_handle) {
        rbus_close(g_bus_handle);
        g_bus_handle = NULL;
    }

    remove_all_ap_device(); /* Should only remove local agent */
}
