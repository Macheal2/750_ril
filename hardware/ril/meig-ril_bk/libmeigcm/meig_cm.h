/**
  ******************************************************************************
  * @file    meig_cm.h
  * @author  zhaopengfei@meigsmart.com
  * @brief   libmeigcm.so header file, export APIs for app communicate with modem by qmi protocol
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2021-20216 MeigSmart.
  * All rights reserved.
  *
  *
  ******************************************************************************
  */




#ifndef __MEIG_CM_H__
#define __MEIG_CM_H__



#define PDP_SUPPORT_MAX    (4)
#define MULTI_PDP_START_OFFSET      (10)

#define QMI_WDS_IPV6_ADDR_LEN 16
#define QMI_WDS_APN_NAME_MAX 150


typedef enum{
    NAS_NOT_REGISTERED = 0,
    NAS_REGISTERED,
    NAS_NOT_REGISTERED_SEARCHING,
    NAS_NOT_REGISTRATION_DENY,
    NAS_NOT_REGISTRATION_UNKNOWN,
}CM_NAS_REG_STATE;




typedef enum{
    NAS_CS_UNKNOWN = 0x0,
    NAS_CS_ATTACHED,
    NAS_CS_DETACHED,
}CM_CS_ATTACH_STATE;

typedef enum{
    NAS_PS_UNKNOWN = 0x0,
    NAS_PS_ATTACHED,
    NAS_PS_DETACHED,
}CM_PS_ATTACH_STATE;

typedef enum
{
  QMI_UIM_FCI_VALUE_NO_DATA                   = 0,
  QMI_UIM_FCI_VALUE_FCP                       = 1,
  QMI_UIM_FCI_VALUE_FCI                       = 2,
  QMI_UIM_FCI_VALUE_FCI_WITH_INTERFACES       = 3,
  QMI_UIM_FCI_VALUE_FMD                       = 4,
} qmi_uim_fci_value_type;

typedef struct {
    unsigned short    aid_len;
    unsigned char     *aid_buffer;
    unsigned char     context;
    unsigned short    auth_data_len;
    unsigned char     *auth_data;
} uim_authentication_data_type;

typedef enum {
    WDS_KEEP_ALIVE_TYPE_ENUM_MIN_ENUM_VAL = -2147483647, /**< To force a 32 bit signed enum.  Do not change or use*/
    WDS_KEEPALIVE_TYPE_NAT = 0, /**<  NAT  */
    WDS_KEEP_ALIVE_TYPE_ENUM_MAX_ENUM_VAL = 2147483647 /**< To force a 32 bit signed enum.  Do not change or use*/
} wds_keep_alive_type_enum_type;

typedef struct {

  /* Mandatory */
  /*  Keep Alive Type */
  wds_keep_alive_type_enum_type keep_alive_type;
  /**<  Values: \n
      - WDS_KEEPALIVE_TYPE_NAT (0) --  NAT  
 */

  /* Optional */
  /*  Keep Alive Timer */
  uint8_t timer_value_valid;  /**< Must be set to true if timer_value is being passed */
  uint32_t timer_value;
  /**<   Timer value in milliseconds to indicate the frequency of 
        the keep alive message that must be sent from the modem.*/

  /* Optional */
  /*  Destination IPv4 Address Type */
  uint8_t dest_ipv4_address_valid;  /**< Must be set to true if dest_ipv4_address is being passed */
  uint32_t dest_ipv4_address;
  /**<   IPv4 destination address information
        in little endian format.*/

  /* Optional */
  /*  Destination IPv6 Address Type */
  uint8_t dest_ipv6_address_valid;  /**< Must be set to true if dest_ipv6_address is being passed */
  uint8_t dest_ipv6_address[QMI_WDS_IPV6_ADDR_LEN];
  /**<   IPv6 destination address in network byte
       order; an 8-element array of 16-bit
       numbers, each of which is in big-endian
       format. */

  /* Optional */
  /*  Source IPv4 Address Type */
  uint8_t source_ipv4_address_valid;  /**< Must be set to true if source_ipv4_address is being passed */
  uint32_t source_ipv4_address;
  /**<   IPv4 source address information
        in little endian format.*/

  /* Optional */
  /*  Source IPv6 Address Type */
  uint8_t source_ipv6_address_valid;  /**< Must be set to true if source_ipv6_address is being passed */
  uint8_t source_ipv6_address[QMI_WDS_IPV6_ADDR_LEN];
  /**<   IPv6 source address in network byte
       order; an 8-element array of 16-bit
       numbers, each of which is in big-endian
       format. */

  /* Optional */
  /*  Destination Port */
  uint8_t dest_port_valid;  /**< Must be set to true if dest_port is being passed */
  uint16_t dest_port;
  /**<   Destination port information. */

  /* Optional */
  /*  Source Port */
  uint8_t source_port_valid;  /**< Must be set to true if source_port is being passed */
  uint16_t source_port;
  /**<   Source port information. */

  /* Optional */
  /*  APN Name */
  uint8_t apn_name_valid;  /**< Must be set to true if apn_name is being passed */
  char apn_name[QMI_WDS_APN_NAME_MAX + 1];
  /**<   APN name. */
}wds_modem_assisted_ka_start_req_msg_type;  /* Message */


typedef struct {
    int sw1;
    int sw2;
    char *simResponse;  /* In hex string format ([a-fA-F0-9]*), except for SIM_AUTHENTICATION
                           response for which it is in Base64 format, see 3GPP TS 31.102 7.1.2 */
} SIM_IO_rsp;

typedef enum {
    RUNNING = 0,
    NONE_STAT = 1,
    REQUESTED = 2,
} KeepaliveStatusCode;

typedef struct {
    uint32_t sessionHandle;
    KeepaliveStatusCode code;
}KeepaliveStatus;

#define UIM_P2_VALUE_FCI                 0x00
#define UIM_P2_VALUE_FCP                 0x04
#define UIM_P2_VALUE_FMD                 0x08
#define UIM_P2_VALUE_NO_DATA             0x0C


//WDS IP FAMILY
#define WDS_IP_FAMILY_IPV4        (0x4)
#define WDS_IP_FAMILY_IPV6        (0x6)
#define CM_VERSON_STRING_LEN_MAX    (28)

#define CM_UNRECOVERY_ERR_PROP    "sys.mgril.unrecverr"
#define MAX_PROFILE_STR_LEN    (128)
#define NDIS_MULTI_NUM_MAX    (4)



typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned char   UCHAR;
typedef unsigned int   ULONG;

typedef enum {
    CM_IPV4 = 0,
    CM_IPV6,
    CM_IPV4V6,
} CM_IP_PROT;

typedef enum {
    WDS_CONNECTION_STATUS_UNDEF = 0,
    WDS_CONNECTION_STATUS_DISCONNECTED = 1,
    WDS_CONNECTION_STATUS_CONNECTED = 2,
    WDS_CONNECTION_STATUS_SUSPEND = 3,
    WDS_CONNECTION_STATUS_AUTHENTICATING = 4,
} CM_CONN_STATE;

#define IpFamilyV4 (0x04)
#define IpFamilyV6 (0x06)


#pragma pack(push, 1)
typedef struct __IPV4 {
    uint32_t Address;
    uint32_t Gateway;
    uint32_t SubnetMask;
    uint32_t DnsPrimary;
    uint32_t DnsSecondary;
    uint32_t Mtu;
} IPV4_ADDR;

typedef struct __IPV6 {
    UCHAR Address[16];
    UCHAR Gateway[16];
    UCHAR SubnetMask[16];
    UCHAR DnsPrimary[16];
    UCHAR DnsSecondary[16];
    UCHAR PrefixLengthIPAddr;
    UCHAR PrefixLengthGateway;
    ULONG Mtu;
} IPV6_ADDR;
#pragma pack(pop)
/*zhangqingyun add esim 2023-7-21 start*/
typedef struct
{
  qmi_uim_fci_value_type  fci_value;
  unsigned char     data_len;
  unsigned char*    data_ptr;
} QMI_UIM_DATA_TYPE;


typedef struct
{
  int                channel_id;
  unsigned short     data_len;
  unsigned char*     data_ptr;
} QMI_UIM_APDU_TYPE;

typedef struct {
    int sw1;
    int sw2;
    char *simResponse;  /* In hex string format ([a-fA-F0-9]*), except for SIM_AUTHENTICATION
                           response for which it is in Base64 format, see 3GPP TS 31.102 7.1.2 */
} APDU_SIM_IO_Response;

/*zhangqingyun add esim 2023-7-21 end*/


//
typedef enum {
    CM_SIM_ABSENT = 0,
    CM_SIM_NOT_READY = 1,
    CM_SIM_READY = 2, /* CM_SIM_READY means the radio state is RADIO_STATE_CM_SIM_READY */
    CM_SIM_PIN = 3,
    CM_SIM_PUK = 4,
    CM_SIM_NETWORK_PERSONALIZATION = 5,
    SIM_BAD = 6,
} CMSIM_Status;
#if 0
/*zhangqingyun add for support body sar 2023-3-21 start*/
typedef enum{
   QMI_SAR_RF_STATE_DEFAULT = 0,
   QMI_SAR_RF_STATE_1       = 1, 
   QMI_SAR_RF_STATE_2       = 2,
   QMI_SAR_RF_STATE_3       = 3,
   QMI_SAR_RF_STATE_4       = 4,
   QMI_SAR_RF_STATE_5       = 5,
   QMI_SAR_RF_STATE_6       = 6,
   QMI_SAR_RF_STATE_7       = 7,
   QMI_SAR_RF_STATE_8       = 8,
 }CMSAR_Value;
/*zhangqingyun add for support body sar 2023-3-21 end*/
#endif 
const char* WDS_CONN_STATE_STR(CM_CONN_STATE state);
const char* PROT_TYPE2STR(CM_IP_PROT prot);


/**
* @brief CMInitInstance
* @retval Status
*/
// Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14
int CMInitInstance(const char* adapterName, int use_oldgobi);
/**
* @brief CMDeinitInstance
* @retval Status
*/
int CMDeinitInstance();

/**
* @brief CMVersion
* @retval version
*/
ULONG CMVersion(void);

/**
* @brief CMShowVersionString
*/
void CMShowVersionString();


/**
* @brief PROT_STR2TYPE
* @param const char* protStr
           This parameter can be one of the three values:
             "IPV4",
             "IPV4V6",
             "IPV6"
* @retval Status
*/

CM_IP_PROT PROT_STR2TYPE(const char* protStr);


/**
* @brief CMEnableQMIDebug
* @param int enable
           This parameter can be one of the two values:
             0 : disable qmi debug
             1 : enable qmi debug
* @retval Status
*/
void CMEnableQMIDebug(int enable);

/**
* @brief CMInitInstance
* @param CMSIM_Status pSIMStatus
           This parameter can be one of the 7 values:
             0 : CM_SIM_ABSENT = 0,
             1 : CM_SIM_NOT_READY = 1,
             2 : CM_SIM_READY = 2,
             3 : CM_SIM_PIN = 3,
             4 : CM_SIM_PUK = 4,
             5 : CM_SIM_NETWORK_PERSONALIZATION = 5,
             6 : SIM_BAD = 6,
* @retval Status
*/
int CMRequestGetSIMStatus(CMSIM_Status *pSIMStatus);

/**
* @brief CMRequestEnterSimPin
* @param const char* pPinCode
* @retval Status
*/
int CMRequestEnterSimPin(const char *pPinCode);

/**
* @brief CMRequestRegistrationState
* @param unsigned char *pPSAttachedState
           This parameter can be one of the these values:
             0 : detached
             1 : attached
* @retval Status
*/
int CMRequestRegistrationState(unsigned char *pPSAttachedState);

/**
* @brief CMRequestSetProfile
* @param int pdpIndex
         const char* apn
         const char* user
         const char* password
         int auth
             This parameter can be one of the these values:
             0 : None
             1 : Pap
             2 : Chap
             3 : MsChapV2
* @retval Status
*/
int CMRequestSetProfile(int pdpIndex, const char* apn, const char* user, const char* password, CM_IP_PROT ipProto,  int auth);

/**
* @brief CMRequestGetIPV4Address
* @param int pdpIndex
          IPV4_ADDR* addr
* @retval Status
*/
int CMRequestGetIPV4Address(int pdpIndex, IPV4_ADDR* addr);

/**
* @brief CMRequestGetIPV6Address
* @param int pdpIndex
          IPV6_ADDR* addr
* @retval Status
*/
int CMRequestGetIPV6Address(int pdpIndex, IPV6_ADDR* addr);

/**
* @brief CMRequestQueryDataCall
* @param int pdpIndex
         CM_CONN_STATE *pConnectionStatus
* @retval Status
*/
int CMRequestQueryDataCall(int pdpIndex, CM_CONN_STATE *pConnectionStatus);

/**
* @brief CMRequestSetupDataCall
* @param int pdpIndex
         CM_IP_PROT ip_protocol
             This parameter can be one of the these values:
             0 : CM_IPV4
             1 : CM_IPV6
             2 : CM_IPV4V6
* @retval Status
*/
int CMRequestSetupDataCall(int pdpIndex);

/**
* @brief CMRequestTurnDownDataCall
* @param int pdpIndex
         CM_IP_PROT ip_protocol
             This parameter can be one of the these values:
             0 : CM_IPV4
             1 : CM_IPV6
             2 : CM_IPV4V6
* @retval Status
*/
int CMRequestTurnDownDataCall(int pdpIndex);


/**
* @brief CMDhcpStart
* @param int pdpIndex
* @retval Status
*/
int CMDhcpStart(int pdpIndex);

/**
* @brief CMDhcpStop
* @param int pdpIndex
* @retval Status
*/
int CMDhcpStop(int pdpIndex);

/**
* @brief CMRegisterDataCallListChangeListener
* @param callback OnCMDataCallListChanged
* @retval Status
*/
int CMRegisterDataCallListChangeListener(void (*OnCMDataCallListChanged)(int pdpIndex, CM_IP_PROT ip_protocol, unsigned char call_state));

/**
* @brief CMRegisterRegisterStateChangedListener
* @param callback OnRegisterStateChanged
* @retval Status
*/
int CMRegisterRegisterStateChangedListener(void (*OnRegisterStateChanged)(CM_NAS_REG_STATE reg_state, CM_CS_ATTACH_STATE cs_state, CM_PS_ATTACH_STATE ps_state));

/**
* @brief CMRegisterRegisterHardwareChangedListener
* @param callback OnHardwareRemoved
* @retval Status
*/
int CMRegisterRegisterHardwareRemovedListener(void (*OnHardwareRemoved)());


/**
* @brief CMUnregisterDataCallListChangeListener
* @retval Status
*/
int CMUnregisterDataCallListChangeListener(void);

/**
* @brief CMUnregisterRegisterStateChangedListener
* @retval Status
*/
int CMUnregisterRegisterStateChangedListener(void);

/**
* @brief CMUnregisterHardwareRemovedListener
* @retval Status
*/
int CMUnregisterHardwareRemovedListener(void);

/*zhangqingyun add for support body sar 2023-3-21 start*/
/**
* @brief CMRequestGetBodySar
* @retval Status
*/
int CMRequestGetBodySar(int* sarValue);

/**
* @brief CMRequestSetBodySar
* @retval Status
*/
int CMRequestSetBodySar(int sarValue);
int CMRequestGetSimAtr(int slotid ,unsigned char* sim_atr,int* atr_eln);
int CMRequestGetSimEid(int slotid,unsigned char* sim_eid);

int CMRequestOpenChannel(int p2, unsigned char* buffer, unsigned short length,int* session_id,int * select_response_length);

int CMRequestCloseChannel(int session_id);


int CMRequestTransmitApduLogicChannel(int channel_id,unsigned char* apdu, unsigned short apdu_length,unsigned char* apdu_response,int* apdu_response_len);
/*zhangqingyun add for support body sar 2023-3-21 end*/
#ifdef MEIG_NEW_FEATURE
int CMRequestSimAuthentication(uim_authentication_data_type *auth_info, SIM_IO_rsp *rsp);
#endif
#ifdef START_KEEP_ALIVE
int CMRequestStartKeepAlive(wds_modem_assisted_ka_start_req_msg_type *ka_info, KeepaliveStatus *rsp);
#endif
/*zhangqingyun add for support getModemActivity 2023-12-5 start*/
int CMRequestGetModemActivityInfo();


#endif



