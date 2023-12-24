/*ril_common.h*/
#ifndef __RIL_COMMON_H__
#define __RIL_COMMON_H__ 1
#include <stdbool.h>
#include "libmeigcm/meig_cm.h"
#include "resetep.h"

#ifdef USE_TI_COMMANDS

// Enable a workaround
// 1) Make incoming call, do not answer
// 2) Hangup remote end
// Expected: call should disappear from CLCC line
// Actual: Call shows as "ACTIVE" before disappearing
#define WORKAROUND_ERRONEOUS_ANSWER 1

// Some varients of the TI stack do not support the +CGEV unsolicited
// response. However, they seem to send an unsolicited +CME ERROR: 150
#define WORKAROUND_FAKE_CGEV 1
#endif

/*[zhaopf@meigsmart-2020-0601] add for sdk version detect { */
//Android SDK version
#define ANDROID_2_2_SDK_VERSION           (8)
#define ANDROID_2_3_3_SDK_VERSION       (10)
#define ANDROID_4_0_SDK_VERSION           (14)
#define ANDROID_4_0_3_SDK_VERSION       (15)
#define ANDROID_4_1_SDK_VERSION           (16)
#define ANDROID_4_2_SDK_VERSION           (17)
#define ANDROID_4_3_SDK_VERSION           (18)
#define ANDROID_4_4_SDK_VERSION           (19)
#define ANDROID_4_4_W_SDK_VERSION      (20)
#define ANDROID_5_0_SDK_VERSION           (21)
#define ANDROID_5_1_SDK_VERSION           (22)
#define ANDROID_6_0_SDK_VERSION           (23)
 #define ANDROID_7_0_SDK_VERSION          (24)
 #define ANDROID_7_1_SDK_VERSION          (25)
 #define ANDROID_8_0_SDK_VERSION          (26)
 #define ANDROID_8_1_SDK_VERSION          (27)
 #define ANDROID_9_SDK_VERSION             (28)
 #define ANDROID_10_SDK_VERSION           (29)
 /*[zhaopf@meigsmart-2020-0601] add for sdk version detect } */

/*meig-zhaopengfei-2019-12-31 add for operator info { */
//operator information MCC & MNC

#define CHINA_MCC                        (460)



#define CHINA_MOBILE_MNC_00     (0)
#define CHINA_MOBILE_MNC_02     (2)
#define CHINA_MOBILE_MNC_07     (7)

#define CHINA_UNICOM_MNC_01     (1)
#define CHINA_UNICOM_MNC_06     (6)
#define CHINA_UNICOM_MNC_09     (9)

#define CHINA_TELECOM_MNC_03     (3)
#define CHINA_TELECOM_MNC_05     (5)
#define CHINA_TELECOM_MNC_11     (11)

#define CHINA_TIETONG_MNC_20     (20)

#ifndef RADIO_TECH_NR5G
#undef RADIO_TECH_NR5G
#define RADIO_TECH_NR5G 20
#endif

typedef enum {
    UNKNOWN_OPER = 0,
    CHINA_MOBILE_OPER,
    CHINA_UNICOM_OPER,
    CHINA_TELECOM_OPER,
    CHINA_TIETONG_OPER,

    //didn't use
    ODM_CM_OPERATOR,
    ODM_CT_OPERATOR_3G,
    ODM_CT_OPERATOR_4G,
    ODM_CU_OPERATOR

} CHINA_OPERATOR;
/*meig-zhaopengfei-2019-12-31 add for operator info } */

//<!--[ODM] mododr always set to 2
#define ODM_MODODR_2
//end-->

#ifdef RIL_SHLIB
struct RIL_Env *s_rilenv;
#define RIL_onRequestComplete(t, e, response, responselen) s_rilenv->OnRequestComplete(t,e, response, responselen)
#define RIL_onUnsolicitedResponse(a,b,c) s_rilenv->OnUnsolicitedResponse(a,b,c)
#define RIL_requestTimedCallback(a,b,c) s_rilenv->RequestTimedCallback(a,b,c)
#endif
void initializeCallback(void *param);

void initializeCallback_unlockPin(void *param);


#define MAX_S_CURRENT_PASSWORD_LEN  (128)
#define MAX_S_CURRENT_USERNAME_LEN  (128)
#define MAX_S_CURRENT_APN_LEN  (64)
#define MAX_S_CURRENT_PROTOCOL_LEN  (64)
extern char s_current_password[MAX_S_CURRENT_PASSWORD_LEN+1];
extern char s_current_username[MAX_S_CURRENT_USERNAME_LEN+1];
extern int s_current_authtype;
extern char s_current_protocol[MAX_S_CURRENT_PROTOCOL_LEN+1];
extern char s_current_apn[MAX_S_CURRENT_APN_LEN+1];
extern bool checkIfPSReady();
typedef enum {
    RIL_SIGNALSTRENGTH_UNKNOWN=0,
    RIL_SIGNALSTRENGTH_GW,
    RIL_SIGNALSTRENGTH_LTE,
    RIL_SIGNALSTRENGTH_CDMA,
    RIL_SIGNALSTRENGTH_EVOD,
    RIL_SIGNALSTRENGTH_TD_SCDMA
} RIL_SignalStrengthType;


typedef struct {
    int gwSignalStrength;
    int gwbitErrorRate;
    int cdma_dbm;
    int cdma_ecio;
    int evdo_dbm;
    int evdo_ecio;
    int evdo_signalNoiseRatio;
    int lte_signalStrength;
    int lte_rsrp;
    int lte_rsrq;
    int lte_rssnr;
} FG_EX_SignalStrength;


//PPP auth type
typedef enum {
    AUTH_NONE = 0,
    AUTH_PAP,
    AUTH_CHAP,
    AUTH_PAP_OR_CHAP
} AUTH_TYPE;

/* begin: added by dongmeirong for public network ip request 20201225 */
// define IPV4V6 address length in string.
#define STRLEN_IPV4_ADDRESS 16
#define STRLEN_IPV6_ADDRESS_DEC 64
#define STRLEN_IPV6_ADDRESS_HEX 40
#define ADDRESS_STRLEN(type) (type == ADDRESS_TYPE_V4 ? STRLEN_IPV4_ADDRESS : STRLEN_IPV6_ADDRESS_HEX)
#define ADDRESS_BUFF_SIZE(type) (ADDRESS_STRLEN(type) * sizeof(char) * ADDRESS_BUFF_ID_MAX)


#ifdef ntohl
#undef  ntohl
#undef  htonl
#undef  ntohs
#undef  htons

#define ntohl(x)    ( ((x) << 24) | (((x) >> 24) & 255) | (((x) << 8) & 0xff0000) | (((x) >> 8) & 0xff00) )
#define htonl(x)    ntohl(x)
#define ntohs(x)    ( (((x) << 8) & 0xff00) | (((x) >> 8) & 255) )
#define htons(x)    ntohs(x)
#endif

typedef enum {
    ADDRESS_TYPE_V4,
    ADDRESS_TYPE_V6
} ADDRESS_TYPE;

typedef enum {
    ADDRESS_BUFF_ID_IPADDRESS = 0,
    ADDRESS_BUFF_ID_GATEWAY,
    ADDRESS_BUFF_ID_PDNS,
    ADDRESS_BUFF_ID_SDNS,
    ADDRESS_BUFF_ID_MAX
} ADDRESS_BUFF_ID;
/* end: added by dongmeirong for public network ip request 20201225 */

/* begin: added by dongmeirong for SLM790 IP address adaption 20210113 */
typedef struct {
    ADDRESS_TYPE type;
    const char *cmdStr;
    const char *responsePrefix;
} DHCP_CMD;
/* end: added by dongmeirong for SLM790 IP address adaption 20210113 */
/* begin: modified by dongmeirong for add network change listenner to CGREG 20210508 */
typedef struct {
    const char *cmdPrefix;
    int stat;
} CXREG_CMD;
/* end: modified by dongmeirong for add network change listenner to CGREG 20210508 */

/*[zhaopf@meigsmart.com-2021/06/10]add for MULTINDIS support { */
typedef struct {
    const char *cmd;
    const char *infname;
}MULTINDIS_ARGS;

/*[zhaopf@meigsmart.com-2021/06/10]add for MULTINDIS support } */

#endif
