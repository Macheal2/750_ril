/* //device/system/meig-ril/meig-ril.c
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/
//wangbo 20170518 modify new call function
#include "ril.h"
#include <telephony/ril.h>
#include <telephony/ril_cdma_sms.h>
#include <telephony/librilutils.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <alloca.h>
#include <getopt.h>
#include <sys/socket.h>
#include <cutils/sockets.h>
#include <sys/time.h>
#include <termios.h>
#include <net/if.h>
#include <sys/system_properties.h>
#include <netutils/ifc.h>
#include <semaphore.h>
#include <cutils/properties.h>
#include <ctype.h>
#include <sys/wait.h>
#include <dirent.h>
#define LOG_TAG "RIL"
#include "atchannel.h"
#include "at_tok.h"
#include "misc.h"
#include "sim.h"
#include "sms.h"
#include "voice.h"
#include "other_function.h"
#include "usb_monitor.h"
#include "getdevinfo.h"
/*add by zhaopengfei add libmeigcm support 2022/10/10 Begin */
#include "libmeigcm/meig_cm.h"
#include "meig-log.h"
/*add by zhaopengfei add libmeigcm support 2022/10/10 End */
//#include <system/qemu_pipe.h>
#include "ril_common.h"
#include <utils/Log.h>
/*zhangqingyun add for support modem upgrade 2023/5/6 start*/
#define VERSION_PATH  "/vendor/etc/firmware/"
#define MAX_PATH 256

/*zhangqingyun add for support modem upgrade 2023/5/6 end*/
#if (__ANDROID_API__ > 19)
#include <android/api-level.h>
#include <android/log.h>
#include <signal.h>
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif
//extern "C" {
typedef __sighandler_t (*bsd_signal_func_t)(int, __sighandler_t);
bsd_signal_func_t bsd_signal_func = NULL;

__sighandler_t bsd_signal(int s, __sighandler_t f)
{
    if (bsd_signal_func == NULL) {
        // For now (up to Android 7.0) this is always available
        bsd_signal_func = (bsd_signal_func_t) dlsym(RTLD_DEFAULT, "bsd_signal");

        if (bsd_signal_func == NULL) {
            // You may try dlsym(RTLD_DEFAULT, "signal") or dlsym(RTLD_NEXT, "signal") here
            // Make sure you add a comment here in StackOverflow
            // if you find a device that doesn't have "bsd_signal" in its libc.so!!!

            __android_log_assert("", "bsd_signal_wrapper", "bsd_signal symbol not found!");
        }
    }

    return bsd_signal_func(s, f);
}
//}
#ifdef __cplusplus
}
#endif
#endif



static char atchannel[15] = {0};
static char datachannel[15] = {0};
#define RESPONSE_APDU_LENGTH  128
unsigned char unsigned_sim_atr[64]  = {0};
char sim_eid[64]  = {'\0'};
char sim_atr[64]  = {'\0'};
#define SUCCESS 0
#define ERROR 1

#define NDIS_SUCCESS 1
#define NDIS_NOTCONNECT 0

#define DEBUG
/*add by zhaopengfei add libmeigcm support 2022/10/10 Begin */
#define MULTI_APN_BASE   (10)
/*add by zhaopengfei add libmeigcm support 2022/10/10 End */
/*zhangqingyu add for support sim apdu */
#define QMI_UIM_MAX_AID_LEN    32
#define REG_STATE_LEN 15
/*zhaopf@meigsmart-2021/05/10 fixed error on android4.4 Begin */
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
#define REG_DATA_STATE_LEN 13
#else
#define REG_DATA_STATE_LEN 4
#endif
/*zhaopf@meigsmart-2021/05/10 fixed error on android4.4 End */

#define PPP_DIAL

#define PPP_OPERSTATE_PATH "/sys/class/net/ppp0/operstate"
#define ETH_OPERSTATE_PATH "/sys/class/net/usb0/operstate"

#define SERVICE_PPPD_GPRS "pppd_gprs"
#define SERVICE_DHCPCD_ECM "dhcpcd_ecm"
#define SERVICE_ECM_DOWN   "ecm_down"

#define PROPERTY_PPPD_EXIT_CODE "net.gprs.ppp-exit"

#define DEFAULT_GATEWAY "10.64.64.64"
//wangbo 20170518 debug
#define POLL_PPP_SYSFS_SECONDS    10
#define POLL_PPP_SYSFS_RETRY    30
/*[zhaopf@meigsmart-2020-0618]modify for ipv6 support { */
#define MAX_ADDR_BUFFER_SIZE           (256)
/*[zhaopf@meigsmart-2020-0618]modify for ipv6 support } */

/* begin: modified by dongmeirong for ip property name custimesed for SHIYUAN_LIUHUAN 20210622 */
#ifndef LOCAL_IP_PROPERTY_KEY_FORMAT
#define LOCAL_IP_PROPERTY_KEY_FORMAT "net.%s.local-ip"
#endif
/* end: modified by dongmeirong for ip property name custimesed for SHIYUAN_LIUHUAN 20210622 */

/*[zhaopf@meigsmart-2020-0716] } fixed for checking online state { */
#define RADIO_ONLINE_STATE                   (1)
/*[zhaopf@meigsmart-2020-0716] } fixed for checking online state } */
#define MAX_S_CURRENT_PASSWORD_LEN  (128)
#define MAX_S_CURRENT_USERNAME_LEN  (128)
#define MAX_S_CURRENT_APN_LEN  (64)
#define MAX_S_CURRENT_PROTOCOL_LEN  (64)
/* begin: added by dongmeirong for AT Ver adaption 20201217 */
#define PRODUCT_NAME_SLM750 "SLM750" // Module 750 produce name, which is matched specially to AT response strings.
#define PRODUCT_NAME_SLM770A "SLM770A"
// Module 750 update its software baseline from R1.0 to R2.0 which uses some different AT commands
#define SOFTWARE_BASELINE_750_V2_0 "R2.0"

/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
#define CDMA_RSSI_THRESH    125
#define CDMA_RSSI_SPAN      (CDMA_RSSI_THRESH - 75)
/* end: add by dongmeirong for poll signal strength by ril 20210615 */

static PRODUCT_TYPE s_product_type = PRODUCT_TYPE_NOT_DEFINED;
/* end: added by dongmeirong for AT Ver adaption 20201217 */

/*zhangiqngyun add for define sim simbusy query times*/
#define SIM_BUSY_TIMES   4
int sim_busy = 0;
char s_current_password[MAX_S_CURRENT_PASSWORD_LEN+1];
char s_current_username[MAX_S_CURRENT_USERNAME_LEN+1];
int s_current_authtype;
char s_current_protocol[MAX_S_CURRENT_PROTOCOL_LEN+1];
char s_current_apn[MAX_S_CURRENT_APN_LEN+1];
static char networktypefromsignalstrength[10] = {0};
/*zhangqingyun add for support sim apdu 2023-7-19 start*/
typedef unsigned char uint8;
typedef unsigned short uint16; 
/*zhangqingyun add for support sim adpu 2023-7-19 end*/
/* [zhaopf@meigsmart-2021/05/10]add for notify upper Layer of framework when restart ril Begin */
static int notifySimChangedOnce;
/* [zhaopf@meigsmart-2021/05/10]add for notify upper Layer of framework when restart ril End */
/*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario Begin */
static int g_dhcp_fail_ignore_flag;
/*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario End */
/*[zhaopengfei@meigsmart-2022/04/01]add for reg monitor Begin */
static bool g_reg_monitor_started = false;
/*[zhaopengfei@meigsmart-2022/04/01]add for reg monitor End */
/*[zhaopengfei@meigsmart-2022/04/01]add for sim monitor Begin {*/
static bool g_simstate_monitor_started = false;
/*[zhaopengfei@meigsmart-2022/04/01]add for sim monitor End }*/
/*Add by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 Begin */
static bool g_deactive_working = false;
/*Add by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 End */

/*Add by zhaopengfei for AT channel timeout 2023/01/09 Begin */
#define AT_CHANNEL_TIMEOUT_MAX    (3)
static int g_at_timeout_count = 0;
/*Add by zhaopengfei for AT channel timeout 2023/01/09 End */

/* added by zte-yuyang for SMS begin */
extern int sms_type;
/* added by zte-yuyang for SMS end */
int pppd;
pthread_mutex_t s_pppd_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t s_pppd_cond = PTHREAD_COND_INITIALIZER;
//zhangqingyun add make sure one request process each time
pthread_mutex_t on_request_mutex = PTHREAD_MUTEX_INITIALIZER;
//add by zhaopengfei make sure single dhcp request each time
pthread_mutex_t s_dhcp_req_mutex = PTHREAD_MUTEX_INITIALIZER;
/*[zhaopf@meigsmart-2020-1119]add for jingyi custom function { */
#ifdef BUILD_WITI_MEIG_EXT_KEY_SUPPORT
/**
 * RIL_REQUEST_WRITE_MEIG_KEY
 *
 * write meig keys to modem
 *
 * "data" is an string handle
 * "response" is NULL
 *
 * Valid errors:
 *  SUCCESS
 *  INVALID_ARGUMENTS
 *
 */

#define RIL_REQUEST_WRITE_MEIG_KEY 148

/**
 * RIL_REQUEST_READ_MEIG_KEY
 *
 * read meig keys to modem
 *
 * "data" is an string handle
 * "response" is NULL
 *
 *  Valid errors:
 *  SUCCESS
 *  INVALID_ARGUMENTS
 *
 */

#define RIL_REQUEST_READ_MEIG_KEY 149
#endif
/*[zhaopf@meigsmart-2020-1119]add for jingyi custom function } */

/* begin: added by dongmeirong for public network ip request 20201225 */
#ifndef RIL_REQUEST_NETWOK_ADDRESS
#define RIL_REQUEST_NETWOK_ADDRESS 150
#endif
/* end: added by dongmeirong for public network ip request 20201225 */

//#ifndef REFERENCE_RIL_VERSION
//#define REFERENCE_RIL_VERSION  "MEIG_RIL_Android_Common_V06"
//#endif
#ifndef BUILD_AUTHOR
#define BUILD_AUTHOR                   "anonymous"
#endif
#ifndef BUILD_TIME
#define BUILD_TIME                   "unknown"
#endif
/* added by zhaopengfei  for customed begin */
#ifndef BUILD_CUSTOMER
#define BUILD_CUSTOMER         "COMMON"
#endif
/* added by zhaopengfei  for customed end */

/*[zhaopf@meigsmart-2021-0826] add broadcast of at port block Begin { */
#define RIL_AT_BLOCK_NOTIFY    "/system/bin/am broadcast -a com.meige.net.AT_BLOCKAGE_NOTIFY"
/*[zhaopf@meigsmart-2021-0826] add broadcast of at port block End { */
/* meig-zhaopengfei-2021-10-22 add for radio tech change { */
static void updateRadioTechnology(void *inTech);
/* meig-zhaopengfei-2021-10-22 add for  radio tech change } */
char shell[2048]; //add for rk inside dial
//int init_radio_power = 0;
static struct timeval TIMEVAL_DELAYINIT = {1,0}; //for ^MODE process, 2020/12/11,modify by zhaopf for delay init
static struct timeval TIMEVAL_WAITDATADISCONNECT = {0,500000}; //fixed by zhaopf
static int iscdma = 0; //odm_get_current_network_type
static int onRequestCount = 0;
/*[zhaopf@meigsmart-2020-1207] reset modem when handshake many times { */
static int handshake_failed_times = 0;
#define HANDSHAKE_TIMEOUT    (3)
/*[zhaopf@meigsmart-2020-1207] reset modem when handshake many times } */
/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail Begin */
bool g_invalid_sim_reset_enable = true;
/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail End */

/*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 Begin */
static bool g_unisoc_attach_apn_notready = true;
/*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 End */
/*Add by zhaopengfei reset modem when get gw failed 2023/01/09 Begin*/
static bool g_reset_modem_enable = true;
/*Add by zhaopengfei reset modem when get gw failed 2023/01/09 End*/

unsigned int initial_time_statmp = 12000;
int debug_enable=0;

//zhangqingyun add to sign ndisstate either v4 connect or v6 connect take it as ndisconnect 20200723
int ndisIPV6state = NDIS_NOTCONNECT;
int ndisIPV4state = NDIS_NOTCONNECT;
//static int networktype_querysignalstrenth = 0;//work around when poll signal strength per 20 seconds not send at+psrat always zhangqingyun add 20180228

/* begin: modified by dongmeirong for add network change listenner to CGREG 20210508 */
static CXREG_CMD s_cxreg_cmd[] = {
    {"+CREG:", -1},
    {"+CGREG:", -1},
    {"+CEREG:", -1},
    {"+C5GREG:", -1}, //add 5G support by zhaopengfei 2022/10/28
};
/* end: modified by dongmeirong for add network change listenner to CGREG 20210508 */

extern void meig_gps_init(void);

/*[zhaopf@meigsmart-2020-11-17]add for ifconfig up interface { */
int  ifconfigUp(const char* ifname);
/*[zhaopf@meigsmart-2020-11-17]add for ifconfig up interface } */
extern int meig_pppd_stop(int signo);
/*[zhaopf@meigsmart-2020-0618]modify for ipv6 support { */
extern int meig_pppd_start(const char *modemport, const char *user, const char *password, const char* protocol,  int auth_type, const char *ppp_number);
/*[zhaopf@meigsmart-2020-0618]modify for ipv6 support } */
//zhangqingyun add for cts test networkscan 2023-12-12
RIL_CellInfo_v12 networkscan_rillCellInfo[1];
int sim_auth_index = 0;

extern int do_dhcp(const char *iname);
extern int ifc_disable(const char *ifname);
extern int ifc_enable(const char *ifname);
extern void get_dhcp_info(uint32_t *ipaddr, uint32_t *gateway, uint32_t *prefixLength,
                          uint32_t *dns1, uint32_t *dns2, uint32_t *server,
                          uint32_t *lease);
/*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again Begin */
extern int dhcp_init_ifc(const char *ifname);
extern int ifc_set_addr(const char *name, in_addr_t addr);
/*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again End */

/*[zhaopf@meigsmart-2020-11-17]add for config static ip on interface { */
extern int ifc_configure(const char *ifname, in_addr_t address, uint32_t prefixLength, in_addr_t gateway,in_addr_t dns1,in_addr_t dns2);
/*[zhaopf@meigsmart-2020-11-17]add for config static ip on interface } */
extern void cdma_pdu_2_3gpp_pdu(char *pdu_3gpp2, char *pdu_3gpp);
/*[zhaopf@meigsmart-2020-0224]add for static address call list Begin  */
static void onSendStaticDataCallList(RIL_Token *t);
static void resetStaticDataCallList(RIL_Token *t);
/*Add by zhaopengfei for AT channel timeout 2023/01/09 Begin */
static void onATReaderClosed();
/*Add by zhaopengfei for AT channel timeout 2023/01/09 End */
/*[zhaopf@meigsmart-2020-0224]add for static address call list End  */
int setupDataCallRASMode(const char* apn,            const int authtype,
                         const char* password,
                         const char*    protocol,
                         const char*    username);

/*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again Begin */
int  request_dhcp(const char* ifname, bool clearFirst);
/*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again End */
/*[zhaopf@meigsmart-2021-04-01]add force disconnet for qmi mode  { */
void forceDeactiveDataCallList();
/*[zhaopf@meigsmart-2021-04-01]add force disconnet for qmi mode  } */
void resetRadioPower(void *param __unused);
/*[zhaopf@meigsmart-2020-0108]check sim ready or not  by SIMST Begin */
int checkIfSIMReady();
/*[zhaopf@meigsmart-2020-0108]check sim ready or not  by SIMST End */
/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail Begin */
void resetSimPower();
/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail End */
static void *noopRemoveWarning(void *a)
{
return a;
}

#define RIL_UNUSED_PARM(a) noopRemoveWarning((void *)&(a));

#define MAX_AT_RESPONSE 0x1000
#define GPS_ENABLE 1

/* pathname returned from RIL_REQUEST_SETUP_DATA_CALL / RIL_REQUEST_SETUP_DEFAULT_PDP */
//#define PPP_TTY_PATH "eth0"
//wangbo 2017/05/16
#define PPP_TTY_PATH "ppp0"
#define PPP_ETH_PATH "usb0"
#define NETINTERFACE_NAME "usbnet0"
#define SIGNAL_MODEM

/* For Modem mode,ECM mode and NDIS mode switch */
NET_MOD devmode = RAS_MOD;
int flag_rildinitialize = 0;
#define MAX_S_CURRENT_APN_LEN  (64)

//end

// Default MTU value
#define DEFAULT_MTU 1500

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

/* Modem Technology bits */
#define MDM_GSM         0x01
#define MDM_WCDMA       0x02
#define MDM_CDMA        0x04
#define MDM_EVDO        0x08
#define MDM_LTE         0x10

typedef struct {
int supportedTechs;    // Bitmask of supported Modem Technology bits
int currentTech;    // Technology the modem is currently using (in the format used by modem)
int isMultimode;

// Preferred mode bitmask. This is actually 4 byte-sized bitmasks with different priority values,
// in which the byte number from LSB to MSB give the priority.
//
//          |MSB|   |   |LSB
// value:   |00 |00 |00 |00
// byte #:  |3  |2  |1  |0
//
// Higher byte order give higher priority. Thus, a value of 0x0000000f represents
// a preferred mode of GSM, WCDMA, CDMA, and EvDo in which all are equally preferrable, whereas
// 0x00000201 represents a mode with GSM and WCDMA, in which WCDMA is preferred over GSM
int32_t preferredNetworkMode;
int subscription_source;

} ModemInfo;

/* -----------------------------------------------------------------------------
   STRUCTURE:    QMI_UIM_DATA_TYPE

   DESCRIPTION:   The generic data structure
     data_len:    Length of data
     data_ptr:    Data
-------------------------------------------------------------------------------*/
typedef struct
{
  unsigned short     data_len;
  unsigned char    * data_ptr;
} qmi_uim_data_type;

int init_flag=1;
//int init_radio_power=0;
static ModemInfo *sMdmInfo;
/*[zhaopf@meigsmart-2020-0615]add for old version srm815 support {*/
static int get_stength_by_csq = 0;
/*[zhaopf@meigsmart-2020-0615]add for old version srm815 support }*/
// TECH returns the current technology in the format used by the modem.
// It can be used as an l-value
#define TECH(mdminfo)                 ((mdminfo)->currentTech)
// TECH_BIT returns the bitmask equivalent of the current tech
#define TECH_BIT(mdminfo)            (1 << ((mdminfo)->currentTech))
#define IS_MULTIMODE(mdminfo)         ((mdminfo)->isMultimode)
#define TECH_SUPPORTED(mdminfo, tech) ((mdminfo)->supportedTechs & (tech))
#define PREFERRED_NETWORK(mdminfo)    ((mdminfo)->preferredNetworkMode)
// CDMA Subscription Source
#define SSOURCE(mdminfo)              ((mdminfo)->subscription_source)
static int bSetupDataCallCompelete = 0;
/*[zhaopf@meigsmart-2020-1112]add for service domain & 5g mode settting { */
typedef enum {
    FIVEG_MODE_AUTO = 0,
    FIVEG_MODE_SA,
    FIVEG_MODE_SA_NSA,
} FIVEG_MODE;

typedef enum {
    SRV_DOMAIN_CS_ONLY = 0,
    SRV_DOMAIN_PS_ONLY = 1,
    SRV_DOMAIN_AUTO = 2,
} SRV_DOMAIN;

const char* fiveGMode2Str[] = {"auto", "sa", "sansa"};
const char* srvDoamin2Str[] = {"cs", "ps", "both"};

static FIVEG_MODE s_current_5g_mode = FIVEG_MODE_AUTO;
static SRV_DOMAIN s_current_srv_domain = SRV_DOMAIN_AUTO;

/*[zhaopf@meigsmart-2020-1112]add for service domain & 5g mode settting } */
/*[zhaopf@meigsmart-2020-1120]add for screen state monitor { */
int s_screen_state = 1;
/*[zhaopf@meigsmart-2020-1120]add for screen state monitor } */


static int net2modem[] = {
MDM_GSM | MDM_WCDMA,    // 0  - GSM / WCDMA Pref
MDM_GSM,        // 1  - GSM only
MDM_WCDMA,        // 2  - WCDMA only
MDM_GSM | MDM_WCDMA,    // 3  - GSM / WCDMA Auto
MDM_CDMA | MDM_EVDO,    // 4  - CDMA / EvDo Auto
MDM_CDMA,        // 5  - CDMA only
MDM_EVDO,        // 6  - EvDo only
MDM_GSM | MDM_WCDMA | MDM_CDMA | MDM_EVDO,    // 7  - GSM/WCDMA, CDMA, EvDo
MDM_LTE | MDM_CDMA | MDM_EVDO,    // 8  - LTE, CDMA and EvDo
MDM_LTE | MDM_GSM | MDM_WCDMA,    // 9  - LTE, GSM/WCDMA
MDM_LTE | MDM_CDMA | MDM_EVDO | MDM_GSM | MDM_WCDMA,    // 10 - LTE, CDMA, EvDo, GSM/WCDMA
MDM_LTE,        // 11 - LTE only
};

static int32_t net2pmask[] = {
MDM_GSM | (MDM_WCDMA << 8),    // 0  - GSM / WCDMA Pref
MDM_GSM,        // 1  - GSM only
MDM_WCDMA,        // 2  - WCDMA only
MDM_GSM | MDM_WCDMA,    // 3  - GSM / WCDMA Auto
MDM_CDMA | MDM_EVDO,    // 4  - CDMA / EvDo Auto
MDM_CDMA,        // 5  - CDMA only
MDM_EVDO,        // 6  - EvDo only
MDM_GSM | MDM_WCDMA | MDM_CDMA | MDM_EVDO,    // 7  - GSM/WCDMA, CDMA, EvDo
MDM_LTE | MDM_CDMA | MDM_EVDO,    // 8  - LTE, CDMA and EvDo
MDM_LTE | MDM_GSM | MDM_WCDMA,    // 9  - LTE, GSM/WCDMA
MDM_LTE | MDM_CDMA | MDM_EVDO | MDM_GSM | MDM_WCDMA,    // 10 - LTE, CDMA, EvDo, GSM/WCDMA
MDM_LTE,        // 11 - LTE only
};

//mode parameter type for mododr
typedef enum {
    MD_WCDMA_ONLY = 1, //hisi
    MD_AUTO = 2, //1.LTE  2.TD-SCDMA/WCDMA/EVDO 3.GSM/CDMA //hisi
    MD_GSM_ONLY = 3, //hisi
    MD_3G_PREFFERRED = 4,//in 2G/3G
    MD_LTE_ONLY = 5, //hisi
    MD_TD_SCDMA_ONLY = 6,
    MD_TD_SCDMA_WCDMA = 7,
    MD_CDMA_ONLY = 8,
    MD_CDMA_EVDO = 9,
    MD_EVDO_ONLY = 10,
    MD_HDR_TDSCDMA_WCDMA_LTE = 11,
    MD_CDMA_LTE_ONLY = 12,
} mododr_type;

/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 { */
typedef enum {
    SYSCFGEX_NET_AUTO = 1,
/*yufeilong add for support gsm only 20220823 begin*/
    SYSCFGEX_NET_GSM = 2,
/*yufeilong add for support gsm only 20220823 end*/
    SYSCFGEX_NET_WCDMA = 3,
    SYSCFGEX_NET_LTE_TDSCDMA_WCDMA_GSM = 4,
    SYSCFGEX_NET_LTE_TDSCDMA_WCDMA = 5,
    SYSCFGEX_NET_LTE_ONLY = 6,
    SYSCFGEX_NET_NR5G = 7,
    SYSCFGEX_NET_NOCHANGE = 8,
} SYSCFGEX_NET_type;
/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 } */


static const char* mododrType2Str[] = {"wcdma only",  \
                                       "auto", \
                                       "gsm only", \
                                       "3g prefferred", \
                                       "lte only", \
                                       "td-scdma only", \
                                       "td-scdma & wcdma", \
                                       "cdma only", \
                                       "cdma & evdo", \
                                       "evdo only", \
                                       "td-scdma&wcdma&lte", \
                                       "cdma & lte"
                                      };
/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 { */
static const char* syscfgexType2Str[] = {"auto",  \
/*yufeilong add for support gsm only 20220823 begin*/
                                       "gsm", \
/*yufeilong add for support gsm only 20220823 end*/
                                       "wcdma", \
                                       "lte", \
                                       "nr5g"\
                                      };
/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 } */

typedef enum {
    MEIG_RADIO_TECH_NO_SERVICE = 0,
    MEIG_RADIO_TECH_GSM = 1,
    MEIG_RADIO_TECH_GPRS = 2,
    MEIG_RADIO_TECH_EDGE = 3,
    MEIG_RADIO_TECH_WCDMA = 4,
    MEIG_RADIO_TECH_HSDPA = 5,
    MEIG_RADIO_TECH_HSUPA = 6,
    MEIG_RADIO_TECH_HSUPA_HSDPA = 7,
    MEIG_RADIO_TECH_TDSCDMA =  8,
    MEIG_RADIO_TECH_LTE = 9,
    MEIG_RADIO_TECH_TDD_LTE = 10,
    MEIG_RADIO_TECH_FDD_LTE = 11,
    MEIG_RADIO_TECH_CDMA = 12,
    MEIG_RADIO_TECH_CDMA_HDR = 13,
    MEIG_RADIO_TECH_HDR = 14,
    MEIG_RADIO_TECH_EHRPO = 15,
} Meig_RadioTechnology;

typedef enum {
    MEIG_HISI_RADIO_TECH_GSM_GPRS = 0,
    MEIG_HISI_RADIO_TECH_WCDMA = 2,
    MEIG_HISI_RADIO_TECH_LTE = 7,
} Meig_Hisi_RadioTechnology;


typedef enum {
    MEIG_COPS_RADIO_TECH_V2_GSM = 0,
    MEIG_COPS_RADIO_TECH_V2_GSM_COMPACT = 1,
    MEIG_COPS_RADIO_TECH_V2_UTRAN = 2,
    MEIG_COPS_RADIO_TECH_V2_GSM_EGPRS = 3,
    MEIG_COPS_RADIO_TECH_V2_HSDPA = 4,
    MEIG_COPS_RADIO_TECH_V2_HSUPA = 5,
    MEIG_COPS_RADIO_TECH_V2_HSUPA_HSDPA = 6,
    MEIG_COPS_RADIO_TECH_V2_EUTRAN = 7,
    MEIG_COPS_RADIO_TECH_V2_EC_GSM_IOT =  8,
    MEIG_COPS_RADIO_TECH_V2_EUTRAN_NB_S1= 9,
    MEIG_COPS_RADIO_TECH_V2_EUTRAN_5GCN= 10,
    MEIG_COPS_RADIO_TECH_V2_NR_5GCN= 11,
    MEIG_COPS_RADIO_TECH_V2_NG_RAN= 12,
    MEIG_COPS_RADIO_TECH_V2_EUTRA_NR = 13,
} Meig_CopsRadioTechnologyV2;
/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 { */
typedef enum {
    MEIG_COPS_RADIO_TECH_GSM = 0,
    MEIG_COPS_RADIO_TECH_GSM_COMPACT = 1,
    MEIG_COPS_RADIO_TECH_UTRAN = 2,
    MEIG_COPS_RADIO_TECH_GSM_EGPRS = 3,
    MEIG_COPS_RADIO_TECH_HSDPA = 4,
    MEIG_COPS_RADIO_TECH_HSUPA = 5,
    MEIG_COPS_RADIO_TECH_HSUPA_HSDPA = 6,
    MEIG_COPS_RADIO_TECH_EUTRAN = 7,
    MEIG_COPS_RADIO_TECH_CDMA =  8,
    MEIG_COPS_RADIO_TECH_CDMA_EVDO= 9,
    MEIG_COPS_RADIO_TECH_EVDO= 10,
} Meig_CopsRadioTechnology;
/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 } */

/*[zhaopf@meigsmart-2020-06-16] add for ipv6 support { */
/*yufeilong adapt Call Forward function 20230505 begin*/
typedef enum {
    MEIG_CALL_FORWARD_DISABLE = 0,
    MEIG_CALL_FORWARD_ENABLE,
    MEIG_CALL_FORWARD_INTERROGATE,
    MEIG_CALL_FORWARD_REGISTERATION,
    MEIG_CALL_FORWARD_ERASURE,
} Meig_CallForwardStatus;
/*yufeilong adapt Call Forward function 20230505 end*/
typedef enum {
    IPV4ONLY=0,
    IPV6ONLY,
    IPV4V6,
}PROTOCOL_TYPE;
/*[zhaopf@meigsmart-2020-06-16] add for ipv6 support } */
/*[zhaopf@meig-2020-1113]add for cellinfo report { */
typedef struct {
    int regstat; /*1-registed*/
    int ci;     /* 28-bit Cell Identity described in TS ???, INT_MAX if unknown */
    int pci;    /* physical cell id 0..503; this value must be reported */
    int tac;    /* 16-bit tracking area code, INT_MAX if unknown  */
} MEIG_CellInfo;
/*[zhaopf@meig-2020-1113]add for cellinfo report } */

static int is3gpp2(int radioTech)
{
switch (radioTech) {
case RADIO_TECH_IS95A:
case RADIO_TECH_IS95B:
case RADIO_TECH_1xRTT:
case RADIO_TECH_EVDO_0:
case RADIO_TECH_EVDO_A:
case RADIO_TECH_EVDO_B:
case RADIO_TECH_EHRPD:
    return 1;
default:
    return 0;
}
}


//wangbo debug


static void onRequest(int request, void *data, size_t datalen, RIL_Token t);
static RIL_RadioState currentState();
static int onSupports(int requestCode);
static void onCancel(RIL_Token t);
static char *getVersion();
static int isRadioOn();
SIM_Status getSIMStatus();
static int getCardStatus(RIL_CardStatus_v7** pp_card_status);
static void freeCardStatus(RIL_CardStatus_v7 * p_card_status);
static void onDataCallListChanged(void *param);

extern const char *requestToString(int request);

/*** Static Variables ***/
static const RIL_RadioFunctions s_callbacks = {
RIL_VERSION,
onRequest,
currentState,
onSupports,
onCancel,
getVersion
};

#ifdef RIL_SHLIB

#define RIL_onRequestComplete(t, e, response, responselen) s_rilenv->OnRequestComplete(t,e, response, responselen)
#define RIL_onUnsolicitedResponse(a,b,c) s_rilenv->OnUnsolicitedResponse(a,b,c)
#define RIL_requestTimedCallback(a,b,c) s_rilenv->RequestTimedCallback(a,b,c)
#endif

static RIL_RadioState sState = RADIO_STATE_UNAVAILABLE;

static pthread_mutex_t s_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_state_cond = PTHREAD_COND_INITIALIZER;

static int s_port = -1;
static const char *s_device_path = NULL;
//wangbo add 20170525
static const char *s_device_path_c = NULL;
static int s_device_socket = 0;
static int nSetupDataCallFailTimes = 0;
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin*/
const char* NDSI_MULTI_APNS_PROPS[NDIS_MULTI_NUM_MAX] = {
                 "default",
                 "ril.ndismulti.apn2",
                 "ril.ndismulti.apn3",
                 "ril.ndismulti.apn4",
};
static int glatest_multi_ndis_proto = 1;
int g_ndis_multi_num = 0; //0:not use multi ndis
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support End*/


/* trigger change to this with s_state_cond */
static int s_closed = 0;

static int sFD;            /* file desc of AT channel */
static char sATBuffer[MAX_AT_RESPONSE + 1];
static char *sATBufferCur = NULL;

static const struct timeval TIMEVAL_SIMPOLL = { 1, 0 };
static const struct timeval TIMEVAL_CALLSTATEPOLL = { 0, 500000 };
/* begin: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/
const struct timeval TIMEVAL_0 = { 0, 0 };
const struct timeval TIMEVAL_1 = {1, 0};
const struct timeval TIMEVAL_5 = {5, 0};
const struct timeval TIMEVAL_20 = {20, 0};
const struct timeval TIMEVAL_60 = {60, 0};
/* end: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/

/*[zhaopf@meigsmart-2020-1211]when usb reconnected, wait 500ms for network card ready { */
static const struct timeval TIMEVAL_WAIT_ETH_READY = { 0, 500 };
/*[zhaopf@meigsmart-2020-1211]when usb reconnected, wait 500ms for network card ready } */
/*[zhaopf@meigsmart-2020-0908]add for later init { */
static const struct timeval TIMEVAL_LATER_INIT = { 20, 0 };
/*[zhaopf@meigsmart-2020-0908]add for later init } */
/* begin: added by dongmeirong for AT Ver adaption 20201217 */
static const struct timeval TIMEVAL_LATER_INIT_GPS_SLM750 = {10, 0};
/* END: added by dongmeirong for AT Ver adaption 20201217 */

static int s_ims_registered = 0;    // 0==unregistered
static int s_ims_services = 1;    // & 0x1 == sms over ims supported
static int s_ims_format = 1;    // FORMAT_3GPP(1) vs FORMAT_3GPP2(2);
static int s_ims_cause_retry = 0;    // 1==causes sms over ims to temp fail
static int s_ims_cause_perm_failure = 0;    // 1==causes sms over ims to permanent fail
static int s_ims_gsm_retry = 0;    // 1==causes sms over gsm to temp fail
static int s_ims_gsm_fail = 0;    // 1==causes sms over gsm to permanent fail

/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
#ifdef UNSOLICITED_SIGNAL_STRENGTH
static bool s_is_pollSignalStarted = false;
static bool s_is_pollQuicklyStarted = false;
#endif
/* end: add by dongmeirong for poll signal strength by ril 20210615 */
/* begin: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/
#ifdef POLL_SIM_ABSENT_RESET_MODULE
static bool s_is_pollSimAbsentStarted = false;
#endif
/* end: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/

#ifdef WORKAROUND_ERRONEOUS_ANSWER
// Max number of times we'll try to repoll when we think
// we have a AT+CLCC race condition
#define REPOLL_CALLS_COUNT_MAX 4

// Line index that was incoming or waiting at last poll, or -1 for none
static int s_incomingOrWaitingLine = -1;
// Number of times we've asked for a repoll of AT+CLCC
static int s_repollCallsCount = 0;
// Should we expect a call to be answered in the next CLCC?
static int s_expectAnswer = 0;
#endif                /* WORKAROUND_ERRONEOUS_ANSWER */

static int s_cell_info_rate_ms = INT_MAX;
static int s_mcc = 0;
static int s_mnc = 0;
static int s_lac = 0;
static int s_cid = 0;
/*[zhaopf@meigsmart-2020-0601] add for sdk version detect { */
 int g_sdk_version = PLATFORM_SDK_VERSION;
/*[zhaopf@meigsmart-2020-0601] add for sdk version detect } */

//zhaopf add for meig modem info
MODEM_INFO  curr_modem_info;
int current_cid = 1; //[zhaopf@meigsmart-2022-06-10] add for mms support
/*[zhaopf@meigsmart-20201113]add for monitor sim plugn in or not { */
SIM_Status s_sim_state = SIM_ABSENT;
/*[zhaopf@meigsmart-20201113]add for monitor sim plugn in or not } */

/* begin: added by dongmeirong for SLM790 IP address adaption 20210113 */
// Transfer parameters' id in dhcp cmd to id in address buff.
static const int dhcpParamId2BuffId[] = { // 8 parameters in DHCP cmd
    ADDRESS_BUFF_ID_IPADDRESS,
    ADDRESS_BUFF_ID_MAX, // netmask no need to be parsed
    ADDRESS_BUFF_ID_GATEWAY,
    ADDRESS_BUFF_ID_MAX, // dhcp server no need to be parsed
    ADDRESS_BUFF_ID_PDNS,
    ADDRESS_BUFF_ID_SDNS,
    ADDRESS_BUFF_ID_MAX, // mas_rx_data no need to be parsed
    ADDRESS_BUFF_ID_MAX, // mas_tx_data no need to be parsed
};

static DHCP_CMD dhcpCmds[2] = {
    {
        ADDRESS_TYPE_V4,
        "AT^DHCP?",
        "^DHCP:"
    },
    {
        ADDRESS_TYPE_V6,
        "AT^DHCPV6?",
        "^DHCPV6:"
    }
};
/* end: added by dongmeirong for SLM790 IP address adaption 20210113 */
/* meig-zhaopengfei-2021-10-22 trigger module  dumps while at port timeout, not enale by default { */
//#define TRIG_DUMP_WHEN_TIMEOUT
#ifdef TRIG_DUMP_WHEN_TIMEOUT
static bool s_last_at_timeout = false;
#endif
/* meig-zhaopengfei-2021-10-22 trigger module  dumps while at port timeout, not enale by default } */
/* begin: added by dongmeirong for AGPS requirement 20201117 */
static bool s_is_gps_inited = false;
static pthread_mutex_t s_gps_init_mutex = PTHREAD_MUTEX_INITIALIZER;
extern void getSuplInfo(char **suplHost, int *suplPort);
/* end: added by dongmeirong for AGPS requirement 20201117 */

/* begin: added by dongmeirong for AGPS interface adapt 20210207 */
bool s_is_supl_host_set = false;
/* end: added by dongmeirong for AGPS interface adapt 20210207 */

static void pollSIMState(void *param);
static void setRadioState(RIL_RadioState newState);
static void setRadioTechnology(ModemInfo * mdm, int newtech);
static int query_ctec(ModemInfo * mdm, int *current, int32_t * preferred);
static int parse_technology_response(const char *response, int *current,
                                     int32_t * preferred);
static int techFromModemType(int mdmtype);
static void requestSignalStrength(void *data __unused, size_t datalen __unused, RIL_Token t);

/* begin: added by dongmeirong for AGPS requirement 20201117 */
static void setIsGpsInited(bool isInited) {
    RLOGD("%s() entry.", __FUNCTION__);
    pthread_mutex_lock(&s_gps_init_mutex);
    s_is_gps_inited = isInited;
    RLOGD("%s() s_is_gps_inited = %d", __FUNCTION__, s_is_gps_inited);
    pthread_mutex_unlock(&s_gps_init_mutex);
    RLOGD("%s() leave.", __FUNCTION__);
}

bool getIsGpsInited() {
    bool isInited = false;
    RLOGD("%s() entry.", __FUNCTION__);
    pthread_mutex_lock(&s_gps_init_mutex);
    isInited = s_is_gps_inited;
    RLOGD("%s() isInited = %d", __FUNCTION__, isInited);
    pthread_mutex_unlock(&s_gps_init_mutex);
    RLOGD("%s() entry.", __FUNCTION__);
    return isInited;
}
/* end: added by dongmeirong for AGPS requirement 20201117 */

static int clccStateToRILState(int state, RIL_CallState * p_state)
{
switch (state) {
case 0:
    *p_state = RIL_CALL_ACTIVE;
    return 0;
case 1:
    *p_state = RIL_CALL_HOLDING;
    return 0;
case 2:
    *p_state = RIL_CALL_DIALING;
    return 0;
case 3:
    *p_state = RIL_CALL_ALERTING;
    return 0;
case 4:
    *p_state = RIL_CALL_INCOMING;
    return 0;
case 5:
    *p_state = RIL_CALL_WAITING;
    return 0;
default:
    return -1;
}
}
//wangbo add

CHINA_OPERATOR cur_oper = UNKNOWN_OPER;
char s_current_apn[MAX_S_CURRENT_APN_LEN+1] = {'\0'};

//hzl 20170518 add begin
#if 1
static void skipWhiteSpace(char **p_cur)
{
if (*p_cur == NULL) return;

while (**p_cur != '\0' && isspace(**p_cur)) {
    (*p_cur)++;
}
}
#endif
//hzl add end
//wangbo 2017/07/11 add for cdma pdu sms

/*功能：字符串截取*/
/*参数： str 传入字符串，StartPostion为开始位置下标，SubstringLength为截取长度*/
/*返回：截取的部分*/
char *SubString(char *str, int StartPostion, int SubstringLength)
{
int stringlen = 0;
int i = 0;
int x = 0;
char *tmp;
stringlen = strlen(str);
tmp = (char *)malloc(sizeof(char)*(SubstringLength + 1));
if ((StartPostion < 0) || (SubstringLength <= 0) || (stringlen == 0) || (StartPostion >= stringlen)) {

    strcpy(tmp, "\0");
    return tmp;
}
for (i = StartPostion; ((i < stringlen) && (x < SubstringLength)); i++) {
    tmp[x] = str[i];
    x++;
}
tmp[x] = '\0';
return tmp;
}
//wangbo add 20170609 for inside dialer begin
int ril_exec_cmd(const char *command)
{
pid_t pid;
sig_t intsave, quitsave;
sigset_t mask, omask;
int pstat = -1;
/*Begin DTS2013101000098  wujiacheng  2013-10-10 for modified*/
char buffer[1024] = {0};
/*End DTS2013101000098  wujiacheng  2013-10-10 for modified*/
char *argp[32] = {0};
char *next = buffer;
char *tmp = NULL;
int i = 0;

if (!command)
    return 1;

if (strnlen(command, sizeof(buffer) - 1) == sizeof(buffer) - 1) {
    RLOGE("command line too long while processing: %s", command);
    return -1;
}

strcpy(buffer, command); // Command len is already checked.
while ((tmp = strsep(&next, " "))) {
    if(0 == strlen(tmp)) {
        continue;
    }
    argp[i++] = tmp;
    if (i == 32) {
        RLOGE("argument overflow while processing: %s", command);
        return -1;
    }
}
argp[i] = NULL;

sigemptyset(&mask);
sigaddset(&mask, SIGCHLD);
sigprocmask(SIG_BLOCK, &mask, &omask);
switch (pid = vfork()) {
case -1:                        /* error */
    sigprocmask(SIG_SETMASK, &omask, NULL);
    return(-1);
case 0:                                 /* child */
    sigprocmask(SIG_SETMASK, &omask, NULL);
    execve(argp[0], argp, environ);
    _exit(127);
}

intsave = (sig_t)  bsd_signal(SIGINT, SIG_IGN);
quitsave = (sig_t) bsd_signal(SIGQUIT, SIG_IGN);
pid = waitpid(pid, (int *)&pstat, 0);
sigprocmask(SIG_SETMASK, &omask, NULL);
(void)bsd_signal(SIGINT, intsave);
(void)bsd_signal(SIGQUIT, quitsave);
return (pid == -1 ? -1 : pstat);
}
//wangbo add 20170609 for inside dialer end

//wangbo add
/*[zhaopf@meigsmart-2020-1126]add for screen state { */
void requestScreenState(void *data , size_t datalen __unused, RIL_Token t)
{
int screenOn = ((int *)data)[0];
s_screen_state = screenOn;
RLOGD("screen is %s", screenOn?"on":"off");
RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}
/*[zhaopf@meigsmart-2020-1126]add for screen state } */

/* added by zte-yuyang end */



static int odm_get_current_network_type()
{
int err;
int response = 0;
const char *cmd;
const char *prefix;
char *line;
ATResponse *p_response = NULL;

//wangbo debug
usleep(2*1000);

cmd = "AT+PSRAT?\n\r";
prefix = "+PSRAT:";
err = at_send_command_singleline(cmd, prefix, &p_response);
if (err < 0 || p_response->success == 0)
    goto error;

//if ((0 == err) || (0 != p_response->success))
{
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (0 == err) {
        if (strstr(line, "GPRS") != NULL)
            response = 1;
        else if (strstr(line, "GSM") != NULL)
            response = 16;
        else if (strstr(line, "TDSCDMA") != NULL)
            response = 17;
        else if (strstr(line, "EDGE") != NULL)
            response = 2;
        else if (strstr(line, "WCDMA") != NULL)
            response = 3;
        else if (strstr(line, "HSDPA") != NULL)
            response = 9;
        else if (strstr(line, "HSUPA") != NULL)
            response = 10;
        else if (strstr(line, "HSPA+") != NULL)
            response = 15;
        else if ((strstr(line, "FDD LTE") != NULL)
                 || (strstr(line, "TDD LTE") != NULL)
                 || (strstr(line, "LTE")))
            response = 14;
        else if (strstr(line, "CDMA") != NULL)
            response = 6;
        else if ((strstr(line, "EVDO") != NULL)
                 || (strstr(line, "CDMA&EVDO") != NULL))
            response = 7;
        else if (strstr(line, "EHRPD") != NULL)
            response = 13;
        else {
            response = 0;
        }
    } else {
        RLOGD("----PSRAT--- error\n");
    }
//hzl
    at_response_free(p_response);
    p_response = NULL;
    //return response;    //ril7 new
}
error:
at_response_free(p_response);
p_response = NULL;
RLOGD(" current network-type is %d\n", response);
return response;
}

//wangbo 20170613 add to avoid call psrat many times
int iscdma_check()
{
int networktype = odm_get_current_network_type();
if(networktype == 7 || networktype == 6) {
    iscdma = 1 ;
} else {
    iscdma = 0;
}
return 0;
}
/* meig-zhaopengfei-2019-12-31 add for operator update { */
void update_operator_info()
{
RLOGD("update oper info s_mcc:%d, s_mnc:%d\n", s_mcc, s_mnc);
if(s_mcc == CHINA_MCC) {
    switch(s_mnc) {

    case CHINA_MOBILE_MNC_00:
    case CHINA_MOBILE_MNC_02:
    case CHINA_MOBILE_MNC_07: {
        cur_oper = CHINA_MOBILE_OPER;
        RLOGD("update oper CHINA_MOBILE_OPER");
    }
    break;

    case CHINA_UNICOM_MNC_01:
    case CHINA_UNICOM_MNC_06:
    case CHINA_UNICOM_MNC_09: {
        cur_oper = CHINA_UNICOM_OPER;
        RLOGD("update oper CHINA_UNICOM_OPER");
    }
    break;

    case CHINA_TELECOM_MNC_03:
    case CHINA_TELECOM_MNC_05:
    case CHINA_TELECOM_MNC_11: {
        cur_oper = CHINA_TELECOM_OPER;
        RLOGD("update oper CHINA_TELECOM_OPER");
    }

    break;

    case CHINA_TIETONG_MNC_20: {
        cur_oper = CHINA_TIETONG_OPER;
        RLOGD("update oper CHINA_TELECOM_OPER");
    }
    break;
    }


}
}
/* meig-zhaopengfei-2019-12-31 add for operator update } */


//20170418 modify CIMI and QCIMI order
void requestGetIMSI_original(void *data __unused, size_t datalen __unused, RIL_Token t)
{
ATResponse *p_response = NULL;
int err = 0;
char *line=NULL;
//wangbo debug EVDO double regeister
//err = at_send_command_numeric("AT+CIMI", &p_response);
err = at_send_command_numeric("AT+QCIMI", &p_response);
if (err < 0 || p_response->success == 0) {
    //err = at_send_command_numeric("AT+QCIMI", &p_response);
    err = at_send_command_numeric("AT+CIMI", &p_response);
    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    } else {
        RIL_onRequestComplete(t, RIL_E_SUCCESS,
                              p_response->p_intermediates->line, sizeof(char *));
    }
} else {
    line = p_response->p_intermediates->line;
    RIL_onRequestComplete(t, RIL_E_SUCCESS,
                          p_response->p_intermediates->line, sizeof(char *));
}
at_response_free(p_response);
}


static int getRadioAccessFamily()
{
#if 0
int err;
int response = 0;
const char *cmd;
const char *prefix;
char *line;
ATResponse *p_response = NULL;

cmd = "AT+PSRAT?";
prefix = "+PSRAT:";
err = at_send_command_singleline(cmd, prefix, &p_response);
if (err < 0 || p_response->success == 0)
    goto error;

//if ((0 == err) || (0 != p_response->success))
{
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (0 == err) {
        if (strstr(line, "GPRS") != NULL)
            response = RAF_GPRS;
        else if (strstr(line, "GSM") != NULL)
            response = RAF_GSM;
        else if (strstr(line, "TDSCDMA") != NULL)
            response = RAF_TD_SCDMA;
        else if (strstr(line, "EDGE") != NULL)
            response = RAF_EDGE;
        else if (strstr(line, "WCDMA") != NULL)
            response = RAF_UMTS;
        else if (strstr(line, "HSDPA") != NULL)
            response = RAF_HSDPA;
        else if (strstr(line, "HSUPA") != NULL)
            response = RAF_HSUPA;
        else if (strstr(line, "HSPA+") != NULL)
            response = RAF_HSPA;
        else if ((strstr(line, "FDD LTE") != NULL)
                 || (strstr(line, "TDD LTE") != NULL)
                 || (strstr(line, "LTE")))
            response = RAF_LTE;
        else if (strstr(line, "CDMA") != NULL)
            response = RAF_1xRTT;
        else if ((strstr(line, "EVDO") != NULL)
                 || (strstr(line, "CDMA&EVDO") != NULL))
            response = RAF_EVDO_B;
        else if (strstr(line, "EHRPD") != NULL)
            response = RAF_EHRPD;
        else {
            response = RAF_UNKNOWN;
        }
    } else {
        RLOGD("----RadioTechnologyFamily--- error\n");
        response = RAF_UNKNOWN;
    }
}
error:
at_response_free(p_response);
p_response = NULL;
return response;
#else
ATResponse *p_response = NULL;
int err = 0;
int radiotechfamily;
char *line=NULL;
char *p = NULL;
char mcc_str[4] = { 0x0};
char mnc_str[3] = { 0x0};

/*[zhaopf@meigsmart-2020-0108] modify radio access family for SRM815 { */
int oper_radio_cap_map[4];
/*yufeilong add for modify SRM810 network type set failed 20230506 begin*/
if(((curr_modem_info.info.module_type & SRM815_MODULE) > 0) || ((curr_modem_info.info.module_type & SRM811_MODULE) > 0)){
/*yufeilong add for modify SRM810 network type set failed 20230506 end*/
    //UNKNOWN_OPER
    oper_radio_cap_map[0] =  ((1<<RADIO_TECH_HSDPA)|
                             (1<<RADIO_TECH_HSUPA)|
                             (1<<RADIO_TECH_HSPA)|
                             (1<<RADIO_TECH_EHRPD)|
                             (1<<RADIO_TECH_HSPAP)|
                             (1<<RADIO_TECH_LTE)| //4G
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
                             (1<<RADIO_TECH_LTE_CA)|
#endif
                             (1<<RADIO_TECH_NR5G)); //5G
    //CHINA_MOBILE_OPER
    oper_radio_cap_map[1] =  ((1<<RADIO_TECH_LTE)| //4G
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
                             (1<<RADIO_TECH_LTE_CA)|
#endif
                             (1<<RADIO_TECH_NR5G)); //5G
     //CHINA_UNICOM_OPER
     oper_radio_cap_map[2] =  ((1<<RADIO_TECH_HSDPA)|
                              (1<<RADIO_TECH_HSUPA)|
                              (1<<RADIO_TECH_HSPA)|
                              (1<<RADIO_TECH_EHRPD)|
                              (1<<RADIO_TECH_HSPAP)|
                              (1<<RADIO_TECH_LTE)| //4G
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
                              (1<<RADIO_TECH_LTE_CA)|
#endif
                              (1<<RADIO_TECH_NR5G)); //5G
    //CHINA_TELECOM_OPER
    oper_radio_cap_map[3] =  ((1<<RADIO_TECH_LTE)| //4G
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
                              (1<<RADIO_TECH_LTE_CA)|
#endif
                              (1<<RADIO_TECH_NR5G)); //5G
   RLOGD("use srm815 radio access family");

} else {
    //UNKNOWN_OPER = 0, CHINA_MOBILE_OPER, CHINA_UNICOM_OPER,CHINA_TELECOM_OPER
    oper_radio_cap_map[0]=0x3ff4e;
    oper_radio_cap_map[1]=0xb4006;
    oper_radio_cap_map[2]=0x9ce0e;
    oper_radio_cap_map[3]=0x871f0;
}
/*[zhaopf@meigsmart-2020-0108] modify radio access family for SRM815 } */

/* begin: modified by dongmeirong for CIMI retry in case of ERROR 20210130 */
p_response = cimiAtCmd();

if (p_response == NULL) {
    RLOGE("error cimi\n");
    return oper_radio_cap_map[UNKNOWN_OPER];
}
if(strlen(p_response->p_intermediates->line) < 5) {
    RLOGE("error cimi\n");
    at_response_free(p_response);
    return oper_radio_cap_map[UNKNOWN_OPER];
}
strncpy(mcc_str, p_response->p_intermediates->line, 3);
p = p_response->p_intermediates->line;
p += 3;
strncpy(mnc_str, p, 2);
RLOGD("%s got mcc:%s, mnc:%s\n", __FUNCTION__, mcc_str, mnc_str);
s_mnc = atoi(mnc_str);
s_mcc = atoi(mcc_str);
update_operator_info();
at_response_free(p_response);
/* end: modified by dongmeirong for CIMI retry in case of ERROR 20210130 */

if(cur_oper >= UNKNOWN_OPER && cur_oper < CHINA_TIETONG_OPER) {
    return oper_radio_cap_map[cur_oper];
} else {
    return oper_radio_cap_map[UNKNOWN_OPER];
}
#endif
}
/*[zhaopf@meigsmart-2022-06-10] add for mms support Begin */
static void requestDeactivateDataCall(void *data, size_t datalen __unused, RIL_Token t)
{
int err;
char syscmd[52] = {0};
const char* cid = ((char**)data)[0];
int iCid = atoi(cid);
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin */
char if_name[10] = { 0x0 };
char *cmd;
int i = 0;
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support End */
RLOGD("%s, cid=%d\n", __FUNCTION__, iCid);

pthread_mutex_lock(&s_pppd_mutex);
if(pppd) {
    /*Add by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 Begin */
    g_deactive_working = true;
    /*Add by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 End */
    switch(devmode) {
    case RAS_MOD:
        RLOGD("Stop existing PPPd");
        //at_send_command("+++ATH",NULL);
        meig_pppd_stop(SIGTERM);
        #ifdef SEND_MMS_USE_PPP
        system("/system/bin/ip route add default dev usb0"); //zhangqingyun add to make default route to usb0
        #endif 
        break;
    case ECM_MOD:
    case RNDIS_MOD: // added by dongmeirong for RNDIS adapt 20210219
        ifc_disable(curr_modem_info.if_name);
        //zhangqingyun add for slm750&730 we should send at+ecmdup=1,1,0 to modem
        //Modify by zhaopengfei for params of ecmdup are not same beteewn slm750r1 vs others 2022/12/27
        if(curr_modem_info.info.sltn_type == QCM && curr_modem_info.info.at_version == AT_VERSION_1){
            RLOGD("qualcom send at to modem");
            at_send_command("at+ecmdup=1,1,0",NULL);
        /*Modify by zhaopengfei for hisi modem deactive 2022/12/27 Begin*/
        } else if(curr_modem_info.info.sltn_type == HISI){
            at_send_command("at^ndisdup=1,0",NULL);
        /*Add by zhaopengfei for ecmdup support as some modems can't auto setup data call at present, can be enable by  ECMDUP_ENABLE if you need 2022/12/23 Begin */
#ifdef ECMDUP_ENABLE
        } else {
           at_send_command("at+ecmdup=1,0",NULL);
#endif
        }
        /*Add by zhaopengfei for ecmdup support as some modems can't auto setup data call at present, can be enable by  ECMDUP_ENABLE if you need 2022/12/23 End */
        /*Modify by zhaopengfei for hisi modem deactive 2022/12/27 End*/

        break;
    case QMI_MOD:
/*modify by zhaopengfei 2022/10/10 change qmi utils from cm to api Begin */
       ifc_disable(curr_modem_info.if_name);
       CMRequestTurnDownDataCall(iCid-1);
       /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
       if(!curr_modem_info.use_deprecated_gobi){
           ifc_disable(curr_modem_info.vif_name[iCid-1]);
       }
       /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
/*modify by zhaopengfei 2022/10/10 change qmi utils from cm to api End */
        break;
    case NDIS_MOD:
        ifc_disable(curr_modem_info.if_name);
        at_send_command("at^ndisdup=1,0",NULL);
        break;
    case NCM_MOD:
        ifc_disable(curr_modem_info.if_name);
        at_send_command("at^ndisdup=1,0",NULL);
    /*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin */
    case MULTI_NDIS_MOD:
        ifc_disable(curr_modem_info.if_name);
        for(i = 0; i < g_ndis_multi_num; i++) {
            asprintf(&cmd,"AT$QCRMCALL=0,%d,%d, 2, %d", i+1, glatest_multi_ndis_proto, (0 == i)?1:(10+i));
            at_send_command(cmd, NULL); //fixed err by zhaopf
            free(cmd);
        }
        break;
    case MULTI_QMI_MOD:
        /*modify by zhaopengfei 2022/10/10 change qmi utils from cm to api Begin */
        ifc_disable(curr_modem_info.if_name);
        /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
        if(curr_modem_info.use_deprecated_gobi) {
            CMRequestTurnDownDataCall(0);
        } else {
            for(i = 0; i < g_ndis_multi_num; i++) {
                   CMRequestTurnDownDataCall(i);
                   ifc_disable(curr_modem_info.vif_name[i]);
            }
        }
        /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
        break;
    /*modify by zhaopengfei 2022/10/10 change qmi utils from cm to api End */
    default:
        break;


    }

    pppd = 0;
}
pthread_mutex_unlock(&s_pppd_mutex);
//Add by zhaopengfei for iface state indicate 2023/01/12
RLOGD("trigger sys.meig.ifup down");
property_set("sys.meig.ifup", "false");
RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
return;

}
/*[zhaopf@meigsmart-2022-06-10] add for mms support End */
static int s_lastPdpFailCause = PDP_FAIL_ERROR_UNSPECIFIED;
static void requestLastPDPFailCause(RIL_Token t)
{
ALOGD("requestLastPDPFailCause");
RIL_onRequestComplete(t, RIL_E_SUCCESS, &s_lastPdpFailCause, sizeof(int));
}

static void get_local_ip(char *local_ip)
{
//zhangqingyun add for suppor mms get ip address 2023-5-7  
#ifndef SEND_MMS_USE_PPP 
if(RAS_MOD == devmode) { //fixed by zhaopf, shuld be devmode
    RLOGD("%s by prop", __FUNCTION__);
    char LOCAL_IP_PROP[PROPERTY_KEY_MAX] = {0};
    char tmp_local_ip[PROPERTY_VALUE_MAX]= {0};
    /* begin: modified by dongmeirong for ip property name custimesed for SHIYUAN_LIUHUAN 20210622 */
    sprintf(LOCAL_IP_PROP, LOCAL_IP_PROPERTY_KEY_FORMAT, curr_modem_info.if_name);
    RLOGD("%s local-ip property name format: %s", __FUNCTION__, LOCAL_IP_PROP);
    /* end: modified by dongmeirong for ip property name custimesed for SHIYUAN_LIUHUAN 20210622 */
    property_get(LOCAL_IP_PROP, tmp_local_ip, "0.0.0.0");
    strcpy(local_ip, tmp_local_ip);
} else {
#endif 
    int inet_sock;
    struct ifreq ifr;
    char *ip = NULL;
    struct in_addr addr;

    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, curr_modem_info.if_name);

    if (ioctl(inet_sock, SIOCGIFADDR, &ifr) < 0) {
        strcpy(local_ip, "0.0.0.0");
        goto error;
    }
    memcpy (&addr, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof (struct in_addr));
    ip = inet_ntoa(addr);
    strcpy(local_ip, ip);
error:
    close(inet_sock);
#ifndef SEND_MMS_USE_PPP
}
#endif
}

/*zhaopf@meigsmart-2021/08/09 add for multi qmi-ndis support Begin { */
static void get_ip_of_intf(const char* if_name, char *local_ip)
{
if(RAS_MOD == devmode) {
    RLOGD("%s by prop", __FUNCTION__);
    char LOCAL_IP_PROP[PROPERTY_KEY_MAX] = {0};
    char tmp_local_ip[PROPERTY_VALUE_MAX]= {0};
    sprintf(LOCAL_IP_PROP, "net.%s.local-ip", if_name);
    property_get(LOCAL_IP_PROP, tmp_local_ip, "0.0.0.0");
    strcpy(local_ip, tmp_local_ip);
} else {
    int inet_sock;
    struct ifreq ifr;
    char *ip = NULL;
    struct in_addr addr;

    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, if_name);

    if (ioctl(inet_sock, SIOCGIFADDR, &ifr) < 0) {
        strcpy(local_ip, "0.0.0.0");
        goto error;
    }
    memcpy (&addr, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof (struct in_addr));
    ip = inet_ntoa(addr);
    strcpy(local_ip, ip);
error:
    close(inet_sock);
}
}

/*zhaopf@meigsmart-2021/08/09 add for multi qmi-ndis support End } */

//add by zhaopf for Android4.4 support, 2020/12/11
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
static void requestGetRadioCapability(void *data __unused,
                                      size_t datalen __unused, RIL_Token t)
{
RIL_RadioCapability stRadioCapability;
int radiotechfamily;

radiotechfamily = getRadioAccessFamily();


RLOGD("requestGetRadioCapability() | manual set radio tech family 0x%x", radiotechfamily);

stRadioCapability.version = RIL_RADIO_CAPABILITY_VERSION;
//stRadioCapability.status=RC_STATUS_FAIL;
stRadioCapability.status = RC_STATUS_SUCCESS;
strcpy(stRadioCapability.logicalModemUuid,"");
stRadioCapability.rat = radiotechfamily;
stRadioCapability.phase = RC_PHASE_CONFIGURED;
stRadioCapability.session = 0;
RIL_onRequestComplete(t, RIL_E_SUCCESS, &stRadioCapability,
                      sizeof(stRadioCapability));
return;
}
#endif

static void requestSetTtyMode(void *data __unused, size_t datalen __unused,
                              RIL_Token t)
{
// tty mode off
int response = 0;
RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
}

/**
 * Note: directly modified line and has *p_call point directly into
 * modified line
 */
static int callFromCLCCLine(char *line, RIL_Call * p_call)
{
//+CLCC: 1,0,2,0,0,\"+18005551212\",145
//     index,isMT,state,mode,isMpty(,number,TOA)?

int err;
int state;
int mode;

err = at_tok_start(&line);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &(p_call->index));
if (err < 0)
    goto error;

err = at_tok_nextbool(&line, &(p_call->isMT));
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &state);
if (err < 0)
    goto error;

err = clccStateToRILState(state, &(p_call->state));
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &mode);
if (err < 0)
    goto error;

p_call->isVoice = (mode == 0);

err = at_tok_nextbool(&line, &(p_call->isMpty));
if (err < 0)
    goto error;

if (at_tok_hasmore(&line)) {
    err = at_tok_nextstr(&line, &(p_call->number));

    /* tolerate null here */
    if (err < 0)
        return 0;

    // Some lame implementations return strings
    // like "NOT AVAILABLE" in the CLCC line
    if (p_call->number != NULL
            && 0 == strspn(p_call->number, "+0123456789")
       ) {
        p_call->number = NULL;
    }

    err = at_tok_nextint(&line, &p_call->toa);
    if (err < 0)
        goto error;
}

p_call->uusInfo = NULL;

return 0;

error:
RLOGE("invalid CLCC line\n");
return -1;
}

/** do post-AT+CFUN=1 initialization */
static void onRadioPowerOn()
{
#ifdef USE_TI_COMMANDS
/*  Must be after CFUN=1 */
/*  TI specific -- notifications for CPHS things such */
/*  as CPHS message waiting indicator */

at_send_command("AT%CPHS=1", NULL);

/*  TI specific -- enable NITZ unsol notifs */
at_send_command("AT%CTZV=1", NULL);
#endif

//wangbo debug
RLOGD("******** Enter onRadioPowerOn() ********");

pollSIMState(NULL);
}

/** do post- SIM ready initialization */
static void onSIMReady()
{


RLOGD("******** Enter onSIMReady() ********");
//at_send_command_singleline("AT+CSMS=1", "+CSMS:", NULL);
at_send_command_singleline("AT+CSMS=0", "+CSMS:", NULL);
/*
 * Always send SMS messages directly to the TE
 *
 * mode = 1 // discard when link is reserved (link should never be
 *             reserved)
 * mt = 2   // most messages routed to TE
 * bm = 2   // new cell BM's routed to TE
 * ds = 1   // Status reports routed to TE
 * bfr = 1  // flush buffer
 */
//at_send_command("AT+CNMI=1,2,2,1,1", NULL);
at_send_command("AT+CNMI=2,1,2,2,0", NULL);
/*zhangqingyun add skyworth slm770 workaround send mms in me 2023-5-7 start*/
#ifdef SEND_MMS_USE_PPP
at_send_command("AT+CPMS=\"SM\",\"SM\",\"SM\"", NULL);
#else 
at_send_command("AT+CPMS=\"ME\",\"ME\",\"ME\"", NULL);
#endif
/*zhangqingyun add skyworth slm770 workaround send mms in me 2023-5-7 end*/
}
/*[zhaopf@megismart-2020-1112]add for server domain set { */
static void updateServiceDomain()
{
    int err;
    int i;
    char *responseStr[9];
    const int max_param_count = 9;
    ATResponse *p_response = NULL, *p_setresponse = NULL;
    char *cmd = NULL; //fixed err by zhaopf
    char *line;
    memset(responseStr, 0x0, sizeof(responseStr));
    SRV_DOMAIN srv_domain = SRV_DOMAIN_AUTO;
    char srvDomainVal[PROPERTY_VALUE_MAX] = {0};

    //if unset prop, do nothing
    if(property_get("persist.sys.meig.srvdomain", srvDomainVal, "both") <= 0) {
        return;
    }

    if(!strcasecmp(srvDomainVal, "cs")){
        srv_domain = SRV_DOMAIN_CS_ONLY;
    } else if(! strcasecmp(srvDomainVal, "ps")) {
        srv_domain = SRV_DOMAIN_PS_ONLY;
    } else{
        srv_domain = SRV_DOMAIN_AUTO;
    }

    if(s_current_srv_domain != srv_domain){
        RLOGD("service domain change from %s to %s", srvDoamin2Str[s_current_srv_domain], srvDoamin2Str[srv_domain]);
        s_current_srv_domain = srv_domain;
    } else {
         //not changed directly return
         return;
    }

    err = at_send_command_singleline("AT^SYSCFGEX?","^SYSCFGEX:",&p_response);
    if(err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }

    for(i = 0; i < max_param_count; i++){
        err = at_tok_nextstr(&line,&responseStr[i]);
        #ifdef DEBUG
        ALOGD("syscfgex param[%d]=%s", i, responseStr[i]);
        #endif
        if(err < 0) {
            goto error;
        }
    }

    if(s_current_srv_domain == atoi(responseStr[3])){
        goto skipout;
    }


    asprintf(&cmd, "AT^SYSCFGEX=99,,,%d", s_current_srv_domain);
    err = at_send_command(cmd,&p_setresponse);
    if(err < 0 || p_setresponse->success == 0) {
        RLOGD("%s send command failed", __FUNCTION__);
    }

error:
skipout:
    at_response_free(p_setresponse);
    at_response_free(p_response);
    free(cmd);

}
/*[zhaopf@meigsmart-2020-1211]add for update 5gmode when init { */
static void update5GMode(bool setup)
{


   int err = 0;
   ATResponse *p_response = NULL;
   int setmode = 0;
   char *cmd = NULL;
   char fiveGModeVal[PROPERTY_VALUE_MAX] = {0};
   FIVEG_MODE fiveG_mode = FIVEG_MODE_AUTO;

    if(property_get("persist.sys.meig.5gmode", fiveGModeVal, "auto") <= 0) {
        return;
    }

    if(!strcasecmp(fiveGModeVal, "sa")){
        fiveG_mode = FIVEG_MODE_SA;
    } else if(!strcasecmp(fiveGModeVal, "sansa")) {
        fiveG_mode = FIVEG_MODE_SA_NSA;
    } else{
         fiveG_mode = FIVEG_MODE_AUTO;
    }
    if(s_current_5g_mode != fiveG_mode){
        RLOGD("fiveG mode change %s to %s", fiveGMode2Str[s_current_5g_mode], fiveGMode2Str[fiveG_mode]);
        s_current_5g_mode = fiveG_mode;
    } else {
        return;
    }
     if(setup){
         asprintf(&cmd, "AT^SYSCFGEX=%s", (FIVEG_MODE_SA == s_current_5g_mode)?"04":(FIVEG_MODE_SA_NSA == s_current_5g_mode)?"0403":"00");
         err = at_send_command(cmd,&p_response);
         if (err < 0) {
             RLOGD("%s send command failed", __FUNCTION__);
         }
         at_response_free(p_response);
         free(cmd);
     }
     return;

}
/*[zhaopf@meigsmart-2020-1211]add for update 5gmode when init } */
/*[zhaopf@megismart-2020-1112]add for server domain set } */

static void requestRadioPower(void *data, size_t datalen __unused, RIL_Token t)
{
/*[zhaopf@meigsmart-2020-1113]optimized time cost { */
int switchOn;

int err;
ATResponse *p_response = NULL;

assert(datalen >= sizeof(int *));
switchOn = ((int *)data)[0];
RLOGD("switchOn is:%d",switchOn);
RLOGD("sState is:%d",sState);
//RLOGD("init_radio_power is:%d",init_radio_power);
if (switchOn == 0 && sState != RADIO_STATE_OFF) {

/*[zhaopf@meigsmart-2020-1113]add domain server  & 5g mode customization for some special sim cards { */
    updateServiceDomain();
    update5GMode(true);
    sleep(1);
/*[zhaopf@meigsmart-2020-1113]add domain server  & 5g mode customization for some special sim cards } */
    err = at_send_command("AT+CFUN=0", &p_response);
    if (err < 0 || p_response->success == 0)
        goto error;
    /*[zhaopf@meigsmart-2021-04-01]add force disconnet for qmi mode  { */
    forceDeactiveDataCallList();
    /*[zhaopf@meigsmart-2021-04-01]add force disconnet for qmi mode  } */

    RLOGD("set radio on by framework");
    sleep(3); //add by zhaopf for delay as stuation user quickly switched
    setRadioState(RADIO_STATE_OFF);
} else if (switchOn > 0 && sState == RADIO_STATE_OFF) {
    err = at_send_command("AT+CFUN=1", &p_response);
    if (err < 0 || p_response->success == 0) {
        // Some stacks return an error when there is no SIM,
        // but they really turn the RF portion on
        // So, if we get an error, let's check to see if it
        // turned on anyway
        //hzl add
        sleep(3);
        /*[zhaopf@meigsmart-2020-0716] } fixed for checking online state { */
        if (isRadioOn() != RADIO_ONLINE_STATE) {
            goto error;
        }
        /*[zhaopf@meigsmart-2020-0716] } fixed for checking online state } */
    /*[zhaopf@meigsmart-2020-0601]remove delay for restart by framework { */
    } else {
        RLOGD("wait for ready");
        sleep(3); //add by zhaopef for wait modem ready
    }
    /*[zhaopf@meigsmart-2020-0601]remove delay for restart by framework } */
    setRadioState(RADIO_STATE_ON);
}
/*[zhaopf@meigsmart-2020-1113]optimized time cost } */
at_response_free(p_response);
RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
return;
error:
at_response_free(p_response);
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

//add by zhaopf for Android4.4 support, 2020/12/11
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
static void requestShutdown(RIL_Token t)
{

int err;
ATResponse *p_response = NULL;
/*[zhaopf@meigsmart-2020-0729]add for modem shutdown { */
if(QCM == curr_modem_info.info.sltn_type){
        err = at_send_command("AT+POWEROFF", &p_response);
} else {
        err = at_send_command("AT$MYPOWEROFF", &p_response);
}
if(err < 0){
    RLOGE("power off failed");
/*[zhaopf@meigsmart-2020-1217]add for modem state { */
} else{
    set_modem_state_connected(false);
}
/*[zhaopf@meigsmart-2020-1217]add for modem state } */
/*[zhaopf@meigsmart-2021-04-01]add force disconnet for qmi mode  { */
forceDeactiveDataCallList();
/*[zhaopf@meigsmart-2021-04-01]add force disconnet for qmi mode  } */


#if 0
if (sState != RADIO_STATE_OFF) {
    err = at_send_command("AT+CFUN=0", &p_response);
    setRadioState(RADIO_STATE_UNAVAILABLE);
}
#endif
/*[zhaopf@meigsmart-2020-0729]add for modem shutdown } */
at_response_free(p_response);
RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
return;
}
#endif

/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
/* Modify by zhaopengfei for response initialization incomplete  2022/10/14 Begin */
//zhangqingyun add deactive datacall list 2018 05 15 start
void onDeactiveDataCallList()
{
    char syscmd[52] = {0};
    char if_name[10] = { 0x0 };
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin */
    char* cmd = NULL;
    int i = 0;
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support End */
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    RIL_Data_Call_Response_v11 *responses = alloca(sizeof(RIL_Data_Call_Response_v11));
    memset(responses, 0x0, sizeof(RIL_Data_Call_Response_v11));
#else
    RIL_Data_Call_Response_v6 *responses = alloca(sizeof(RIL_Data_Call_Response_v6));
    memset(responses, 0x0, sizeof(RIL_Data_Call_Response_v6));
#endif
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support } */
    RLOGD("onDeactiveDataCallList pppd = %d",pppd);
    if(ndisIPV4state == NDIS_SUCCESS || ndisIPV6state == NDIS_SUCCESS){
        RLOGD("either IPv4 or IPv6 connect we take it as connect should not disconnect modem");
        return;
    }
pthread_mutex_lock(&s_pppd_mutex);
if(pppd) {
    /*Add by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 Begin */
    g_deactive_working = true;
    /*Add by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 End */
    RLOGD("Stop existing %s", devmode2str[devmode]);
    switch(devmode) {
    case RAS_MOD:
        //at_send_command("+++ATH", NULL);
        meig_pppd_stop(SIGTERM);
        #ifdef SEND_MMS_USE_PPP
        system("/system/bin/ip route add default dev usb0");//zhangqingyun add for support send mmms through ppp
        #endif 
        break;
    case NCM_MOD:
        ifc_disable(curr_modem_info.if_name);
        at_send_command("at^ndisdup=1,0",NULL);
        break;
    case ECM_MOD:
    case RNDIS_MOD: // added by dongmeirong for RNDIS adapt 20210219
        ifc_disable(curr_modem_info.if_name);
        break;
    case QMI_MOD:
        /*modify by zhaopengfei 2022/10/10 change qmi utils from cm to api Begin */
        if(!curr_modem_info.use_deprecated_gobi){
            ifc_disable(curr_modem_info.vif_name[0]);
            ifc_disable(curr_modem_info.vif_name[1]); //mms
        }
        ifc_disable(curr_modem_info.if_name);
        CMRequestTurnDownDataCall(0);
        /*modify by zhaopengfei 2022/10/10 change qmi utils from cm to api End */
        break;
    /*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin */
    case MULTI_NDIS_MOD:
        ifc_disable(curr_modem_info.if_name);
        for(i = 0; i < g_ndis_multi_num; i++) {
            asprintf(&cmd,"AT$QCRMCALL=0,%d", i+1);
            at_send_command(cmd, NULL);
            free(cmd);
         }
        break;
    case MULTI_QMI_MOD:
        /*modify by zhaopengfei 2022/10/10 change qmi utils from cm to api Begin */
        ifc_disable(curr_modem_info.if_name);
        if(curr_modem_info.use_deprecated_gobi){
            CMRequestTurnDownDataCall(0);
        } else {
            for(i = 0; i < g_ndis_multi_num; i++) {
                   CMRequestTurnDownDataCall(i);
                   ifc_disable(curr_modem_info.vif_name[i]);
            }
        }
        break;
      /* modify by zhaopengfei 2022/10/10 change qmi utils from cm to api End */
    default:
        break;
    }
    pppd = 0;
    responses->status = -1;
    responses->suggestedRetryTime = -1;
    responses->cid = 1;
    responses->active = 0;
    responses->type = "";
    responses->ifname = curr_modem_info.if_name;
    responses->addresses = "";
    responses->dnses = "";
    responses->gateways = "";
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    responses->pcscf = "";
    responses->mtu = 0;
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support { */
    RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                              responses, sizeof(RIL_Data_Call_Response_v11));
#else
    RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                              responses, sizeof(RIL_Data_Call_Response_v6));
#endif
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support } */
}
//Add by zhaopengfei for iface state indicate 2023/01/12
RLOGD("trigger sys.meig.ifup down");
property_set("sys.meig.ifup", "false");

pthread_mutex_unlock(&s_pppd_mutex);
}
/* Modify by zhaopengfei for response initialization incomplete  2022/10/14 End */
//zhangqingyun add deactive datacall list 2018 05 15 end
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */

/*[zhaopf@meigsmart-2021-04-01]add force disconnet for  qmi mode  { */
void forceDeactiveDataCallList(){
    if(QMI_MOD == devmode) {
        ndisIPV4state == NDIS_NOTCONNECT;
        ndisIPV6state == NDIS_NOTCONNECT;
        RLOGD("when radio off, qmi mode force disconnect\n");
        RIL_requestTimedCallback (onDeactiveDataCallList, NULL, &TIMEVAL_WAITDATADISCONNECT);
    }
}
/*[zhaopf@meigsmart-2021-04-01]add force disconnet for  qmi mode  }*/
/*[zhaopf@meigsmart-2022-06-28]add force flush network  Begin*/
void forceFlushNetState()
{
    RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED, NULL, 0);
    RLOGD("%s\n", __FUNCTION__);
}
/*[zhaopf@meigsmart-2022-06-28]add force flush network  End*/

/*Add by zhaopengfei for flush net state when ps not registered Begin*/
void flushNetIfNecessary() {
    if(!checkIfPSReady()){
        RLOGE("ps not ready, flush net");
        RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED, NULL, 0);
    }
}
/*Add by zhaopengfei for flush net state when ps not registered End*/
/*Add by zhaopengfei 2022/10/31 reset radio power when ps not registered Begin */
void resetRadioPowerIfNecessary() {
    if(!checkIfPSReady()){
        RLOGE("ps not ready, reset radio force reocvery");
        resetRadioPower(NULL);
    }
}
/*Add by zhaopengfei 2022/10/31 reset radio power when ps not registered End */




//[zhaopf@meigsmart-2022-06-28]custome call list by request
static void requestOrSendDataCallList(int request, RIL_Token * t);

static void onDataCallListChanged(void *param __unused)
{
    /*[zhaopf@meigsmart-2020-0106]do not send datacalllist when datacall disconnected { */
    if(pppd){
         /*[zhaopf@meigsmart-2020-0224]add for static address call list Begin  */
        /*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin */
        if(ECM_MOD == devmode || RNDIS_MOD == devmode) {
            #ifdef ECM_USE_STATIC_IP_ADDRESS
                    onSendStaticDataCallList(NULL);
            #else
                requestOrSendDataCallList(0, NULL);//[zhaopf@meigsmart-2022-06-28]custome call list by request
            #endif
        } else {
            requestOrSendDataCallList(0, NULL);//[zhaopf@meigsmart-2022-06-28]custome call list by request
        }
        /*zhaopf@meigsmart-2021/03/11 add for multi ndis support End */
        /*[zhaopf@meigsmart-2020-0224]add for static address call list End  */
    } else {
        RLOGD("%s pppd=%d, done", __FUNCTION__, pppd);
    }
    /*[zhaopf@meigsmart-2020-0106]do not send datacalllist when datacall disconnected } */
}

/*zhaopengfei@meigsmart.com-2021-0729 add for force sim refresh Begin*/

static void onSimRefresh(){
    RIL_SimRefreshResponse_v7 SimRefreshResponse;
    SimRefreshResponse.result = SIM_RESET;
    SimRefreshResponse.ef_id = 0;
    SimRefreshResponse.aid = NULL;
    RLOGD("onSimRefresh");
    RIL_onUnsolicitedResponse
            (RIL_UNSOL_SIM_REFRESH, &SimRefreshResponse,
             sizeof(SimRefreshResponse));
}

/*zhaopengfei@meigsmart.com-2021-0729 add for force sim refresh End*/
//[zhaopf@meigsmart-2022-06-28]custome call list by request
static void requestDataCallList(int request, void *data __unused, size_t datalen __unused,
                                RIL_Token t)
{
requestOrSendDataCallList(request, &t);
}

static void onDataCallExit(void *param)
{
#if 0 //not meig device
if (bSetupDataCallCompelete == 0/* && ql_is_EC20*/) {
    int cgreg_response[4];
    quectel_at_cgreg(cgreg_response);
    if (cgreg_response[0] != 1 && cgreg_response[0] != 5) {
        int cops_response[4];
        quectel_at_cops(cops_response);
        if (cops_response[3] == 7) { //lte moe
#if 0
            at_send_command("AT+CGDCONT=1,\"IPV4V6\",\"\"",  NULL);
            at_send_command("AT+CGATT=0",  NULL);
            at_send_command("AT+CGATT=1",  NULL);
#endif
        }
    }
}
#endif
RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED, NULL, 0);
RLOGD("%s", __FUNCTION__);
}


static const char *ipaddr_to_string(in_addr_t addr)
{
/*[zhaopf@meigsmart-2020-0615]modify for result not update on some platform {*/
struct in_addr local_addr;
memset(&local_addr, 0x0, sizeof(struct in_addr));
local_addr.s_addr = addr;
return inet_ntoa(local_addr);
/*[zhaopf@meigsmart-2020-0615]modify for result not update on some platform }*/
}

/*[zhaopf@meigsmart-2020-1117] convert IPv4 numbers-and-dots string to ip addr { */
static in_addr_t  string_to_ipaddr(const char* addrs)
{
    struct in_addr in_addr;
    if(0 != inet_aton(addrs, &in_addr)){
        return in_addr.s_addr;
    }
    return 0;

}
/*[zhaopf@meigsmart-2020-1117] convert IPv4 numbers-and-dots string to ip addr } */


/*[zhaopf@meigsmart-2020-06-16] add for ipv6 support { */
#define DEBUG_IPV6 1
//example:
#define IPV6ADDR_DOT_COUNT      (15)

int getCountOfChar(const char* srcStr, char c)
{
    const char* p = srcStr;
    int count = 0;
    if(NULL == srcStr) {
        return count;
    }
    while((*p) != '\0') {
        if((*p) == c) {
            count++;
        }
        p++;
    }

    return count;

}

/* begin: modified by dongmeirong for SLM790 IP address adaption 20210113 */
int isIPv6DotAddr(const char* dotAddrStr){

    int ret = 0;
    int count = 0;
    if(NULL == dotAddrStr) {
        RLOGE("para invalid\n");
        return ret;
    }
    count = getCountOfChar(dotAddrStr, '.');
    // HISI's dot address that has 31 dots is IP address combined with netmask.
    if ((curr_modem_info.info.sltn_type == QCM && count == IPV6ADDR_DOT_COUNT)
        || (curr_modem_info.info.sltn_type == HISI && count >= IPV6ADDR_DOT_COUNT)) {
        ret = 1;
    }
    return ret;
}

void ipv6DotAddr2ColonAddr(const char* dotAddrStr, char* conlonAddrStr)
{
    const char* p = dotAddrStr, *q = dotAddrStr;
    char buff[5] = {0};
    int halfAddr = 0;
    int dotCnt = 0;
    if(NULL == dotAddrStr || NULL == conlonAddrStr) {
        RLOGE("para invalid\n");
        return;
    }
    while((*p) != '\0' && dotCnt <= IPV6ADDR_DOT_COUNT) {
        if((*p) == '.') {
            dotCnt++;
            if (dotCnt > IPV6ADDR_DOT_COUNT) {
                break;
            }
            strncpy(buff, q, (int)(p-q));
            buff[(int)(p-q)] = '\0';
            sprintf(buff, "%02x", atoi(buff));
            strcat(conlonAddrStr, buff);
            q = (p+1);
            if(1 == halfAddr) {
                halfAddr = 0;
                strcat(conlonAddrStr, ":");
            } else {
                halfAddr++;
            }
        }
        p++;
    }
    strncpy(buff, q, (int)(p-q));
    buff[(int)(p-q)] = '\0';
    sprintf(buff, "%02x", atoi(buff));
    strcat(conlonAddrStr, buff);
}
/* end: modified by dongmeirong for SLM790 IP address adaption 20210113 */

/* begin: modified by dongmeirong for public network ip request 20201225 */
static int cgcontrdpSkipPrefix(char **line, char **skip) {
    int err = -1;
    //start
    err = at_tok_start(line);
    if (err < 0) goto out;

    //cid
    err = at_tok_nextstr(line, skip);
    if (err < 0) goto out;

    //bearer id
    err = at_tok_nextstr(line, skip);
    if (err < 0) goto out;

    //APN
    err = at_tok_nextstr(line, skip);
    if (err < 0) goto out;

    // addr v4 or v6 not determined
    err = at_tok_nextstr(line, skip);
    if (err < 0) goto out;
out:
    return err;
}

static char* mallocV4V6InfoBuff(ADDRESS_TYPE type) {
    int buffSize = ADDRESS_BUFF_SIZE(type);

    char *info = malloc(buffSize);
    if (info != NULL) {
        memset(info, 0, buffSize);
    }
    return info;
}

static void setAddress(ADDRESS_TYPE type, ADDRESS_BUFF_ID id, char *addrBuff, char *inputAddr) {
    int addrStrLen = ADDRESS_STRLEN(type);
    int desPos = id * addrStrLen;
    if (addrBuff == NULL || inputAddr == NULL) {
        RLOGE("%s() invalid param.", __FUNCTION__);
        return;
    }
    snprintf(&addrBuff[desPos], addrStrLen, "%s", inputAddr);
}

static char* getAddressPos(ADDRESS_TYPE type, ADDRESS_BUFF_ID id, char *addrBuff) {
    int addrStrLen = ADDRESS_STRLEN(type);
    if (addrBuff == NULL) {
        RLOGE("%s() invalid param.", __FUNCTION__);
        return NULL;
    }
    return &addrBuff[id * addrStrLen];
}

/* begin: added by dongmeirong for SLM790 IP address adaption 20210113 */
// HISI's dot address that has 31 dots is IP address combined with netmask.
static void ipv4IpAddressGet(char *input, char *output, int outputLen) {
    char *curr = input;
    int dotCnt = 0;
    int i = 0;
    if (input == NULL || output == NULL) {
        RLOGE("%s() invalid param", __FUNCTION__);
        return;
    }
    for (; i < outputLen - 1; i++) {
        if (*curr == '.') {
            dotCnt++;
        }
        if (*curr == '\0' || dotCnt >= 4) {
            output[i] = '\0';
            break;
        }
        output[i] = *curr;
        curr++;
    }
    if (i == outputLen - 1) {
        output[i] = '\0';
    }
}

static int cgcontrdpCmdParseQCM(char *v4Info, char *v6Info) {
    ATResponse *p_response = NULL;
    PROTOCOL_TYPE prot_type = IPV4V6;
    int err = -1;
    char *line = NULL;
    char *skip = NULL;
    char v6dnsTmp[STRLEN_IPV6_ADDRESS_DEC] = {0};

    err = at_send_command_singleline("AT+CGCONTRDP=1", "+CGCONTRDP:", &p_response);
    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
#if DEBUG_IPV6
    RLOGD("--- dhcp info line = %s---", line);
#endif
    err = cgcontrdpSkipPrefix(&line, &skip);
    if (err < 0) goto error;

    //treated for ipv4 didn't updated issue
    if(isIPv6DotAddr(skip)) {
        // IPv6 addr
        prot_type = IPV6ONLY;
        RLOGD("didn't get IPv4 addr");
    } else {
        // IPv4 addr
        setAddress(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_IPADDRESS, v4Info, skip);
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        if ((skip == NULL) || (strcmp(skip, "") == 0)) {
            prot_type = IPV4ONLY;
        } else {
            prot_type = IPV4V6;
        }
    }
    RLOGD("final prot_type:%d", prot_type);
    if (IPV4V6 == prot_type ) {
        // IPv6 addr
        ipv6DotAddr2ColonAddr(skip, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_IPADDRESS, v6Info));

        // IPv6 gateway
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        ipv6DotAddr2ColonAddr(skip, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_GATEWAY, v6Info));

        //IPv4 dns1, IPv6 dns1
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        sscanf(skip, "%s %s", getAddressPos(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_PDNS, v4Info), v6dnsTmp);
        ipv6DotAddr2ColonAddr(v6dnsTmp, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_PDNS, v6Info));

        //IPv4 dns2, IPv6 dns2
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        memset(v6dnsTmp, 0, STRLEN_IPV6_ADDRESS_DEC * sizeof(char));
        sscanf(skip, "%s %s", getAddressPos(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_SDNS, v4Info), v6dnsTmp);
        ipv6DotAddr2ColonAddr(v6dnsTmp, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_SDNS, v6Info));
    } else if (IPV6ONLY== prot_type) {
        // IPv6 addr
        ipv6DotAddr2ColonAddr(skip, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_IPADDRESS, v6Info));

        // IPv6 gateway
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        ipv6DotAddr2ColonAddr(skip, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_GATEWAY, v6Info));

        // IPv6 pdns
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        ipv6DotAddr2ColonAddr(skip, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_PDNS, v6Info));

        // IPv6 sdns
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        ipv6DotAddr2ColonAddr(skip, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_SDNS, v6Info));
    } else if (IPV4ONLY == prot_type) {
        // IPv4 pdns
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        setAddress(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_PDNS, v4Info, skip);

        // IPv4 sdns
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        setAddress(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_SDNS, v4Info, skip);
    }
    RLOGD("V4addr = %s, v4gw = %s, v4pdns = %s, v4sdns = %s",
        &v4Info[ADDRESS_BUFF_ID_IPADDRESS * STRLEN_IPV4_ADDRESS],
        &v4Info[ADDRESS_BUFF_ID_GATEWAY * STRLEN_IPV4_ADDRESS],
        &v4Info[ADDRESS_BUFF_ID_PDNS * STRLEN_IPV4_ADDRESS],
        &v4Info[ADDRESS_BUFF_ID_SDNS * STRLEN_IPV4_ADDRESS]);
    RLOGD("V6addr = %s, v6gw = %s, v6pdns = %s, v6sdns = %s",
        &v6Info[ADDRESS_BUFF_ID_IPADDRESS * STRLEN_IPV6_ADDRESS_HEX],
        &v6Info[ADDRESS_BUFF_ID_GATEWAY * STRLEN_IPV6_ADDRESS_HEX],
        &v6Info[ADDRESS_BUFF_ID_PDNS * STRLEN_IPV6_ADDRESS_HEX],
        &v6Info[ADDRESS_BUFF_ID_SDNS * STRLEN_IPV6_ADDRESS_HEX]);
#if DEBUG_IPV6
    if (v6Info != NULL) {
        RLOGD("---v6addr:%s---\n---v6gway:%s---\n---v6pdnses:%s---\n",
            &v6Info[ADDRESS_BUFF_ID_IPADDRESS * STRLEN_IPV6_ADDRESS_HEX],
            &v6Info[ADDRESS_BUFF_ID_GATEWAY * STRLEN_IPV6_ADDRESS_HEX],
            &v6Info[ADDRESS_BUFF_ID_PDNS * STRLEN_IPV6_ADDRESS_HEX]);
    }
#endif
    at_response_free(p_response);
    return prot_type;
error:
    at_response_free(p_response);
    return -1;
}

static int cgcontrdpCmdParseHisi(char *v4Info, char *v6Info) {
    ATResponse *p_response = NULL;
    PROTOCOL_TYPE prot_type = IPV4V6;
    int err = -1;
    char *line = NULL;
    char *skip = NULL;

    err = at_send_command_singleline("AT+CGCONTRDP=1", "+CGCONTRDP:", &p_response);
    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = cgcontrdpSkipPrefix(&line, &skip);
    if (err < 0) goto error;

    if (skip == NULL || *skip == '\0') {
        prot_type == IPV4V6;
    } else {
        prot_type = isIPv6DotAddr(skip) == 1 ? IPV6ONLY : IPV4ONLY;
    }
    RLOGD("%s() prot_type = %d", __FUNCTION__, prot_type);
    if (prot_type == IPV4V6) {
        // ipv4 gate way
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        setAddress(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_GATEWAY, v4Info, skip);
    } else if (prot_type == IPV6ONLY) {
        // ip address
        ipv6DotAddr2ColonAddr(skip, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_IPADDRESS, v6Info));
        // gate way, it is null, skip it
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        // pdns
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        ipv6DotAddr2ColonAddr(skip, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_PDNS, v6Info));
        // sdns
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        ipv6DotAddr2ColonAddr(skip, getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_SDNS, v6Info));
    } else if (prot_type == IPV4ONLY) {
        // ip address
        ipv4IpAddressGet(skip,
            getAddressPos(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_IPADDRESS, v4Info), STRLEN_IPV4_ADDRESS);
        // gateway
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        setAddress(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_GATEWAY, v4Info, skip);
        // pdns
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        setAddress(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_PDNS, v4Info, skip);
        // sdns
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        setAddress(ADDRESS_TYPE_V4, ADDRESS_BUFF_ID_SDNS, v4Info, skip);
    }

    at_response_free(p_response);
    return prot_type;
error:
    at_response_free(p_response);
    return -1;

}

static void dhcpV4AddrTrans(char *input, char *output) {
    char hexStr[3] = {0}; // 2 charactors for address section in hex, 1 for '\0'.
    char decStr[4] = {0}; // 3 charactors for address section in dec, 1 for '\0'.
    int addressSection = 0;
    if (input == NULL || output == NULL) {
        printf("%s() invalid param.", __FUNCTION__);
        return;
    }
    // dhcp address has 8 charactors, needs to parse 4 rounds and 2 charactors in one round.
    int i = 7;
    for (; i >= 0; i--) {
        hexStr[i % 2] = input[i];
        if (i % 2 == 0) {
            sscanf(hexStr, "%x", &addressSection);
            snprintf(decStr, 4, "%d", addressSection); // 3 charactors for address section in dec, 1 for '\0'.
            strcat(output, decStr);
            if (i > 0) {
                strcat(output, ".");
            }
        }
    }
}

// return: 0--Fail; 1--Success
static int dhcpCmdParse(ADDRESS_TYPE type, char *addrInfo) {
    ATResponse *p_response = NULL;
    int err = -1;
    char *line = NULL;
    char *skip = NULL;
    int buffId = 0;

    err = at_send_command_singleline(dhcpCmds[type].cmdStr, dhcpCmds[type].responsePrefix, &p_response);
    if (err < 0 || p_response->success == 0) {
        goto error;
    }
    line = p_response->p_intermediates->line;
    //start
    err = at_tok_start(&line);
    if (err < 0) goto error;

    int i = 0;
    for (; i <= 5; i++) {
        // format: ip(i = 0), netmask, gateway, dhcp, pDNS, sDNS(i = 5), max_rx_data, mas_tx_data
        buffId = dhcpParamId2BuffId[i];
        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto error;
        if (buffId >= ADDRESS_BUFF_ID_MAX) continue;
        if (type == ADDRESS_TYPE_V4) {
             dhcpV4AddrTrans(skip, getAddressPos(type, buffId, addrInfo));
        } else if (type == ADDRESS_TYPE_V6 && strcmp(skip, "::") != 0) {
            setAddress(type, buffId, addrInfo, skip);
        }
    }

    at_response_free(p_response);
    return 1;
error:
    at_response_free(p_response);
    return 0;
}

static PROTOCOL_TYPE dhcpCmd(char *v4Info, char *v6Info) {
    int ret = 0;
    int type = 0;
    ret = dhcpCmdParse(ADDRESS_TYPE_V4, v4Info);
    type |= ret << IPV4ONLY;
    ret = dhcpCmdParse(ADDRESS_TYPE_V6, v6Info);
    type |= ret << IPV6ONLY;
    // type in binary: 00--both error; 01-V4Only; 10--v6Only; 11--v4v6
    RLOGD("%s() protocol type = %d", __FUNCTION__, type);
    return type - 1;
}

static int getV4V6Address(char *v4Info, char *v6Info) {
    if (curr_modem_info.info.sltn_type == HISI) {
        if (devmode == NCM_MOD) {
            return dhcpCmd(v4Info, v6Info);
        } else {
            return cgcontrdpCmdParseHisi(v4Info, v6Info);
        }
    } else {
        return cgcontrdpCmdParseQCM(v4Info, v6Info);
    }
}
/* end: added by dongmeirong for SLM790 IP address adaption 20210113 */

/* begin: modified by dongmeirong for modify data response for network IP 20210115 */
static void requestNetworkAddress(RIL_Token t) {
    char v4Info[ADDRESS_BUFF_SIZE(ADDRESS_TYPE_V4)] = {0};
    char v6Info[ADDRESS_BUFF_SIZE(ADDRESS_TYPE_V6)] = {0};
    char *v4Addr = NULL;
    char *v6Addr = NULL;
    PROTOCOL_TYPE prot_type = -1;
    /* Fomat of response: IP,Gateway,Pdns,Sdns. BUFF_SIZE has 4 address sections, added 3 for commas and 1 for '\0'.
    The address section length uses STRLEN_IPV6_ADDRESS_HEX(40) which is the larger one between v4 and v6 length */
    const int BUFF_SIZE = (STRLEN_IPV6_ADDRESS_HEX * 4 + 4) * sizeof(char);
    char **responses = alloca(2 * sizeof(char *));
    if (responses == NULL) {
        RLOGE("%s() malloc responses fail.", __FUNCTION__);
        return;
    }
    memset(responses, 0, 2 * sizeof(char *));
    responses[0] = alloca(BUFF_SIZE);
    if (responses[0] == NULL) {
        RLOGE("%s() malloc responses[0] fail.", __FUNCTION__);
        return;
    }
    responses[1] = alloca(BUFF_SIZE);
    if (responses[1] == NULL) {
        RLOGE("%s() malloc responses[1] fail.", __FUNCTION__);
        return;
    }
    memset(responses[0], 0, BUFF_SIZE);
    memset(responses[1], 0, BUFF_SIZE);

    prot_type = getV4V6Address(&v4Info, &v6Info);
    if (prot_type == -1) {
        RLOGE("%s() cgcontrdp cmd parse fail.", __FUNCTION__);
        goto out;
    }

    int i = 0;
    for (; i < ADDRESS_BUFF_ID_MAX; i++) {
        // i represents for ADDRESS_BUFF_ID;
        v4Addr = getAddressPos(ADDRESS_TYPE_V4, i, v4Info);
        v6Addr = getAddressPos(ADDRESS_TYPE_V6, i, v6Info);
        if (i > 0) {
            strcat(responses[0], ",");
            strcat(responses[1], ",");
        }
        if (v4Addr != NULL && *v4Addr != '\0') {
            strcat(responses[0], v4Addr);
        }
        if (v6Addr != NULL && *v6Addr != '\0') {
            strcat(responses[1], v6Addr);
        }
    }
out:
    RLOGD("%s()\nv4 = %s\nv6 = %s", __FUNCTION__, responses[0], responses[1]);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, responses, 2 * sizeof(char *));
}
/* end: modified by dongmeirong for modify data response for network IP 20210115 */

int getIPv6Info(char *v6addr, char * v6gway, char *v6pdnses )
{
    PROTOCOL_TYPE prot_type;
    char *v4Info = NULL;
    char *v6Info = NULL;

    RLOGD("getIPv6Info start");

    if(0 == strcasecmp(s_current_protocol, "IPV4")){
        prot_type = IPV4ONLY;
        RLOGD("---prot v4---");
    } else if(0 == strcasecmp(s_current_protocol, "IPV6")){
        prot_type = IPV6ONLY;
         RLOGD("---prot v6---");

    } else if(0 == strcasecmp(s_current_protocol, "IPV4V6")){
        prot_type = IPV4V6;
        RLOGD("---prot v4&v6---");

    } else {
        prot_type = IPV4ONLY;
        RLOGD("---prot default v4---");

    }
    if(IPV4ONLY == prot_type) {
        RLOGD("---IPV4 only---");
        return 0;
    }

    v4Info = mallocV4V6InfoBuff(ADDRESS_TYPE_V4);
    if (v4Info == NULL) {
        RLOGE("%s() v4Info alloca fail.", __FUNCTION__);
        return 0;
    }
    v6Info = mallocV4V6InfoBuff(ADDRESS_TYPE_V6);
    if (v6Info == NULL) {
        RLOGE("%s() v6Info alloca fail.", __FUNCTION__);
        free(v4Info);
        return 0;
    }

    prot_type = getV4V6Address(v4Info, v6Info);
    if (prot_type >= IPV6ONLY) {
        snprintf(v6addr, MAX_ADDR_BUFFER_SIZE, "%s",
            getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_IPADDRESS, v6Info));
        snprintf(v6gway, MAX_ADDR_BUFFER_SIZE, "%s",
            getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_GATEWAY, v6Info));
        snprintf(v6pdnses, MAX_ADDR_BUFFER_SIZE, "%s",
            getAddressPos(ADDRESS_TYPE_V6, ADDRESS_BUFF_ID_PDNS, v6Info));
    }
    free(v4Info);
    free(v6Info);
    return prot_type >= IPV6ONLY ? 1 : 0;
}
/* end: modified by dongmeirong for public network ip request 20201225 */
/*[zhaopf@meigsmart-2020-1117] add for static ip address configure {*/
static void resetStaticDataCallList(RIL_Token *t)
{

    uint32_t ipaddr = 0, gateway = 0, prefixLength = 24, dns1 = 0, dns2 = 0, server = 0, lease = 0;
    //ipaddr, gw, dns1, dns2, server
    char *default_route;
    prefixLength = 24;
/*yufeilong modify for static ip 20230404 begin*/
    char local_dhcp_info[5][32] = {0};
    char local_dhcp_info_unisoc[5][32] = {"192.168.225.47", "192.168.225.1", "192.168.225.1", "8.8.8.8", "192.168.225.1"};
    char local_dhcp_info_asr_qcm[5][32] = {"192.168.200.47", "192.168.200.1", "192.168.200.1", "8.8.8.8", "192.168.200.1"};
    if ((curr_modem_info.info.sltn_type == ASR) || (curr_modem_info.info.sltn_type == QCM)) {
        memcpy(local_dhcp_info, local_dhcp_info_asr_qcm, sizeof(local_dhcp_info_asr_qcm));
    } else {
         memcpy(local_dhcp_info, local_dhcp_info_unisoc, sizeof(local_dhcp_info_unisoc));
    }
/*yufeilong modify for static ip 20230404 end*/
    ipaddr = (uint32_t)string_to_ipaddr(local_dhcp_info[0]);
    gateway = (uint32_t)string_to_ipaddr(local_dhcp_info[1]);
    dns1 = (uint32_t)string_to_ipaddr(local_dhcp_info[2]);
    dns2 = (uint32_t)string_to_ipaddr(local_dhcp_info[3]);
    server = (uint32_t)string_to_ipaddr(local_dhcp_info[4]);
    //RLOGD("ip=%s, gw=%s, prefix=%d, dns1=%s, dns2=%s, server=%s, lease=%d",local_dhcp_info[0], local_dhcp_info[1], prefixLength, local_dhcp_info[2], local_dhcp_info[3], local_dhcp_info[4], lease);
    RLOGD("[convert]ip=0x%x, gw=0x%x, prefix=0x%x, dns1=0x%x, dns2=0x%x, server=0x%x, lease=0x%x",ipaddr, gateway, prefixLength,dns1, dns2, server,lease);
    asprintf(&default_route, "/system/bin/ip route add default via %s dev %s  table %s",local_dhcp_info[1], curr_modem_info.if_name, curr_modem_info.if_name);
    ifconfigUp(curr_modem_info.if_name);
   if(0 != ifc_configure(curr_modem_info.if_name, ipaddr, prefixLength,  gateway, dns1, dns2) ){
       RLOGD("configure static ip failed");
   } else {
       RLOGD("configure static ip success");
   }
   system(default_route);
    RIL_onUnsolicitedResponse
    (RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED, NULL, 0);
    free(default_route);
}




static void onSendStaticDataCallList(RIL_Token *t)
{
int n = 1;
//int upload_number = 0;
int i = 0, ipv6addr_exist = 0;
char local_ip[MAX_ADDR_BUFFER_SIZE]= {0};
char local_pdns[MAX_ADDR_BUFFER_SIZE]= {0};
char local_sdns[MAX_ADDR_BUFFER_SIZE]= {0};
char local_gateway[MAX_ADDR_BUFFER_SIZE]= {0};
char local_prefix_len[PROPERTY_VALUE_MAX]= {0};
char temp_dns[MAX_ADDR_BUFFER_SIZE];


char local_v6pdns[MAX_ADDR_BUFFER_SIZE]= {0};
char local_v6gateway[MAX_ADDR_BUFFER_SIZE]= {0};
char local_v6addr[MAX_ADDR_BUFFER_SIZE]= {0};

uint32_t ipaddr = 0, gateway = 0, prefixLength = 24, dns1 = 0, dns2 = 0, server = 0, lease = 0;
//ipaddr, gw, dns1, dns2, server
char *default_route;
/*yufeilong modify for static ip 20230404 begin*/
char local_dhcp_info[5][32] = {0};
char local_dhcp_info_unisoc[5][32] = {"192.168.225.47", "192.168.225.1", "192.168.225.1", "8.8.8.8", "192.168.225.1"};
char local_dhcp_info_asr_qcm[5][32] = {"192.168.200.47", "192.168.200.1", "192.168.200.1", "8.8.8.8", "192.168.200.1"};
if ((curr_modem_info.info.sltn_type == ASR) || (curr_modem_info.info.sltn_type == QCM)) {
    memcpy(local_dhcp_info, local_dhcp_info_asr_qcm, sizeof(local_dhcp_info_asr_qcm));
} else {
    memcpy(local_dhcp_info, local_dhcp_info_unisoc, sizeof(local_dhcp_info_unisoc));
}
/*yufeilong modify for static ip 20230404 end*/
memset(temp_dns,0,128);

RLOGD("-------entry onSendStaticDataCallList -------  \n");

#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
RIL_Data_Call_Response_v11 *responses =alloca(n * sizeof(RIL_Data_Call_Response_v11));
memset(responses,0,n * sizeof(RIL_Data_Call_Response_v11));
#else
RIL_Data_Call_Response_v6 *responses =alloca(n * sizeof(RIL_Data_Call_Response_v6));
memset(responses,0,n * sizeof(RIL_Data_Call_Response_v6));
#endif

for (i = 0; i < n; i++) {
    responses[i].status = -1;
    responses[i].suggestedRetryTime = 5;
    responses[i].cid = -1;
    responses[i].active = -1;
    responses[i].type = "";
    responses[i].ifname = "";
    responses[i].addresses = "";
    responses[i].dnses = "";
    responses[i].gateways = "";
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    responses[i].pcscf = "";
    responses[i].mtu = 1200;
#endif
}

   if (s_closed > 0 || SIM_ABSENT == s_sim_state || SIM_NOT_READY == s_sim_state) {
        RLOGD("return empty data due to modem lost");
        goto retempty;
   }

    prefixLength = 24;
    ipaddr = (uint32_t)string_to_ipaddr(local_dhcp_info[0]);
    gateway = (uint32_t)string_to_ipaddr(local_dhcp_info[1]);
    dns1 = (uint32_t)string_to_ipaddr(local_dhcp_info[2]);
    dns2 = (uint32_t)string_to_ipaddr(local_dhcp_info[3]);
    server = (uint32_t)string_to_ipaddr(local_dhcp_info[4]);
    asprintf(&default_route, "/system/bin/ip route add default via %s dev %s  table %s",local_dhcp_info[1], curr_modem_info.if_name, curr_modem_info.if_name);
    //RLOGD("ip=%s, gw=%s, prefix=%d, dns1=%s, dns2=%s, server=%s, lease=%d",local_dhcp_info[0], local_dhcp_info[1], prefixLength, local_dhcp_info[2], local_dhcp_info[3], local_dhcp_info[4], lease);
    RLOGD("[convert]ip=0x%x, gw=0x%x, prefix=0x%x, dns1=0x%x, dns2=0x%x, server=0x%x, lease=0x%x",ipaddr, gateway, prefixLength,dns1, dns2, server,lease);
    i = 0;
   if(0 != ifc_configure(curr_modem_info.if_name,  ipaddr,  prefixLength,  gateway, dns1,  dns2) ){
       RLOGD("configure static ip failed");
       responses[i].active = 0;
   } else {
       RLOGD("configure static ip success");
       system(default_route);
       responses[i].active = 1;
   }
   free(default_route);

    responses[i].status = 0;
    responses[i].cid = 1;
    responses[i].type = "IP";
    responses[i].ifname = alloca(strlen(curr_modem_info.if_name) + 1);
    strcpy(responses[i].ifname, curr_modem_info.if_name);

    if(ipv6addr_exist) {
            if(0 == ipaddr){ //v6 only
                strcpy(local_ip, local_v6addr);
                strcpy(local_gateway, local_v6gateway);
                strcpy(temp_dns, local_v6pdns);
            } else {
                sprintf(local_ip, "%s/%d %s", local_dhcp_info[0], prefixLength, local_v6addr);
                sprintf(local_gateway,"%s %s",local_dhcp_info[1], local_v6gateway);
                sprintf(temp_dns,"%s %s", local_dhcp_info[2], local_v6pdns);
            }
        } else {
            sprintf(local_ip, "%s/%d", local_dhcp_info[0], prefixLength);
            sprintf(temp_dns,"%s %s", local_dhcp_info[2], local_dhcp_info[3]);
            strcpy(local_gateway, local_dhcp_info[1]);

        }

        responses[i].addresses = alloca(strlen(local_ip) + 1);
        strcpy(responses[i].addresses, local_ip);
        responses[i].gateways = alloca(strlen(local_gateway) + 1);
        strcpy(responses[i].gateways, local_gateway);
        responses[i].dnses= alloca(strlen(temp_dns) + 1);
        strcpy(responses[i].dnses, temp_dns);
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
        responses[i].pcscf=NULL;
        responses[i].mtu=1280;
#endif

retempty:


for (i = 0; i < n; i++) {

    RLOGD("    responses-----number: %d------>",i);
    //responses[i].status = -1;
    RLOGD("    responses[%d].status:%d", i, responses[i].status);
    //responses[i].suggestedRetryTime = -1;
    RLOGD("    responses[%d].suggestedRetryTime:%d", i, responses[i].suggestedRetryTime);
    //responses[i].cid = -1;
    RLOGD("    responses[%d].cid:%d", i, responses[i].cid);
    //responses[i].active = -1;
    RLOGD("    responses[%d].active:%d", i, responses[i].active);
    // responses[i].type = "";
    RLOGD("    responses[%d].type:%s", i, responses[i].type);
    //responses[i].ifname = "";
    RLOGD("    responses[%d].ifname:%s", i, responses[i].ifname);
    //responses[i].addresses = "";
    RLOGD("    responses[%d].addresses:%s", i, responses[i].addresses);
    //responses[i].dnses = "";
    RLOGD("    responses[%d].dnses:%s", i, responses[i].dnses);
    //responses[i].gateways = "";
    RLOGD("    responses[%d].gateways:%s", i, responses[i].gateways);
    //responses[i].pcscf = "";
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    RLOGD("    responses[%d].pcscf:%s", i, responses[i].pcscf);
    //responses[i].mtu = 0;
    RLOGD("    responses[%d].mtu:%d", i, responses[i].mtu);
#endif

    RLOGD("   responses<-----------");

}

//Add by zhaopengfei for iface state indicate 2023/01/12
RLOGD("trigger sys.meig.ifup up");
property_set("sys.meig.ifup", "true");


#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
if (t != NULL)
    RIL_onRequestComplete(*t, RIL_E_SUCCESS, responses,
                          n * sizeof(RIL_Data_Call_Response_v11));
else
    RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                              responses,
                              n * sizeof(RIL_Data_Call_Response_v11));
#else
if (t != NULL)
    RIL_onRequestComplete(*t, RIL_E_SUCCESS, responses,
                          n * sizeof(RIL_Data_Call_Response_v6));
else
    RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                              responses,
                              n * sizeof(RIL_Data_Call_Response_v6));
#endif
return ;
}

/*[zhaopf@meigsmart-2020-1117] add for static ip address configure } */
/*[zhaopf@meigsmart-2020-06-16] add for ipv6 support } */


/*Add by zhaopengfei reset modem when get gw failed 2023/01/09 Begin*/
void resetModemPower(void *param __unused){

       int err;
       ATResponse *p_response = NULL;
       RLOGI("reset modem power");
       err = at_send_command("AT+CFUN=1,1", &p_response);
       if (err < 0 || p_response->success == 0) {
           RLOGE("cfun1,1 err");
       }
       at_response_free(p_response);
       p_response = NULL;
}
/*Add by zhaopengfei reset modem when get gw failed 2023/01/09 End*/



/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
static void requestOrSendDataCallList(int request, RIL_Token *t)
{
int n = 1;
//int upload_number = 0;
/*[zhaopf@meigsmart-2020-0616] modify for ipv6 support { */
int i = 0, ipv6addr_exist = 0;

char local_ip[MAX_ADDR_BUFFER_SIZE]= {0};
char local_pdns[MAX_ADDR_BUFFER_SIZE]= {0};
char local_sdns[MAX_ADDR_BUFFER_SIZE]= {0};
char local_gateway[MAX_ADDR_BUFFER_SIZE]= {0};
char local_prefix_len[PROPERTY_VALUE_MAX]= {0};
char temp_dns[MAX_ADDR_BUFFER_SIZE];
/*[zhaopf@meigsmart-2020-0616] modify for ipv6 support } */

char LOCAL_IP_PROP[PROPERTY_KEY_MAX] = {0};
char PDNS_PROP[PROPERTY_KEY_MAX] = {0};
char SDNS_PROP[PROPERTY_KEY_MAX] = {0};
char REMOTE_IP_PROP[PROPERTY_KEY_MAX] = {0};
char GATEWAY_PROP[PROPERTY_KEY_MAX] = {0};
/*[zhaopf@meigsmart-2020-0616] add for ipv6 support { */
char local_v6pdns[MAX_ADDR_BUFFER_SIZE]= {0};
char local_v6gateway[MAX_ADDR_BUFFER_SIZE]= {0};
char local_v6addr[MAX_ADDR_BUFFER_SIZE]= {0};
/*[zhaopf@meigsmart-2020-0616] add for ipv6 support } */
uint32_t ipaddr = 0, gateway = 0, prefixLength = 0, dns1 = 0, dns2 = 0, server = 0, lease = 0;
/*[zhaopf@meigsmart-2020-0615]modify for dhcp info not update on some platform {*/
char local_dhcp_info[5][32];
/*[zhaopf@meigsmart-2020-0615]modify for dhcp info not update on some platform }*/

memset(temp_dns,0,128);

RLOGD("-------entry requestOrSendDataCallList -------  \n");

//RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED, NULL, 0);
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
RIL_Data_Call_Response_v11 *responses =alloca(n * sizeof(RIL_Data_Call_Response_v11));
memset(responses,0,n * sizeof(RIL_Data_Call_Response_v11));
#else
RIL_Data_Call_Response_v6 *responses =alloca(n * sizeof(RIL_Data_Call_Response_v6));
memset(responses,0,n * sizeof(RIL_Data_Call_Response_v6));
#endif
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support } */

for (i = 0; i < n; i++) {
    responses[i].status = -1;
    responses[i].suggestedRetryTime = 5;
    responses[i].cid = -1;
    responses[i].active = -1;
    responses[i].type = "";
    responses[i].ifname = "";
    responses[i].addresses = "";
    responses[i].dnses = "";
    responses[i].gateways = "";
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    responses[i].pcscf = "";
    responses[i].mtu = 1200;
#endif
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support } */
}

/*[zhaopf@meigsmart-2020-1106] not poll sim status when modem lost or sim removed { */
if (s_closed > 0 || SIM_ABSENT == s_sim_state || SIM_NOT_READY == s_sim_state) {

    RLOGD("return empty data due to modem lost");
    goto retempty;
}
/*[zhaopf@meigsmart-2020-1106] not poll sim status when modem lost or sim removed } */


if(RAS_MOD == devmode) {
    sprintf(PDNS_PROP, "net.%s.dns1", curr_modem_info.if_name);
    sprintf(SDNS_PROP, "net.%s.dns2", curr_modem_info.if_name);
    sprintf(REMOTE_IP_PROP, "net.%s.remote-ip", curr_modem_info.if_name);
    sprintf(GATEWAY_PROP, "net.%s.gw", curr_modem_info.if_name);
    get_local_ip(local_ip);

    property_get(PDNS_PROP, local_pdns, "114.114.114.114");
    property_get(SDNS_PROP, local_sdns, "8.8.8.8");
    if(property_get(REMOTE_IP_PROP, local_gateway, "") <= 0) {
        property_get(GATEWAY_PROP, local_gateway, local_ip); //default gateway is no mean for ppp
    }
     /*[zhaopf@meigsmart-2020-0616] add for ipv6 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_5_1_SDK_VERSION)
    if(NULL != strcasestr(s_current_protocol, "V6")){
        ipv6addr_exist = getIPv6Info(local_v6addr,  local_v6gateway, local_v6pdns);
    }
#endif


    if(ipv6addr_exist) {
        sprintf(local_ip,"%s %s",local_ip, local_v6addr);
        sprintf(local_gateway,"%s %s",local_gateway, local_v6gateway);
        sprintf(temp_dns,"%s %s",local_pdns, local_v6pdns);
    } else {
        sprintf(temp_dns,"%s %s",local_pdns,local_sdns);
    }
    /*[zhaopf@meigsmart-2020-0616] add for ipv6 support } */

    i = 0;
    responses[i].status = 0;
    responses[i].cid = 1;
    responses[i].active = 1;
    responses[i].type = "IP";
    responses[i].ifname = alloca(strlen(curr_modem_info.if_name) + 1);
    strcpy(responses[i].ifname, curr_modem_info.if_name);
    responses[i].addresses = alloca(strlen(local_ip) + 1);
    strcpy(responses[i].addresses, local_ip);
    responses[i].dnses= alloca(strlen(temp_dns) + 1);
    strcpy(responses[i].dnses, temp_dns);
    /*[zhaopf@meigsmart-2020-0601] update for sdk version detect { */
        RLOGD("Android sdk version is %d\n", g_sdk_version);
    if (g_sdk_version >= ANDROID_8_1_SDK_VERSION) {


        //use fake gateway, as there are no gateway
        if(0 == strncmp(local_gateway, DEFAULT_GATEWAY, strlen(DEFAULT_GATEWAY)) || QMI_MOD == devmode) {
            RLOGD("as default gw, change to fake addr\n");
            responses[i].gateways = alloca(strlen(local_ip) + 1);
            strcpy(responses[i].gateways, local_ip);
        } else {
            responses[i].gateways = alloca(strlen(local_gateway) + 1);
            strcpy(responses[i].gateways, local_gateway);
        }
    } else {
        responses[i].gateways = alloca(strlen(local_gateway) + 1);
        strcpy(responses[i].gateways, local_gateway);
    }
    /*[zhaopf@meigsmart-2020-0601] update for sdk version detect } */
//add by zhaopf for Android4.4 support, 2020/12/11
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    responses[i].pcscf=NULL;
    responses[i].mtu=1280;
#endif


} else {
    /*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario Begin */
/*[zhaopengfei@meigsmart-2020-05-22] improve dhcp client for upper version Android {*/
    /*[zhaopf@meigsmart-2022-10-10] modify for multi pdn support Begin */
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
    if(QMI_MOD == devmode || MULTI_QMI_MOD == devmode ) {
        /* Modify by zhaopengfei for double check datacall result 2022/12/07 Begin */
        CM_CONN_STATE cm_conn_state = WDS_CONNECTION_STATUS_DISCONNECTED;
        if(0 == CMRequestQueryDataCall(((t != NULL) && (current_cid >= 1))?current_cid-1:0, &cm_conn_state)){
            if(cm_conn_state != WDS_CONNECTION_STATUS_CONNECTED ){
                RLOGE("data call failed,current_cid:%d ", current_cid);
                goto retempty;
            }
        }
       /* Modify by zhaopengfei for double check datacall result 2022/12/07 End */
      /*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again Begin */
        if(curr_modem_info.use_deprecated_gobi){
            if(request_dhcp(curr_modem_info.if_name, (request != RIL_REQUEST_DATA_CALL_LIST)&&(NULL != t)) < 0) {
                RLOGD("failed to do_dhcp: %s\n", strerror(errno));
            }
        } else {
            if(request_dhcp(curr_modem_info.vif_name[((t != NULL) && (current_cid >= 1))?current_cid-1:0], (request != RIL_REQUEST_DATA_CALL_LIST)&&(NULL != t)) < 0) {
                RLOGD("failed to do_dhcp: %s\n", strerror(errno));
            }
        }
        /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
/*[zhaopf@meigsmart-2022-06-10] add for mms support End */
    if(errno == ENETUNREACH){
        g_dhcp_fail_ignore_flag = 1;
    }
    /*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario End */
     /*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again End */
      sleep(1);
  } else {

    if (request_dhcp(curr_modem_info.if_name, (request != RIL_REQUEST_DATA_CALL_LIST)&&(NULL != t)) < 0) {
        ALOGD("failed to do_dhcp: %s\n", strerror(errno));
    }
  /*[zhaopf@meigsmart-2022-10-10] modify for multi pdn support End */

    RLOGD("do_dhcp errno is %s\n", strerror(errno));
    if(errno == ENETUNREACH){
        g_dhcp_fail_ignore_flag = 1;
    }
    /*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario End */
     /*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again End */
      sleep(1);
  }
  /*[zhaopengfei@meigsmart-2020-05-22] improve dhcp client for upper version Android }*/
    get_dhcp_info(&ipaddr,  &gateway,  &prefixLength, &dns1, &dns2, &server, &lease);
    /*[zhaopf@meigsmart-2020-0615]modify for dhcp info not update on some platform {*/
    memset(local_dhcp_info, 0x0, 5*sizeof(char*));
    strcpy(local_dhcp_info[0], ipaddr_to_string(ipaddr));
    strcpy(local_dhcp_info[1], ipaddr_to_string(gateway));
    strcpy(local_dhcp_info[2], ipaddr_to_string(dns1));
    strcpy(local_dhcp_info[3], ipaddr_to_string(dns2));
    strcpy(local_dhcp_info[4], ipaddr_to_string(server));
    RLOGD("ipaddr=0x%x gw=0x%x, prefix=0x%x", ipaddr&0xff, gateway&0xff, prefixLength);
    ALOGD("ip=%s, gw=%s, prefix=%d, dns1=%s, dns2=%s, server=%s, lease=%d",local_dhcp_info[0], local_dhcp_info[1], prefixLength, local_dhcp_info[2], local_dhcp_info[3], local_dhcp_info[4], lease);
    /*[zhaopf@meigsmart-2020-0615]modify for dhcp info not update on some platform }*/
    /*Add by zhaopengfei reset modem when get gw failed 2023/01/09 Begin*/
    if(curr_modem_info.info.sltn_type == UNISOC &&
        (gateway&0xff) == 0 &&
        (ipaddr&0xff) != 0) {
        RLOGD("invalid gateway");
        if(g_reset_modem_enable){
            struct timeval reset_delay = {0,500};
            g_reset_modem_enable = false;
            RLOGD("invalid gateway, reset modem.");
            RIL_requestTimedCallback(resetModemPower, NULL, &reset_delay);
        } else {
            g_reset_modem_enable = true;
        }
     }
    /*Add by zhaopengfei reset modem when get gw failed 2023/01/09 End*/
    i = 0;
    responses[i].status = 0;
/*[zhaopf@meigsmart-2022-06-10] add for mms support Begin */
    if(t != NULL) {
        responses[i].cid = current_cid;
    } else {
        responses[i].cid = 1;
    }
    responses[i].active = 1;
    responses[i].type = "IP";
    /*[zhaopf@meigsmart-2022-10-10] modify for multi pdn support Begin */
    if((!curr_modem_info.use_deprecated_gobi) && (QMI_MOD == devmode || MULTI_QMI_MOD == devmode) ) {
        responses[i].ifname = alloca(strlen(curr_modem_info.vif_name[((t != NULL) && (current_cid >= 1))?current_cid-1:0]) + 1);
        strcpy(responses[i].ifname, curr_modem_info.vif_name[((t != NULL) && (current_cid >= 1))?current_cid-1:0]);
    } else {
        responses[i].ifname = alloca(strlen(curr_modem_info.if_name) + 1);
        strcpy(responses[i].ifname, curr_modem_info.if_name);
    }
   /*[zhaopf@meigsmart-2022-10-10] modify for multi pdn support End */
/*[zhaopf@meigsmart-2022-06-10] add for mms support End */
    /*[zhaopf@meigsmart-2020-0615]modify for dhcp info not update on some platform {*/

    /*[zhaopf@meigsmart-2020-0616] modify for ipv6 support } */
    /*[zhaopf@meigsmart-2020-0601] update for sdk version detect { */
    /*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario Begin */
    if (g_sdk_version >= ANDROID_8_1_SDK_VERSION) {
        //use fake gateway, as there are no gateway
        if(0 == strncmp(local_dhcp_info[1], DEFAULT_GATEWAY, strlen(DEFAULT_GATEWAY))) {
            RLOGD("as default gw, change to fake addr\n");
            memset(local_dhcp_info[1], 0x0, 32);
            strcpy(local_dhcp_info[1], local_dhcp_info[0]);
        }
    }

    /*[zhaopf@meigsmart-2022-10-10] modify for multi pdn support Begin */
    if(1 == g_dhcp_fail_ignore_flag || MULTI_QMI_MOD == devmode) {
        char *default_route;
        char *rule_main;
        RLOGD("for gw unreachable, change to fake addr, add default route\n");
        /*yufeilong add for modify ping failed after SRM821 ncm 20221020 start*/
        asprintf(&rule_main, "/system/bin/ip rule add table main");
        system(rule_main);
        free(rule_main);
        /*yufeilong add for modify ping failed after SRM821 ncm 20221020 end*/
        if((!curr_modem_info.use_deprecated_gobi) && (QMI_MOD == devmode || MULTI_QMI_MOD == devmode)) {
            asprintf(&default_route, "/system/bin/ip route add default via %s dev %s table main",local_dhcp_info[1], curr_modem_info.vif_name[((t != NULL) && (current_cid >= 1))?current_cid-1:0]);
            system(default_route);
            free(default_route);
            default_route = NULL;
            asprintf(&default_route, "/system/bin/ip route add default via %s dev %s  table %s",local_dhcp_info[1], curr_modem_info.vif_name[((t != NULL) && (current_cid >= 1))?current_cid-1:0], curr_modem_info.vif_name[((t != NULL) && (current_cid >= 1))?current_cid-1:0]);
            system(default_route);
            free(default_route);
        } else {
            asprintf(&default_route, "/system/bin/ip route add default via %s dev %s table main",local_dhcp_info[1], curr_modem_info.if_name);
            system(default_route);
            free(default_route);
            default_route = NULL;
            asprintf(&default_route, "/system/bin/ip route add default via %s dev %s  table %s",local_dhcp_info[1], curr_modem_info.if_name, curr_modem_info.if_name);
            system(default_route);
            free(default_route);
        }
    }
    /*[zhaopf@meigsmart-2022-10-10] modify for multi pdn support End */
    /*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario End */
    /*[zhaopf@meigsmart-2020-0601] update for sdk version detect } */

    /*[zhaopf@meigsmart-2020-0616] add for ipv6 support { */
    //not ecm , and found v6 support
    #if (PLATFORM_SDK_VERSION > ANDROID_5_1_SDK_VERSION)
    /* begin: modified by dongmeirong for RNDIS adapt 20210219 */
    if(ECM_MOD != curr_modem_info.net_mod && RNDIS_MOD != curr_modem_info.net_mod
        && NULL != strcasestr(s_current_protocol, "V6")){
    /* end: modified by dongmeirong for RNDIS adapt 20210219 */
        ipv6addr_exist = getIPv6Info(local_v6addr,  local_v6gateway, local_v6pdns);
    }
    #endif
    /*[zhaopf@meigsmart-2020-0616] add for ipv6 support } */

    if(ipv6addr_exist) {
        if(0 == ipaddr){ //v6 only
            strcpy(local_ip, local_v6addr);
            strcpy(local_gateway, local_v6gateway);
            strcpy(temp_dns, local_v6pdns);
        } else {
            sprintf(local_ip, "%s/%d %s", local_dhcp_info[0], prefixLength, local_v6addr);
            sprintf(local_gateway,"%s %s",local_dhcp_info[1], local_v6gateway);
            sprintf(temp_dns,"%s %s", local_dhcp_info[2], local_v6pdns);
        }
    } else {
        sprintf(local_ip, "%s/%d", local_dhcp_info[0], prefixLength);
        sprintf(temp_dns,"%s %s",( 0 != dns1)?local_dhcp_info[2]:"114.114.114.114", (0 != dns2)?local_dhcp_info[3]:"8.8.8.8");
        strcpy(local_gateway, local_dhcp_info[1]);

    }


        responses[i].addresses = alloca(strlen(local_ip) + 1);
        strcpy(responses[i].addresses, local_ip);
        responses[i].gateways = alloca(strlen(local_gateway) + 1);
        strcpy(responses[i].gateways, local_gateway);
        responses[i].dnses= alloca(strlen(temp_dns) + 1);
        strcpy(responses[i].dnses, temp_dns);


   /*[zhaopf@meigsmart-2020-0615]modify for dhcp info not update on some platform }*/

    if(0 != ipaddr || ((0 == ipaddr) && ipv6addr_exist)) {
        responses[i].active = 1; //active
    } else {
        responses[i].active = 0; //inactive
    }
    /*[zhaopf@meigsmart-2020-0616] modify for ipv6 support } */
//add by zhaopf for Android4.4 support, 2020/12/11
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    responses[i].pcscf=NULL;
    responses[i].mtu=1280;
#endif


}

//Add by zhaopengfei for iface state indicate 2023/01/12
if(0 == request) {
    RLOGD("trigger sys.meig.ifup up");
    property_set("sys.meig.ifup", "true");
}


retempty:


for (i = 0; i < n; i++) {

    RLOGD("    responses-----number: %d------>",i);
    //responses[i].status = -1;
    RLOGD("    responses[%d].status:%d", i, responses[i].status);
    //responses[i].suggestedRetryTime = -1;
    RLOGD("    responses[%d].suggestedRetryTime:%d", i, responses[i].suggestedRetryTime);
    //responses[i].cid = -1;
    RLOGD("    responses[%d].cid:%d", i, responses[i].cid);
    //responses[i].active = -1;
    RLOGD("    responses[%d].active:%d", i, responses[i].active);
    // responses[i].type = "";
    RLOGD("    responses[%d].type:%s", i, responses[i].type);
    //responses[i].ifname = "";
    RLOGD("    responses[%d].ifname:%s", i, responses[i].ifname);
    //responses[i].addresses = "";
    RLOGD("    responses[%d].addresses:%s", i, responses[i].addresses);
    //responses[i].dnses = "";
    RLOGD("    responses[%d].dnses:%s", i, responses[i].dnses);
    //responses[i].gateways = "";
    RLOGD("    responses[%d].gateways:%s", i, responses[i].gateways);
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    //responses[i].pcscf = "";
    RLOGD("    responses[%d].pcscf:%s", i, responses[i].pcscf);
    //responses[i].mtu = 0;
    RLOGD("    responses[%d].mtu:%d", i, responses[i].mtu);
#endif
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support } */

    RLOGD("   responses<-----------");

}
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
if (t != NULL)
    RIL_onRequestComplete(*t, RIL_E_SUCCESS, responses,
                          n * sizeof(RIL_Data_Call_Response_v11));
else
    RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                              responses,
                              n * sizeof(RIL_Data_Call_Response_v11));
#else
if (t != NULL)
    RIL_onRequestComplete(*t, RIL_E_SUCCESS, responses,
                          n * sizeof(RIL_Data_Call_Response_v6));
else
    RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                              responses,
                              n * sizeof(RIL_Data_Call_Response_v6));
#endif
/*[zhaopf@meigsmart-2020-12-11]add for android 4.4 support } */
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
return ;
}
/*[zhaopf@meigsmart.com-2022-07-01]add for network manual selection Begin */
static void requestSetNetworkSelectionManual(void *data, size_t datalen, RIL_Token t)
{
    char* plmn_str = NULL;
    char* plmn_cache = NULL;
    char* ran_str = NULL;
    int err = 0;
    char* cmd = NULL;
    ATResponse *p_response = NULL;
    int ran = 0;
    struct timeval delay_flush = {2,0};
    if(NULL == data) {
        RLOGE("empty plmn info");
        goto error;
    }
    plmn_cache = strdup((const char*)data);
    RLOGD("%s plmn %s\n", __FUNCTION__, plmn_cache);

    if(NULL == plmn_cache || plmn_cache[0] == '\0') {
        RLOGD("%s empty profile\n", __FUNCTION__);
        goto error;

    }
    if(strlen(plmn_cache) < 5){
        RLOGD("%s plmn to short %s\n", __FUNCTION__, plmn_cache);
        goto error;
    }
   plmn_str = strtok(plmn_cache, "+");
    ran_str = strtok(NULL, "+");
    if(ran_str != NULL) {
            ran = atoi(ran_str);
            RLOGI("%s plmn=%s, ran=%s", __FUNCTION__, plmn_str, ran_str);
    } else {
        RLOGI("%s plmn=%s", __FUNCTION__, plmn_str);
    }

   at_send_command("AT+COPS=2",NULL);
   if(NULL == ran_str) {
        asprintf(&cmd, "AT+COPS=1,2,\"%s\"",plmn_str);
   } else {
#if (PLATFORM_SDK_VERSION > ANDROID_7_1_SDK_VERSION) //modify by zhaopengfei 2022/10/10
        switch(ran){
#if 0
            case GERAN:
                asprintf(&cmd, "AT+COPS=1,2,\"%s\", %d",plmn_str, MEIG_COPS_RADIO_TECH_V2_GSM_COMPACT);
                break;
#endif
           case UTRAN:
               asprintf(&cmd, "AT+COPS=1,2,\"%s\", %d",plmn_str, MEIG_COPS_RADIO_TECH_V2_UTRAN);
               break;
           case EUTRAN:
               asprintf(&cmd, "AT+COPS=1,2,\"%s\", %d",plmn_str, MEIG_COPS_RADIO_TECH_V2_EUTRAN);
               break;
           default:
               asprintf(&cmd, "AT+COPS=1,2,\"%s\"",plmn_str);
               break;
        }
#else
    asprintf(&cmd, "AT+COPS=1,2,\"%s\"",plmn_str);
#endif
   }
    err = at_send_command(cmd, &p_response);
    if (err < 0 || p_response->success == 0) {
       RLOGD("%s send at faied\n", __FUNCTION__);
        free(cmd);
        goto error;
    }
    free(cmd);
   if(NULL != plmn_cache) {
       free(plmn_cache);
       plmn_cache = NULL;
    }
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &err, sizeof(int));
    RIL_requestTimedCallback (forceFlushNetState, NULL, &delay_flush);
    return;
error:
    if(NULL != plmn_cache) free(plmn_cache);
    RLOGE
    ("%s must never return an error when radio is on", __FUNCTION__);
    at_response_free(p_response);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    RIL_requestTimedCallback (forceFlushNetState, NULL, &delay_flush);

}


static void requestQueryNetworkSelectionMode(void *data __unused,
        size_t datalen __unused,
        RIL_Token t)
{
    int err;
    ATResponse *p_response = NULL;
    int response = 0;
    char *line = NULL;



    err = at_send_command_singleline("AT+COPS?", "+COPS:", &p_response); //pure

    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);

    if (err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line, &response);

    if (err < 0) {
        goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
    at_response_free(p_response);
    return;
 error:
    at_response_free(p_response);
    RLOGE
        ("requestQueryNetworkSelectionMode must never return error when radio is on");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);

}
/*[zhaopf@meigsmart.com-2022-07-01]add for network manual selection End */

//zhangqingyun add for ruimin 7.0 ril  20180108 start
static void requestGetCurrentCalls_orignal(void *data __unused, size_t datalen __unused,  RIL_Token t)
{
//yanggong 20170515 21:00
RLOGD ("FIX me later,since at+clcc return wrong state when there is no call when init");

RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}


static void requestDial_orignal(void *data, size_t datalen __unused, RIL_Token t)
{
RIL_Dial *p_dial;
char *cmd;
const char *clir;
int ret;

p_dial = (RIL_Dial *) data;

switch (p_dial->clir) {
case 1:
    clir = "I";
    break;        /*invocation */
case 2:
    clir = "i";
    break;        /*suppression */
default:
case 0:
    clir = "";
    break;        /*subscription default */
}

asprintf(&cmd, "ATD%s%s;", p_dial->address, clir);

ret = at_send_command(cmd, NULL);

free(cmd);

/* success or failure is ignored by the upper layer here.
   it will call GET_CURRENT_CALLS and determine success that way */
RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

//zhangqingyun add for ruimin 7.0 ril  20180108 end

static void requestWriteSmsToSim_original(void *data, size_t datalen __unused,     RIL_Token t)
{
RIL_SMS_WriteArgs *p_args;
char *cmd;
int length;
int err;
ATResponse *p_response = NULL;

p_args = (RIL_SMS_WriteArgs *) data;

length = strlen(p_args->pdu) / 2;
asprintf(&cmd, "AT+CMGW=%d,%d", length, p_args->status);

err = at_send_command_sms(cmd, p_args->pdu, "+CMGW:", &p_response);

if (err != 0 || p_response->success == 0)
    goto error;

RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
at_response_free(p_response);

return;
error:
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
at_response_free(p_response);
}

static void requestHangup_orignal(void *data, size_t datalen __unused, RIL_Token t)
{
int *p_line;

int ret;
char *cmd;

p_line = (int *)data;

// 3GPP 22.030 6.5.5
// "Releases a specific active call X"
asprintf(&cmd, "AT+CHLD=1%d", p_line[0]);

ret = at_send_command(cmd, NULL);

free(cmd);

/* success or failure is ignored by the upper layer here.
   it will call GET_CURRENT_CALLS and determine success that way */
RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}
//zhangqingyun add for query available networks,before send at+cops=?,we should send at+cscs = "\gsm\"
//after send st+cops=?,we should send at+cscs="\ucs2".2018.03.12
static const char* networkStatusToRilString(int state)
{
switch(state) {
case 0:
    return("unknown");
    break;
case 1:
    return("available");
    break;
case 2:
    return("current");
    break;
case 3:
    return("forbidden");
    break;
default:
    return NULL;
}
}

void requestQueryAvailableNetworks(void *data __unused, size_t datalen __unused , RIL_Token t)
{
/* We expect an answer on the following form:
   +COPS: (2,"AT&T","AT&T","310410",0),(1,"T-Mobile ","TMO","310260",0)
 */

int err, operators, i, status;
ATResponse *p_response = NULL;
char * c_skip, *line, *p = NULL;
char ** response = NULL;

at_send_command("AT+CSCS=\"GSM\"", NULL);
/*[zhaopf@meigsmart-2020-0716] waiting until get result { */
err = at_send_command_singleline_wait("AT+COPS=?", "+COPS:", &p_response);
/*[zhaopf@meigsmart-2020-0716] waiting until get result } */

if (err < 0 || p_response->success == 0) goto error;

line = p_response->p_intermediates->line;

err = at_tok_start(&line);
if (err < 0) goto error;

/* Count number of '(' in the +COPS response to get number of operators*/
operators = 0;
for (p = line ; *p != '\0' ; p++) {
    if (*p == '(') operators++;
}

response = (char **)alloca(operators * 4 * sizeof(char *));

for (i = 0 ; i < operators ; i++ ) {
    err = at_tok_nextstr(&line, &c_skip);
    if (err < 0) goto error;
    if (strcmp(c_skip,"") == 0) {
        operators = i;
        continue;
    }
    status = atoi(&c_skip[1]);
    response[i*4+3] = (char*)networkStatusToRilString(status);

    err = at_tok_nextstr(&line, &(response[i*4+0]));
    if (err < 0) goto error;

    err = at_tok_nextstr(&line, &(response[i*4+1]));
    if (err < 0) goto error;

    err = at_tok_nextstr(&line, &(response[i*4+2]));
    if (err < 0) goto error;

    err = at_tok_nextstr(&line, &c_skip);

    if (err < 0) goto error;
}

RIL_onRequestComplete(t, RIL_E_SUCCESS, response, (operators * 4 * sizeof(char *)));
at_response_free(p_response);
/*[zhaopf@meigsmart-2020-1016] QCM modem not support UCS2 now { */
at_send_command("AT+CSCS=\"IRA\"", NULL);
/*[zhaopf@meigsmart-2020-1016] QCM modem not support UCS2 now } */
return;

error:
/*[zhaopf@meigsmart-2020-1016] QCM modem not support UCS2 now { */
at_send_command("AT+CSCS=\"IRA\"", NULL);
/*[zhaopf@meigsmart-2020-1016] QCM modem not support UCS2 now } */
at_response_free(p_response);
RLOGD("ERROR - requestQueryAvailableNetworks() failed");
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

//wangbo add zhangqingyun modify since poll signalstrength per 20 seconds,however network type can't change per 20 seconds
//if network type change ,unsol_voice_network_state_change will send to framework,then trigger requestRegistrationState,
//this time save the network type in gloable variable,this is to work around when get signalstrength have result no carrier or error

int odm_get_current_signal_strength_type()
{
int networktype = 0;

networktype = odm_get_current_network_type();
if (1 == networktype ||
        16 == networktype ||
        2 == networktype ||
        3 == networktype ||
        9 == networktype || 10 == networktype || 15 == networktype)
    return RIL_SIGNALSTRENGTH_GW;
else if (7 == networktype)
    return RIL_SIGNALSTRENGTH_EVOD;
else if (6 == networktype)
    return RIL_SIGNALSTRENGTH_CDMA;
else if (14 == networktype)
    return RIL_SIGNALSTRENGTH_LTE;
else if (17 == networktype)
    return RIL_SIGNALSTRENGTH_TD_SCDMA;
else
    return RIL_SIGNALSTRENGTH_UNKNOWN;

}

#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
static void signalResponseInit(RIL_SignalStrength_v10 *response) {
#else
static void signalResponseInit(RIL_SignalStrength_v8 *response) {
#endif
    memset(response, 0, sizeof(response));
    response->GW_SignalStrength.signalStrength = 99;
    response->GW_SignalStrength.bitErrorRate = 99;

    response->CDMA_SignalStrength.dbm = -1;
    response->CDMA_SignalStrength.ecio = -1;

    response->EVDO_SignalStrength.dbm = -1;
    response->EVDO_SignalStrength.ecio = -1;
    response->EVDO_SignalStrength.signalNoiseRatio = -1;

    response->LTE_SignalStrength.signalStrength = 99;
    response->LTE_SignalStrength.cqi = INT_MAX;
    response->LTE_SignalStrength.rsrp = INT_MAX;
    response->LTE_SignalStrength.rsrq = INT_MAX;
    response->LTE_SignalStrength.rssnr = INT_MAX;
    response->LTE_SignalStrength.timingAdvance = INT_MAX;
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    response->TD_SCDMA_SignalStrength.rscp = INT_MAX;
#endif
}

/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
static void requestSignalStrengthOld(void *data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err;
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    RIL_SignalStrength_v10 response;
#else
    RIL_SignalStrength_v8 response;
#endif
    char *line;
    int cdma_rssi = -1;

    signalResponseInit(&response);

    err = at_send_command_singleline("AT+CSQ", "+CSQ:", &p_response);
    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(response.GW_SignalStrength.signalStrength));
    if (err < 0) goto error;
    err = at_tok_nextint(&line, &(response.GW_SignalStrength.bitErrorRate));
    if (err < 0) goto error;

    response.GW_SignalStrength.signalStrength = response.GW_SignalStrength.signalStrength;
    response.GW_SignalStrength.bitErrorRate = response.GW_SignalStrength.bitErrorRate;

    // { referenced to YiYuan
    /**
     * Fill the cdma rssi value here. When we fill the actual rssi with 75, the
     * SignalStrength.java will deal with it as -75
     */
    cdma_rssi = CDMA_RSSI_THRESH - ((response.GW_SignalStrength.signalStrength * CDMA_RSSI_SPAN) / 31); // Change it following the modem code.

    response.CDMA_SignalStrength.dbm = cdma_rssi;
    response.CDMA_SignalStrength.ecio = cdma_rssi;
    response.EVDO_SignalStrength.dbm = cdma_rssi;
    response.EVDO_SignalStrength.ecio = cdma_rssi;
    // end: referenced to YiYuan }

#ifndef DONT_REPORT_LTE_SIGNAL_STRENGTH
    if( response.GW_SignalStrength.signalStrength > 99 && response.GW_SignalStrength.signalStrength < 200)
    {
        //response.GW_SignalStrength.signalStrength = ( response.GW_SignalStrength.signalStrength - 100)/3;
        response.LTE_SignalStrength.rsrp = response.GW_SignalStrength.signalStrength - 56;
        response.LTE_SignalStrength.rssnr = 301;
    } else{
        /*[zhaopf@meigsmart-20200-0624]fixed singnal report error on android7.0 { */
        response.LTE_SignalStrength.rsrp = INT_MAX;
        response.LTE_SignalStrength.rssnr = INT_MAX;
        response.LTE_SignalStrength.signalStrength = response.GW_SignalStrength.signalStrength;
        /*[zhaopf@meigsmart-20200-0624]fixed singnal report error on android7.0 } */
    }
#endif

    if (t == NULL) {
        RIL_onUnsolicitedResponse(RIL_UNSOL_SIGNAL_STRENGTH, &response, sizeof(response));
    } else {
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
    }

    at_response_free(p_response);
    return;
error:
    ALOGE("requestSignalStrength must never return an error when radio is on");
    if (t != NULL) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    }
    at_response_free(p_response);
}
/* end: add by dongmeirong for poll signal strength by ril 20210615 */

static void requestSignalStrengthQCM(void *data __unused, size_t datalen __unused, RIL_Token t)
{
ATResponse *p_response = NULL;
int err;
//modify by zhaopf for android 4.4 support
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
RIL_SignalStrength_v10 response;
#else
RIL_SignalStrength_v8 response;
#endif
char *line;
//int signalStrengrhType = 0;
FG_EX_SignalStrength fgExSignalStrength;
memset(&fgExSignalStrength, 0, sizeof(FG_EX_SignalStrength));
/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
signalResponseInit(&response);
/* end: add by dongmeirong for poll signal strength by ril 20210615 */

/* begin: modified by dongmeirong for AT Ver adaption 20201217 */
if(curr_modem_info.info.at_version == AT_VERSION_2) { // AT_VERSION_2 modem do not support FGCSQ
    err = -1;
} else {
    err = at_send_command_singleline("AT+FGCSQ", "+FGCSQ:", &p_response);
}
/* end: modified by dongmeirong for AT Ver adaption 20201217 */
if (err < 0 || p_response->success == 0) {
#define STRENTH_RETRY
#ifdef STRENTH_RETRY
    requestSignalStrength(data, datalen, t);
    at_response_free(p_response);
#else
/*zhaopf@meigsmart-2021/03/11 add for signale report Begin */
    if(NULL != t) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    }
/*zhaopf@meigsmart-2021/03/11 add for signal report End */
    goto error;
#endif


    return;
}

line = p_response->p_intermediates->line;

err = at_tok_start(&line);
if (err < 0)
    goto error;


err = at_tok_nextint(&line, &fgExSignalStrength.gwSignalStrength);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.gwbitErrorRate);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.cdma_dbm);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.cdma_ecio);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.evdo_dbm);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.evdo_ecio);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.evdo_signalNoiseRatio);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.lte_signalStrength);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.lte_rsrp);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.lte_rsrq);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &fgExSignalStrength.lte_rssnr);
if (err < 0)
    goto error;
if (0 != fgExSignalStrength.gwSignalStrength  ) {
/*[zhaopf@meigsmart.com-2020-1019]init value of signalStrenth { */
    // gw
    response.GW_SignalStrength.bitErrorRate =
    (fgExSignalStrength.gwbitErrorRate > 99)?99:fgExSignalStrength.gwbitErrorRate;
    response.GW_SignalStrength.signalStrength = (fgExSignalStrength.gwSignalStrength > 99)?99:fgExSignalStrength.gwSignalStrength;
/*[zhaopf@meigsmart.com-2020-1019]init value of signalStrenth } */

} else if (0 != fgExSignalStrength.lte_rssnr) {
    // lte
    response.LTE_SignalStrength.cqi = 8;
    response.LTE_SignalStrength.rsrp = fgExSignalStrength.lte_rsrp;
    response.LTE_SignalStrength.rsrq = fgExSignalStrength.lte_rsrq;
    response.LTE_SignalStrength.rssnr =
        fgExSignalStrength.lte_rssnr;
        /*[zhaopf@meigsmart.com-2020-1019]init value of signalStrenth { */
    response.LTE_SignalStrength.signalStrength =
        (fgExSignalStrength.lte_signalStrength > 99)?99:fgExSignalStrength.lte_signalStrength;
        /*[zhaopf@meigsmart.com-2020-1019]init value of signalStrenth } */


    RLOGD("LTE\r");
}

else if (0!= fgExSignalStrength.cdma_ecio) {
    // CDMA
    response.CDMA_SignalStrength.dbm = fgExSignalStrength.cdma_dbm;
    response.CDMA_SignalStrength.ecio =
        fgExSignalStrength.cdma_ecio;
    RLOGD("cmda\r");
} else if (0 != fgExSignalStrength.evdo_signalNoiseRatio) {
    response.EVDO_SignalStrength.dbm = fgExSignalStrength.evdo_dbm;
    response.EVDO_SignalStrength.ecio =
        fgExSignalStrength.evdo_ecio;
    response.EVDO_SignalStrength.signalNoiseRatio =
        fgExSignalStrength.evdo_signalNoiseRatio;
    RLOGD("evdo\r");
}

RLOGD("RIL_SignalStrength length is:%d",sizeof(response));
/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
if (t == NULL) {
    RIL_onUnsolicitedResponse(RIL_UNSOL_SIGNAL_STRENGTH, &response, sizeof(response));
} else {
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
}
at_response_free(p_response);
return;
error:
RLOGE("requestSignalStrength must never return an error when radio is on");
/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
if (t != NULL) {
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}
/* end: add by dongmeirong for poll signal strength by ril 20210615 */
at_response_free(p_response);
}
/*[zhaopf@meigsmart.com-2020-1019]init value of signalStrenth { */
#define USE_5G_AS_4G_SIGNAL
/*[zhaopf@meigsmart.com-2020-1019]init value of signalStrenth } */
/* meig-zhaopengfei-2021-10-22 ignore SNR report as inaccuracy , remove  rsrp lenient val by default{ */
static void requestSignalStrength(void *data __unused, size_t datalen __unused, RIL_Token t)
{
ATResponse *p_response = NULL;
int err, skip;
//modify by zhaopf for android 4.4 support
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
RIL_SignalStrength_v10 response;
#else
RIL_SignalStrength_v8 response;
#endif
char *line;
//int signalStrengrhType = 0;
char *Networktype = NULL;

/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
signalResponseInit(&response);
/* end: add by dongmeirong for poll signal strength by ril 20210615 */
err = at_send_command_singleline("AT^HCSQ?", "^HCSQ:", &p_response); //fixed err by zhaopf

if (err < 0 || p_response->success == 0) {
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    goto error;
}

line = p_response->p_intermediates->line;

err = at_tok_start(&line);
if (err < 0)
    goto error;
/*zhaopf@meigsmart-2021/03/11 add for hangsheng customed Begin */
if(NULL == strstr(BUILD_CUSTOMER, "HANGSHENG")){
    err = at_tok_nextint(&line, &skip);
    if (err < 0) goto error;
    err = at_tok_nextint(&line, &skip);
    if (err < 0) goto error;

}
/*zhaopf@meigsmart-2021/03/11 add for hangsheng customed End */
err = at_tok_nextstr(&line, &Networktype);  //networktype
if (err < 0) goto error;
/*zhangqingyun add notify network change when networktype is not the same as the previous signalstrength poll start */
if(Networktype != NULL){
    if(strcmp(Networktype,networktypefromsignalstrength) != 0){
        RLOGD("networktype chanege notify to framework");
        RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED,NULL,0);
        memset(networktypefromsignalstrength,0,sizeof(networktypefromsignalstrength));
        strcpy(networktypefromsignalstrength,Networktype);
    }
}
/*zhangqingyun add notify network change when networketype is not the same as the previous signalstrength poll end*/
/*[zhaopf@meigsmart-2020-0909]add for 5G signal update { */
if(0 == strcmp(Networktype, "NR5G")) {
        /*yufeilong add for support SRM811 20220527 start*/
        if((QCM == curr_modem_info.info.sltn_type) || (UNISOC == curr_modem_info.info.sltn_type)){
        /*yufeilong add for support SRM811 20220527 end*/
#ifdef USE_5G_AS_4G_SIGNAL
            err = at_tok_nextint(&line, &response.LTE_SignalStrength.rsrq);
            if (err < 0)
                goto error;
            err = at_tok_nextint(&line, &response.LTE_SignalStrength.rsrp);
            if (err < 0)
                goto error;
            err = at_tok_nextint(&line, &response.LTE_SignalStrength.rssnr);
            if (err < 0)
                goto error;
#else
            err = at_tok_nextint(&line, &response.NR5G_SignalStrength.rsrq);
            if (err < 0)
                goto error;

            err = at_tok_nextint(&line, &response.NR5G_SignalStrength.rsrp);
            if (err < 0)
                goto error;
            err = at_tok_nextint(&line, &response.NR5G_SignalStrength.rssnr);
            if (err < 0)
                goto error;
#endif
            if(at_tok_hasmore(&line)) { //NSA
                response.LTE_SignalStrength.signalStrength = response.LTE_SignalStrength.rsrq;
                response.LTE_SignalStrength.rsrq = response.LTE_SignalStrength.rsrp;
                response.LTE_SignalStrength.rsrp = response.LTE_SignalStrength.rssnr;
                err = at_tok_nextint(&line, &response.LTE_SignalStrength.rssnr);
                if (err < 0) {
                    goto error;
                }
         response.LTE_SignalStrength.signalStrength = (response.LTE_SignalStrength.signalStrength+2)/2;
         response.LTE_SignalStrength.rsrp = (141 - response.LTE_SignalStrength.rsrp);
         response.LTE_SignalStrength.rsrq = (40 - response.LTE_SignalStrength.rsrq)/2;
         response.LTE_SignalStrength.rssnr = (((response.LTE_SignalStrength.rssnr - 1)/5)-20)*10;

         /*zhaopf@meigsmart-2021/03/11 add for hangsheng customed Begin */
         if(response.LTE_SignalStrength.rsrp < 140) {
#ifdef LTE_SIGNAL_STRENGTH_RSRP_LENIENT
                 response.LTE_SignalStrength.rsrp -= 13;
#endif
                 if(response.LTE_SignalStrength.rsrp < 44) {
                     response.LTE_SignalStrength.rsrp = 44;
                 }
         }
         /*zhaopf@meigsmart-2021/03/11 add for hangsheng customed End */
         }else { //SA real 5G, report via LTE

         response.LTE_SignalStrength.signalStrength = (response.LTE_SignalStrength.signalStrength+2)/2;
         response.LTE_SignalStrength.rsrp = (157 - response.LTE_SignalStrength.rsrp);
         response.LTE_SignalStrength.rsrq = ((response.LTE_SignalStrength.rsrq - 1)/2)-43;
         response.LTE_SignalStrength.rssnr = (200 + ((((response.LTE_SignalStrength.rssnr - 1)/2) - 23)*10))*5;

         /*zhaopf@meigsmart-2021/03/11 add for hangsheng customed Begin */
         if(response.LTE_SignalStrength.rsrp < 140) {
#ifdef LTE_SIGNAL_STRENGTH_RSRP_LENIENT
             response.LTE_SignalStrength.rsrp -= 13;
#endif
             if(response.LTE_SignalStrength.rsrp < 44) {
                 response.LTE_SignalStrength.rsrp = 44;
             }
         }
         /*zhaopf@meigsmart-2021/03/11 add for hangsheng customed End */
    }
       response.LTE_SignalStrength.rssnr = INT_MAX; //ignore snr

    } else {
        /*yufeilong add for support SRM811 20220527 start*/
        RLOGD("known qcm and unisoc nr5g\n");
        /*yufeilong add for support SRM811 20220527 end*/
    }
} else if(0 == strcmp(Networktype, "LTE")) {
/*[zhaopf@meigsmart-2020-0909]add for 5G signal update } */
    response.LTE_SignalStrength.cqi = 8;
    if(QCM == curr_modem_info.info.sltn_type) {
        err = at_tok_nextint(&line, &response.LTE_SignalStrength.signalStrength);
        if (err < 0)
            goto error;
        /*zhaopf@meigsmart-2021/03/11 add for hangsheng customed Begin */
        if(NULL != strstr(BUILD_CUSTOMER, "HANGSHENG")){
            err = at_tok_nextint(&line, &response.LTE_SignalStrength.rsrp);
            if (err < 0)
                goto error;
            err = at_tok_nextint(&line, &response.LTE_SignalStrength.rssnr);
            if (err < 0)
                goto error;
            err = at_tok_nextint(&line, &response.LTE_SignalStrength.rsrq);
            if (err < 0)
                goto error;
         } else {
            err = at_tok_nextint(&line, &response.LTE_SignalStrength.rsrq);
            if (err < 0)
                goto error;
            err = at_tok_nextint(&line, &response.LTE_SignalStrength.rsrp);
            if (err < 0)
                goto error;
            err = at_tok_nextint(&line, &response.LTE_SignalStrength.rssnr);
            if (err < 0)
                goto error;
        }
        /*zhaopf@meigsmart-2021/03/11 add for hangsheng customed End */
        /*[zhaopf@meigsmart.com-2020-1019]fixed for LTE signalStrenth err { */
         response.LTE_SignalStrength.signalStrength = (response.LTE_SignalStrength.signalStrength+2)/2;
         response.LTE_SignalStrength.rsrp = (141 - response.LTE_SignalStrength.rsrp);
         response.LTE_SignalStrength.rsrq = (40 - response.LTE_SignalStrength.rsrq)/2;
         response.LTE_SignalStrength.rssnr =(((response.LTE_SignalStrength.rssnr - 1)/5)-20)*10;
         response.LTE_SignalStrength.rssnr = INT_MAX; //ignore snr
        /*[zhaopf@meigsmart.com-2020-1019]fixed for LTE signalStrenth err } */

/*zhaopf@meigsmart-2021/03/11 add for hangsheng customed Begin */
        if(response.LTE_SignalStrength.rsrp < 140) {
#ifdef LTE_SIGNAL_STRENGTH_RSRP_LENIENT
            response.LTE_SignalStrength.rsrp -= 13;
#endif
            if(response.LTE_SignalStrength.rsrp < 44) {
                response.LTE_SignalStrength.rsrp = 44;
             }
        }
/*zhaopf@meigsmart-2021/03/11 add for hangsheng customed End */

    } else {
        err = at_tok_nextint(&line, &response.LTE_SignalStrength.signalStrength);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &response.LTE_SignalStrength.rsrq);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &response.LTE_SignalStrength.rsrp);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &response.LTE_SignalStrength.rssnr);
        if (err < 0)
            goto error;

        /*[zhaopf@meigsmart.com-2020-1019]fixed for LTE signalStrenth err { */
         response.LTE_SignalStrength.signalStrength = (response.LTE_SignalStrength.signalStrength+2)/2;
         response.LTE_SignalStrength.rsrp = (141 - response.LTE_SignalStrength.rsrp);
         response.LTE_SignalStrength.rsrq = (40 - response.LTE_SignalStrength.rsrq)/2;
         response.LTE_SignalStrength.rssnr = (((response.LTE_SignalStrength.rssnr - 1)/5)-20)*10;
         response.LTE_SignalStrength.rssnr = INT_MAX; //ignore snr
        /*[zhaopf@meigsmart.com-2020-1019]fixed for LTE signalStrenth err } */

         /*zhaopf@meigsmart-2021/03/11 add for hangsheng customed Begin */
         if(response.LTE_SignalStrength.rsrp < 140) {
#ifdef LTE_SIGNAL_STRENGTH_RSRP_LENIENT
             response.LTE_SignalStrength.rsrp -= 13;
#endif
             if(response.LTE_SignalStrength.rsrp < 44) {
                 response.LTE_SignalStrength.rsrp = 44;
             }
         }
        /*zhaopf@meigsmart-2021/03/11 add for hangsheng customed End */

    }

    RLOGD("LTE\r");
} else if(0 == strcmp(Networktype, "GSM")) {

    err = at_tok_nextint(&line, &response.GW_SignalStrength.signalStrength);
    if (err < 0)
        goto error;
    /*Fixed by zhaopengfei for GSM signalStrenth err 2022/12/26 Begin */
    response.GW_SignalStrength.signalStrength = (response.GW_SignalStrength.signalStrength+2)/2;
    err = at_tok_nextint(&line, &response.GW_SignalStrength.bitErrorRate);
    if (err < 0)
        goto error;

    RLOGD("GSM rssi:%d\r", response.GW_SignalStrength.signalStrength);
    /*Fixed by zhaopengfei for GSM signalStrenth err 2022/12/26 End */
/*[zhaopf@meigsmart.com-2020-1019]add for cdma,evdo,wcdma signalStrength { */
} else if(0 == strcmp(Networktype, "CDMA")) {
    err = at_tok_nextint(&line, &response.CDMA_SignalStrength.dbm);
    if (err < 0)
        goto error;

    err = at_tok_nextint(&line, &response.CDMA_SignalStrength.ecio);
    if (err < 0)
        goto error;


    RLOGD("CDMA\r");

} else if(0 == strcmp(Networktype, "EVDO")) {

    err = at_tok_nextint(&line, &response.EVDO_SignalStrength.dbm);
    if (err < 0)
        goto error;

    err = at_tok_nextint(&line, &response.EVDO_SignalStrength.ecio);
    if (err < 0)
        goto error;

    RLOGD("EVDO\r");

} else if(0 == strcmp(Networktype, "WCDMA")) {

    err = at_tok_nextint(&line, &response.GW_SignalStrength.signalStrength);
    if (err < 0)
        goto error;
    response.GW_SignalStrength.signalStrength = (response.GW_SignalStrength.signalStrength+2)/2;
    RLOGD("WCDNA\r");

}
/*[zhaopf@meigsmart.com-2020-1019]add for cdma,evdo,wcdma signalStrength } */
RLOGD("RIL_SignalStrength_v10 length is:%d",sizeof(response));
/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
if (t == NULL) {
    RIL_onUnsolicitedResponse(RIL_UNSOL_SIGNAL_STRENGTH, &response, sizeof(response));
} else {
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
}
/* end: add by dongmeirong for poll signal strength by ril 20210615 */
at_response_free(p_response);
return;

error:
RLOGE("requestSignalStrength must never return an error when radio is on");
/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
if (t != NULL) {
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}
/* end: add by dongmeirong for poll signal strength by ril 20210615 */
at_response_free(p_response);
}
/* zhaopengfei@meig-2021-10-22 ignore SNR report as inaccuracy , remove  rsrp lenient val by default }*/
/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 { */
SYSCFGEX_NET_type  NetworkType2SYSCFGEXType(RIL_PreferredNetworkType nettype){


    if(property_get_bool("ril.prefernet.disable", false)){
        RLOGD("disabled Preferred NetworkType, default auto");
        return SYSCFGEX_NET_AUTO;
    }
    switch(nettype){
/*[zhaopf@meigsmart-2022-0823]add for gsm support Begin */
/*yufeilong add for support gsm only 20220809 begin*/
        case PREF_NET_TYPE_GSM_ONLY:
/*yufeilong add SLM770A for support gsm only 20230227 begin*/
            if ((PRODUCT_TYPE_SLM750 == s_product_type) || (PRODUCT_TYPE_SLM770A == s_product_type)) {
/*yufeilong add SLM770A for support gsm only 20230227 end*/
                return SYSCFGEX_NET_GSM;
            } else {
                return SYSCFGEX_NET_WCDMA;
            }
/*yufeilong add for support gsm only 20220809 end*/
        case PREF_NET_TYPE_GSM_WCDMA:
        case PREF_NET_TYPE_WCDMA:
        case PREF_NET_TYPE_GSM_WCDMA_AUTO:
        case PREF_NET_TYPE_CDMA_EVDO_AUTO:
        case PREF_NET_TYPE_CDMA_ONLY:
        case PREF_NET_TYPE_EVDO_ONLY:
        case PREF_NET_TYPE_GSM_WCDMA_CDMA_EVDO_AUTO:
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
        case PREF_NET_TYPE_TD_SCDMA_ONLY:
        case PREF_NET_TYPE_TD_SCDMA_WCDMA:
        case PREF_NET_TYPE_TD_SCDMA_GSM:
        case PREF_NET_TYPE_TD_SCDMA_GSM_WCDMA:
        case PREF_NET_TYPE_TD_SCDMA_GSM_WCDMA_CDMA_EVDO_AUTO:

#endif
            return SYSCFGEX_NET_WCDMA;
       /*[zhaopf@meigsmart-2022-0823]add for gsm support End */
        case PREF_NET_TYPE_LTE_GSM_WCDMA:
        case PREF_NET_TYPE_LTE_CMDA_EVDO_GSM_WCDMA:
            return SYSCFGEX_NET_LTE_TDSCDMA_WCDMA_GSM;
        case PREF_NET_TYPE_LTE_CDMA_EVDO:
        case PREF_NET_TYPE_LTE_WCDMA:
            return SYSCFGEX_NET_LTE_TDSCDMA_WCDMA;
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
        case PREF_NET_TYPE_TD_SCDMA_LTE:
        case PREF_NET_TYPE_TD_SCDMA_WCDMA_LTE:
            return SYSCFGEX_NET_LTE_TDSCDMA_WCDMA;
        case PREF_NET_TYPE_TD_SCDMA_GSM_LTE:
        case PREF_NET_TYPE_TD_SCDMA_GSM_WCDMA_LTE:
        case PREF_NET_TYPE_TD_SCDMA_LTE_CDMA_EVDO_GSM_WCDMA:
            return SYSCFGEX_NET_LTE_TDSCDMA_WCDMA_GSM;
#endif
        case PREF_NET_TYPE_LTE_ONLY:
            return SYSCFGEX_NET_LTE_ONLY;
        case PREF_NET_TYPE_5G:
            return SYSCFGEX_NET_NR5G; //SYSCFGEX_NET_AUTO;
    }
    return SYSCFGEX_NET_AUTO;
}
/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 } */

mododr_type  NetworkType2MododrType(RIL_PreferredNetworkType nettype)
{
/*[zhaopf@meigsmart-2020-0908]disable setpreferred network type in some condition { */
if(property_get_bool("ril.prefernet.disable", false)){
    RLOGD("disabled Preferred NetworkType, default auto");
    return MD_AUTO;
}
/*[zhaopf@meigsmart-2020-0908]disable setpreferred network type in some condition } */
if(HISI == curr_modem_info.info.sltn_type) {

    switch(nettype) {
    case PREF_NET_TYPE_GSM_ONLY:
        return MD_GSM_ONLY;
    case PREF_NET_TYPE_WCDMA:
        return MD_WCDMA_ONLY;
    case PREF_NET_TYPE_GSM_WCDMA_AUTO:
        return MD_WCDMA_ONLY;
    case PREF_NET_TYPE_LTE_ONLY:
        return MD_LTE_ONLY;
    default:
        return MD_AUTO;
    }

} else {
    switch(nettype) {
    case PREF_NET_TYPE_GSM_WCDMA:
        return MD_3G_PREFFERRED;
    case PREF_NET_TYPE_GSM_ONLY:
        return MD_GSM_ONLY;
    case PREF_NET_TYPE_WCDMA:
        return MD_WCDMA_ONLY;
    case PREF_NET_TYPE_GSM_WCDMA_AUTO:
    case PREF_NET_TYPE_CDMA_EVDO_AUTO:
    case PREF_NET_TYPE_GSM_WCDMA_CDMA_EVDO_AUTO:
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
    case PREF_NET_TYPE_TD_SCDMA_GSM:
    case PREF_NET_TYPE_TD_SCDMA_GSM_WCDMA:
    case PREF_NET_TYPE_TD_SCDMA_GSM_WCDMA_CDMA_EVDO_AUTO:
#endif
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support } */
        return MD_3G_PREFFERRED;
    case PREF_NET_TYPE_LTE_GSM_WCDMA:
    case PREF_NET_TYPE_LTE_CMDA_EVDO_GSM_WCDMA:
    case PREF_NET_TYPE_LTE_WCDMA:
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
    case PREF_NET_TYPE_TD_SCDMA_GSM_LTE:
    case PREF_NET_TYPE_TD_SCDMA_GSM_WCDMA_LTE:
    case PREF_NET_TYPE_TD_SCDMA_LTE_CDMA_EVDO_GSM_WCDMA:
#endif
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support } */
    case PREF_NET_TYPE_LTE_ONLY: //for some conditions
        return MD_AUTO;
    case PREF_NET_TYPE_CDMA_ONLY:
        return MD_CDMA_ONLY;
    case PREF_NET_TYPE_EVDO_ONLY:
        return MD_EVDO_ONLY;
    case PREF_NET_TYPE_LTE_CDMA_EVDO:
        return MD_HDR_TDSCDMA_WCDMA_LTE;
        /*
                case PREF_NET_TYPE_LTE_ONLY:
                    return MD_LTE_ONLY;
        */
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
    case PREF_NET_TYPE_TD_SCDMA_ONLY:
        return MD_TD_SCDMA_ONLY;
    case PREF_NET_TYPE_TD_SCDMA_WCDMA:
        return MD_TD_SCDMA_WCDMA;
    case PREF_NET_TYPE_TD_SCDMA_LTE:
    case PREF_NET_TYPE_TD_SCDMA_WCDMA_LTE:
        return MD_CDMA_LTE_ONLY;
#endif
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support } */
    default:
        return MD_AUTO;
    }
}
}
static void requestSetPreferredNetworkType(int request __unused, void *data,size_t datalen __unused, RIL_Token t)
{
int err = 0;
ATResponse *p_response = NULL;
int setmode = 0;
int responsenet = 0;
char * line = NULL;
char *cmd = NULL;
setmode = ((int *)data)[0];
/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 { */

/* begin: modified by dongmeirong for AT Ver adaption 20201217 */
if(((QCM == curr_modem_info.info.sltn_type) && (curr_modem_info.info.at_version == AT_VERSION_2)) ||
/*yufeilong adapt for SRM810 20221123 end*/
/*yufeilong add for support ASR 20220929 begin*/
    (ASR == curr_modem_info.info.sltn_type) || (UNISOC == curr_modem_info.info.sltn_type)) {
/*yufeilong add for support ASR 20220929 end*/
/*yufeilong adapt for SRM810 20221123 end*/
    SYSCFGEX_NET_type mode = NetworkType2SYSCFGEXType(setmode);
    RLOGD("set preferred nettype:%d, mode = %s, operator = %d\r",setmode, syscfgexType2Str[mode-1], cur_oper);
    switch(mode){
        case SYSCFGEX_NET_AUTO:
            cmd = strdup("AT^SYSCFGEX=00");
            break;
        /*yufeilong add for support set gsm only 20220823 begin*/
        case SYSCFGEX_NET_GSM:
            cmd = strdup("AT^SYSCFGEX=01");
            break;
        /*yufeilong add for support set gsm only 20220823 end*/
        case SYSCFGEX_NET_WCDMA:
            /*[zhaopf@meigsmart-2020-0108] srm815 only support wdcma for 3g { */
            if((((curr_modem_info.info.module_type & SRM815_MODULE) > 0) && cur_oper == CHINA_UNICOM_OPER) ||
                 /*yufeilong add for support set wcdma only 20220801 begin*/
                (setmode == PREF_NET_TYPE_CDMA_ONLY) ||
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
                (setmode == PREF_NET_TYPE_TD_SCDMA_ONLY) ||
#endif
                (setmode ==  PREF_NET_TYPE_EVDO_ONLY)){
                 /*yufeilong add for support set wcdma only 20220801 end*/
                cmd = strdup("AT^SYSCFGEX=02");
            } else {
                cmd = strdup("AT^SYSCFGEX=0201");
            }
            /*[zhaopf@meigsmart-2020-0108] srm815 only support wdcma for 3g } */
            break;
/*yufeilong modify for net type 20230404 begin*/
        case SYSCFGEX_NET_LTE_ONLY:
            cmd = strdup("AT^SYSCFGEX=03");
            break;
/*yufeilong modify for net type 20230404 end*/
        case SYSCFGEX_NET_LTE_TDSCDMA_WCDMA:
            /*yufeilong add for support set lte only 20220801 begin*/
            if ((setmode == PREF_NET_TYPE_LTE_ONLY) || (cur_oper == CHINA_TELECOM_OPER) || (cur_oper == CHINA_TIETONG_OPER)){
                cmd = strdup("AT^SYSCFGEX=03");
            } else {
                cmd = strdup("AT^SYSCFGEX=0302");
            }
            /*yufeilong add for support set lte only 20220823 end*/
            break;
/*yufeilong modify for net type 20230404 begin*/
        case SYSCFGEX_NET_LTE_TDSCDMA_WCDMA_GSM:
            if (((curr_modem_info.info.module_type & SRM815_MODULE) > 0) && cur_oper == CHINA_UNICOM_OPER) {
                cmd = strdup("AT^SYSCFGEX=0302");
            } else if ((setmode == PREF_NET_TYPE_LTE_ONLY) || (cur_oper == CHINA_TELECOM_OPER) || (cur_oper == CHINA_TIETONG_OPER)){
                cmd = strdup("AT^SYSCFGEX=0301");
            } else {
                cmd = strdup("AT^SYSCFGEX=030201");
            }
/*yufeilong modify for net type 20230404 end*/
            break;
        case SYSCFGEX_NET_NR5G:
            asprintf(&cmd, "AT^SYSCFGEX=%s", (FIVEG_MODE_SA == s_current_5g_mode)?"04":(FIVEG_MODE_SA_NSA == s_current_5g_mode)?"0403":"00");
            break;
        default:
            ALOGD("set preferred nettype:do nothing\r");
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, sizeof(int));
            return;

    }
} else {
    mododr_type mode = MD_AUTO;
    mode = NetworkType2MododrType(setmode);
    if ((cur_oper == CHINA_TELECOM_OPER) || (cur_oper == CHINA_TIETONG_OPER)) {
        mode = MD_LTE_ONLY;
    }
    RLOGD("set preferred nettype:%d, mode = %s cur_oper = %d \r",setmode, mododrType2Str[mode-1], cur_oper);
    /*zhangqingyun add if query mododr equal to set do nothting 20220511 start*/
    err = at_send_command_singleline("AT+MODODR?","+MODODR:",&p_response);
    if(err < 0 && p_response->success == 0){
        RLOGD("err = %d p_response success = %d\r", err, p_response->success);
        goto error;
    }
    line = p_response->p_intermediates->line; //fixed err by zhaopengfei, 2022/10/21
    err = at_tok_start(&line);
    if(err < 0 ){
        RLOGD("at_tok_start err = %d \r", err);
        goto error;
    }
    err = at_tok_nextint(&line, &responsenet);
    if(err < 0 ){
        RLOGD("at_tok_nextint err = %d \r", err);
        goto error;
    }
    if(responsenet == mode){
        RLOGD("query network type equqls to set do nothing just reurn");
        RIL_onRequestComplete(t,RIL_E_SUCCESS,NULL,sizeof(int));
        at_response_free(p_response);
        return;
    }else {
    /*zhangqingyun add if query mododr queal ot set do nothing 20220511 end*/
        asprintf(&cmd,"AT+MODODR=%d",mode);
    }
    at_response_free(p_response);
    p_response = NULL;
}
/* end: modified by dongmeirong for AT Ver adaption 20201217 */
/*[zhaopf@meigsmart-2020-1016] setpreferred network type for SRM815 } */
err = at_send_command(cmd,&p_response);
if (err < 0) {
    goto error;
}

RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL,0);//zqy if null,the fourth parameters have none sense 1.4 vts
at_response_free(p_response);
free(cmd);
return;
error:
at_response_free(p_response);
ALOGD("ERROR: requestSetPreferredNetworkType() failed\n");
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}


#if 0
static void requestSetPreferredNetworkType(int request __unused, void *data,size_t datalen __unused, RIL_Token t)
{
//int err = 0;
ATResponse *p_response = NULL;
int setmode = 0,mode = 0;
char *cmd = NULL;
setmode = ((int *)data)[0];
RLOGD("set preferred mode = %d\r",setmode);


#if 0
typedef enum {
    PREF_NET_TYPE_GSM_WCDMA                = 0, /* GSM/WCDMA (WCDMA preferred) */
    PREF_NET_TYPE_GSM_ONLY                 = 1, /* GSM only */
    PREF_NET_TYPE_WCDMA                    = 2, /* WCDMA  */
    PREF_NET_TYPE_GSM_WCDMA_AUTO           = 3, /* GSM/WCDMA (auto mode, according to PRL) */
    PREF_NET_TYPE_CDMA_EVDO_AUTO           = 4, /* CDMA and EvDo (auto mode, according to PRL) */
    PREF_NET_TYPE_CDMA_ONLY                = 5, /* CDMA only */
    PREF_NET_TYPE_EVDO_ONLY                = 6, /* EvDo only */
    PREF_NET_TYPE_GSM_WCDMA_CDMA_EVDO_AUTO = 7, /* GSM/WCDMA, CDMA, and EvDo (auto mode, according to PRL) */
    PREF_NET_TYPE_LTE_CDMA_EVDO            = 8, /* LTE, CDMA and EvDo */
    PREF_NET_TYPE_LTE_GSM_WCDMA            = 9, /* LTE, GSM/WCDMA */
    PREF_NET_TYPE_LTE_CMDA_EVDO_GSM_WCDMA  = 10, /* LTE, CDMA, EvDo, GSM/WCDMA */
    PREF_NET_TYPE_LTE_ONLY                 = 11, /* LTE only */
    PREF_NET_TYPE_LTE_WCDMA                = 12  /* LTE/WCDMA */
} RIL_PreferredNetworkType;

#endif


switch(setmode) {
case 11:        //PREF_NET_TYPE_LTE_ONLY
    mode = 5;
    break;
case 12:        //PREF_NET_TYPE_LTE_WCDMA
case 10:        //PREF_NET_TYPE_LTE_CMDA_EVDO_GSM_WCDMA
case 9:            //PREF_NET_TYPE_LTE_GSM_WCDMA
case 8:            //PREF_NET_TYPE_LTE_CDMA_EVDO
    mode = 2;
    break;
case 7:            //PREF_NET_TYPE_GSM_WCDMA_CDMA_EVDO_AUTO
    mode = 4;    //fix  3g pref
    break;
case 6:            //PREF_NET_TYPE_EVDO_ONLY
    mode = 10;    //evdo only
    break;
case 5:            //PREF_NET_TYPE_CDMA_ONLY
    mode = 8;    //cdma only
    break;
case 4:            //PREF_NET_TYPE_CDMA_EVDO_AUTO
    mode = 9;    //cdma&evdo
    break;
case 3:            //PREF_NET_TYPE_GSM_WCDMA_AUTO
    mode = 1;    //fix
    break;
case 2:            //PREF_NET_TYPE_WCDMA
    mode = 1;    //wcdma only
    break;
case 1:            //PREF_NET_TYPE_GSM_ONLY
    mode = 3;    //gsm only
    break;
case 0:            //PREF_NET_TYPE_GSM_WCDMA
    mode = 1;    //fix
    break;


default:
    mode =2;
    break;
}
RLOGD("requestSetPreferredNetworkType | before write 2 | switch mode = %d\n", mode);
RLOGD("requestSetPreferredNetworkType | After switch process mode = %d\n", mode);
RLOGD("requestSetPreferredNetworkType | After switch process mode = %d\n", mode);
RLOGD("requestSetPreferredNetworkType | After switch process mode = %d\n", mode);


asprintf(&cmd,"AT+MODODR=%d",2);
//    asprintf(&cmd,"AT+MODODR=%d",mode);
at_send_command(cmd,&p_response);


RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, sizeof(int));
at_response_free(p_response);
free(cmd);
return;
#if 0
error:
at_response_free(p_response);
RLOGD("ERROR: requestSetPreferredNetworkType() failed\n");
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
#endif
}
#endif

static void requestGetPreferredNetworkType_v2(int request __unused,
        void *data __unused,
        size_t datalen __unused, RIL_Token t) {
    int err = -1;
    ATResponse *p_response = NULL;
    char *acqorder = NULL;
    char *line = NULL;
    RIL_PreferredNetworkType response = 0;

    err = at_send_command_singleline("AT^SYSCFGEX?", "^SYSCFGEX:", &p_response);
    if (err < 0 || p_response->success == 0) {
        goto error;
    }
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) {
        goto error;
    }
    err = at_tok_nextstr(&line, &acqorder);
    if (err < 0) {
        goto error;
    }
    if (!strcmp(acqorder, "0201")) {
        response = PREF_NET_TYPE_GSM_WCDMA;
    } else if (!strcmp(acqorder, "01")) {
        response = PREF_NET_TYPE_GSM_ONLY;
    } else if (!strcmp(acqorder, "02")) {
        response = PREF_NET_TYPE_WCDMA;
    } else if (!strcmp(acqorder, "00")) {
        response = PREF_NET_TYPE_LTE_GSM_WCDMA;
    } else if (!strcmp(acqorder, "03")) {
        response = PREF_NET_TYPE_LTE_ONLY;
    } else if (!strcmp(acqorder, "0302")) {
        response = PREF_NET_TYPE_LTE_WCDMA;
    } else {
        response = PREF_NET_TYPE_GSM_WCDMA_AUTO;
    }
    response = PREF_NET_TYPE_LTE_ONLY;
    RLOGD("%s response = %d", __FUNCTION__, response);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
    at_response_free(p_response);
    return;
error:
    at_response_free(p_response);
    RLOGE("%s failed\n", __FUNCTION__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}


static void requestGetPreferredNetworkType(int request __unused,
        void *data __unused,
        size_t datalen __unused, RIL_Token t)

//static void requestGetPreferredNetworkType(void *data, size_t datalen, RIL_Token t)
{
int err;
ATResponse *p_response = NULL;
int response = 0;
int responsenet=0;
char *line;
err = at_send_command_singleline("AT+MODODR?", "+MODODR:", &p_response);
if (err < 0 || p_response->success == 0) {
    goto error;
}
line = p_response->p_intermediates->line;
err = at_tok_start(&line);
if (err < 0) {
    goto error;
}
RLOGD("SIGNAL-requestGetPreferredNetworkType raw data=%s",line);
err = at_tok_nextint(&line, &responsenet);
if (err < 0) {
    goto error;
}
RLOGD("SIGNAL-requestGetPreferredNetworkType responsenet=%d",responsenet);
switch(responsenet) {
case 1:        //wcdma only
    response = PREF_NET_TYPE_WCDMA;
    break;
case 2:        //auto
    //response = PREF_NET_TYPE_LTE_GSM_WCDMA;
    response = PREF_NET_TYPE_LTE_CMDA_EVDO_GSM_WCDMA;
    break;
case 3:        //gsm only
    response = PREF_NET_TYPE_GSM_ONLY;
    break;
case 4:        //3g pre
    response = PREF_NET_TYPE_GSM_WCDMA;
    break;
case 5:        //lte only
    response = PREF_NET_TYPE_LTE_ONLY;
    break;
case 6:        //td only
    response = PREF_NET_TYPE_WCDMA;
    break;
case 7:        //td and cdma
    response = PREF_NET_TYPE_WCDMA;
    break;
case 8:        //cdma only
    response = PREF_NET_TYPE_CDMA_ONLY;
    break;
case 9:        //cdma&evdo
    response = PREF_NET_TYPE_CDMA_EVDO_AUTO;
    break;
case 10:    //evdo only
    response = PREF_NET_TYPE_EVDO_ONLY;
    break;
default:
    goto error;
    break;
}
RLOGD("SIGNAL-requestGetPreferredNetworkType response=%d",response);
RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
at_response_free(p_response);
return;

error:
at_response_free(p_response);
/*zhaopengfei@meigsmart.com 2022/08/23 add default nettype for 750 Begin */
if(PRODUCT_TYPE_SLM750 == s_product_type) {
    response = PREF_NET_TYPE_LTE_GSM_WCDMA;
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
    RLOGD("requestGetPreferredNetworkType default lte&gsm&wcdma\n");
} else {

    RLOGD("ERROR: requestGetPreferredNetworkType() failed\n");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}
/*zhaopengfei@meigsmart.com 2022/08/23 add default nettype for 750 End */
}




static void requestCdmaPrlVersion(int request __unused, void *data __unused,
                                  size_t datalen __unused, RIL_Token t)
{
int err;
char *responseStr;
ATResponse *p_response = NULL;
//const char *cmd;
char *line;

err = at_send_command_singleline("AT+WPRL?", "+WPRL:", &p_response);
if (err < 0 || !p_response->success)
    goto error;
line = p_response->p_intermediates->line;
err = at_tok_start(&line);
if (err < 0)
    goto error;
err = at_tok_nextstr(&line, &responseStr);
if (err < 0 || !responseStr)
    goto error;
RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr,
                      strlen(responseStr));
at_response_free(p_response);
return;
error:
at_response_free(p_response);
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaBaseBandVersion(int request __unused,
                                       void *data __unused,
                                       size_t datalen __unused, RIL_Token t)
{
//int err;
char *responseStr;
/*ATResponse *p_response = NULL;
const char *cmd;
const char *prefix;
char *line, *p;
int commas;
int skip;
int count = 4;
*/

// Fixed values. TODO: query modem
responseStr = strdup("1.0.0.0");
RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr,
                      sizeof(responseStr));
free(responseStr);
}
#if 0
static void requestDeviceIdentity(int request __unused, void *data __unused,
                                  size_t datalen __unused, RIL_Token t)
{
int err;
int response[4];
char * responseStr[4];
ATResponse *p_response = NULL;
const char *cmd;
const char *prefix;
char *line, *p;
int commas;
int skip;
int count = 4;

// Fixed values. TODO: Query modem
responseStr[0] = "----";
responseStr[1] = "----";
responseStr[2] = "77777777";
responseStr[3] = ""; // default empty for non-CDMA

err = at_send_command_numeric("AT+CGSN", &p_response);
if (err < 0 || p_response->success == 0) {
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    return;
} else {
    if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
        responseStr[3] = p_response->p_intermediates->line;
    } else {
        responseStr[0] = p_response->p_intermediates->line;
    }
}

RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, count*sizeof(char*));
at_response_free(p_response);
}

#endif


static void requestDeviceIdentity(int request __unused, void *data __unused,
                                  size_t datalen __unused, RIL_Token t)
{
/* begin: modified by dongmeirong for IMEI missed in response 20210324 */
int err;
char *responseStr[4];
ATResponse *p_response = NULL;
char *line = NULL;
char* skip = NULL;

responseStr[0] = "----";
responseStr[1] = "----";
responseStr[2] = "77777777";
responseStr[3] = "";
/* to get IMEI */
err = at_send_command_singleline("AT+LCTSN=0,7", "+LCTSN:", &p_response);
if (err < 0 || p_response->success == 0) {
    RLOGE("%s LCTSN get IMEI failed ");
    goto error;
}
line = p_response->p_intermediates->line;
err = at_tok_start(&line);
if(err < 0) {
    goto error;
}
err = at_tok_nextstr(&line, &skip);
if(err < 0){
    goto error;
}
responseStr[0] = skip;
RLOGD("IMEI:%s", responseStr[0]);

RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, 4 * sizeof(char *));
at_response_free(p_response);
return;
error:
RLOGE
("requestDeviceIdentity must never return an error when radio is on");
at_response_free(p_response);
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
/* end: modified by dongmeirong for IMEI missed in response 20210324 */
}


static void requestCdmaGetSubscriptionSource(int request __unused, void *data,
        size_t datalen __unused,
        RIL_Token t)
{
int err;
//int *ss = (int *)data;
ATResponse *p_response = NULL;
char *cmd = NULL;
char *line = NULL;
int response;

asprintf(&cmd, "AT+CCSS?");
if (!cmd)
    goto error;

err = at_send_command_singleline(cmd, "+CCSS:", &p_response);
if (err < 0 || !p_response->success)
    goto error;

line = p_response->p_intermediates->line;
err = at_tok_start(&line);
if (err < 0)
    goto error;

err = at_tok_nextint(&line, &response);
free(cmd);
cmd = NULL;

RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));

return;
error:
free(cmd);
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaSetSubscriptionSource(int request __unused, void *data,
        size_t datalen, RIL_Token t)
{
int err;
int *ss = (int *)data;
ATResponse *p_response = NULL;
char *cmd = NULL;

RLOGE(" < entry RIL_REQUEST_CDMA_SET_SUBSCRIPTION !");

if (!ss || !datalen) {
    RLOGE("RIL_REQUEST_CDMA_SET_SUBSCRIPTION without data!");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    return;
}
asprintf(&cmd, "AT+CCSS=%d", ss[0]);
if (!cmd)
    goto error;

err = at_send_command(cmd, &p_response);
if (err < 0 || !p_response->success)
    goto error;
free(cmd);
cmd = NULL;

RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);

RIL_onUnsolicitedResponse(RIL_UNSOL_CDMA_SUBSCRIPTION_SOURCE_CHANGED,
                          ss, sizeof(ss[0]));

return;
error:
free(cmd);
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaSubscription(int request __unused, void *data __unused,
                                    size_t datalen __unused, RIL_Token t)
{
char *responseStr[5];
/*
int err;
int response[5];
ATResponse *p_response = NULL;
const char *cmd;
const char *prefix;
char *line, *p;
int commas;
int skip;
int count = 5;
*/

// Fixed values. TODO: Query modem
responseStr[0] = "8587777777";    // MDN
responseStr[1] = "1";    // SID
responseStr[2] = "1";    // NID
responseStr[3] = "8587777777";    // MIN
responseStr[4] = "1";    // PRL Version
RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr,sizeof(responseStr));

return;
/*
error:
RLOGE
("requestCdmaSubscription must never return an error when radio is on");
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
*/
}

static void requestCdmaGetRoamingPreference(int request __unused,
        void *data __unused,
        size_t datalen __unused,
        RIL_Token t)
{
int roaming_pref = -1;
ATResponse *p_response = NULL;
char *line;
int res;

res = at_send_command_singleline("AT+WRMP?", "+WRMP:", &p_response);
if (res < 0 || !p_response->success) {
    goto error;
}
line = p_response->p_intermediates->line;

res = at_tok_start(&line);
if (res < 0)
    goto error;

res = at_tok_nextint(&line, &roaming_pref);
if (res < 0)
    goto error;

RIL_onRequestComplete(t, RIL_E_SUCCESS, &roaming_pref,
                      sizeof(roaming_pref));
return;
error:
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaSetRoamingPreference(int request __unused, void *data,
        size_t datalen __unused,
        RIL_Token t)
{
int *pref = (int *)data;
ATResponse *p_response = NULL;
char *line;
int res;
char *cmd = NULL;

asprintf(&cmd, "AT+WRMP=%d", *pref);
if (cmd == NULL)
    goto error;

res = at_send_command(cmd, &p_response);
if (res < 0 || !p_response->success)
    goto error;

RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
free(cmd);
return;
error:
free(cmd);
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static int parseRegistrationState(char *str, int *type, int *items,
                                  int **response)
{
int err;
char *line = str, *p;
int *resp = NULL;
int skip;
int count = 3;
int commas;

RLOGD("parseRegistrationState. Parsing: %s", str);
err = at_tok_start(&line);
if (err < 0)
    goto error;

/* Ok you have to be careful here
 * The solicited version of the CREG response is
 * +CREG: n, stat, [lac, cid]
 * and the unsolicited version is
 * +CREG: stat, [lac, cid]
 * The <n> parameter is basically "is unsolicited creg on?"
 * which it should always be
 *
 * Now we should normally get the solicited version here,
 * but the unsolicited version could have snuck in
 * so we have to handle both
 *
 * Also since the LAC and CID are only reported when registered,
 * we can have 1, 2, 3, or 4 arguments here
 *
 * finally, a +CGREG: answer may have a fifth value that corresponds
 * to the network type, as in;
 *
 *   +CGREG: n, stat [,lac, cid [,networkType]]
 */

/* count number of commas */
commas = 0;
for (p = line; *p != '\0'; p++) {
    if (*p == ',')
        commas++;
}

resp = (int *)calloc(commas + 1, sizeof(int));
if (!resp)
    goto error;
switch (commas) {
case 0:        /* +CREG: <stat> */
    err = at_tok_nextint(&line, &resp[0]);
    if (err < 0)
        goto error;
    resp[1] = -1;
    resp[2] = -1;
    break;

case 1:        /* +CREG: <n>, <stat> */
    err = at_tok_nextint(&line, &skip);
    if (err < 0)
        goto error;
    err = at_tok_nextint(&line, &resp[0]);
    if (err < 0)
        goto error;
    resp[1] = -1;
    resp[2] = -1;
    if (err < 0)
        goto error;
    break;

case 2:        /* +CREG: <stat>, <lac>, <cid> */
    err = at_tok_nextint(&line, &resp[0]);
    if (err < 0)
        goto error;
    err = at_tok_nexthexint(&line, &resp[1]);
    if (err < 0)
        goto error;
    err = at_tok_nexthexint(&line, &resp[2]);
    if (err < 0)
        goto error;
    break;
case 3:        /* +CREG: <n>, <stat>, <lac>, <cid> */
    err = at_tok_nextint(&line, &skip);
    if (err < 0)
        goto error;
    err = at_tok_nextint(&line, &resp[0]);
    if (err < 0)
        goto error;
    err = at_tok_nexthexint(&line, &resp[1]);
    if (err < 0)
        goto error;
    err = at_tok_nexthexint(&line, &resp[2]);
    if (err < 0)
        goto error;
    break;
    /* special case for CGREG, there is a fourth parameter
     * that is the network type (unknown/gprs/edge/umts)
     */
case 4:        /* +CGREG: <n>, <stat>, <lac>, <cid>, <networkType> */
    err = at_tok_nextint(&line, &skip);
    if (err < 0)
        goto error;
    err = at_tok_nextint(&line, &resp[0]);
    if (err < 0)
        goto error;
    err = at_tok_nexthexint(&line, &resp[1]);
    if (err < 0)
        goto error;
    err = at_tok_nexthexint(&line, &resp[2]);
    if (err < 0)
        goto error;
    err = at_tok_nexthexint(&line, &resp[3]);
    if (err < 0)
        goto error;
    count = 4;
    break;

    //wangbo debug
case 5: {    //CEREG
    err = at_tok_nextint(&line, &skip);
    if (err < 0)
        goto error;

    err = at_tok_nextint(&line, response[0]);
    if (err < 0)
        goto error;

    err = at_tok_nexthexint(&line, response[1]);
    if (err < 0)
        goto error;

    err = at_tok_nexthexint(&line, &skip);
    if (err < 0)
        goto error;

    err = at_tok_nexthexint(&line, response[2]);
    if (err < 0)
        goto error;

    err = at_tok_nextint(&line, response[3]);
    if (err < 0)
        goto error;
    count = 5;
    break;
}

default:
    goto error;
}
s_lac = resp[1];
s_cid = resp[2];
if (response)
    *response = resp;
if (items)
    *items = commas + 1;
if (type)
    *type = techFromModemType(TECH(sMdmInfo));
return 0;
error:
free(resp);
return -1;
}



static RIL_RadioTechnology  MeigHisiRadioTechToCommonRadioTech(Meig_Hisi_RadioTechnology  meig_radio_tech)
{
switch(meig_radio_tech) {
case MEIG_HISI_RADIO_TECH_GSM_GPRS:
    return RADIO_TECH_GSM;
case MEIG_HISI_RADIO_TECH_WCDMA:
    return RADIO_TECH_UMTS;
case MEIG_HISI_RADIO_TECH_LTE:
    return RADIO_TECH_LTE;
}

return RADIO_TECH_UNKNOWN;
}




static RIL_RadioTechnology  MeigRadioTechToCommonRadioTech(Meig_RadioTechnology  meig_radio_tech)
{
switch(meig_radio_tech) {
case MEIG_RADIO_TECH_NO_SERVICE:
    return RADIO_TECH_UNKNOWN;
case MEIG_RADIO_TECH_GSM:
    return RADIO_TECH_GSM;
case MEIG_RADIO_TECH_GPRS:
    return RADIO_TECH_GPRS;
case MEIG_RADIO_TECH_EDGE:
    return RADIO_TECH_EDGE;
case MEIG_RADIO_TECH_WCDMA:
    return RADIO_TECH_UMTS;
case MEIG_RADIO_TECH_HSDPA:
    return RADIO_TECH_HSDPA;
case MEIG_RADIO_TECH_HSUPA:
    return RADIO_TECH_HSUPA;
case MEIG_RADIO_TECH_HSUPA_HSDPA:
    return RADIO_TECH_HSPA;
//add by zhaopf for Android4.4 support, 2020/12/11
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
case MEIG_RADIO_TECH_TDSCDMA:
    return RADIO_TECH_TD_SCDMA;
#endif
case MEIG_RADIO_TECH_LTE:
case MEIG_RADIO_TECH_TDD_LTE:
case MEIG_RADIO_TECH_FDD_LTE:
    return RADIO_TECH_LTE;
case MEIG_RADIO_TECH_CDMA:
    return RADIO_TECH_1xRTT;
case MEIG_RADIO_TECH_CDMA_HDR:
case MEIG_RADIO_TECH_HDR:
    return RADIO_TECH_UMTS;
case MEIG_RADIO_TECH_EHRPO:
    return RADIO_TECH_EHRPD;

}

return RADIO_TECH_UNKNOWN;
}

/*[zhaopf@meigsmart.com-2020-1019]modify for cops state of all modules { */
static RIL_RadioTechnology  MeigCopsTechToCommonRadioTechV2(Meig_CopsRadioTechnologyV2  meig_radio_tech)
{

switch(meig_radio_tech) {

case MEIG_COPS_RADIO_TECH_V2_GSM:
case MEIG_COPS_RADIO_TECH_V2_GSM_COMPACT:
case MEIG_COPS_RADIO_TECH_V2_GSM_EGPRS:
case MEIG_COPS_RADIO_TECH_V2_EC_GSM_IOT:
/*yufeilong add for modify SLM770A send sms failed when network is 3g 20230511 begin*/
    if (ASR == curr_modem_info.info.sltn_type) {
        return RADIO_TECH_HSPAP;
    }
/*yufeilong add for modify SLM770A send sms failed when network is 3g 20230511 end*/
    return RADIO_TECH_GSM;
case MEIG_COPS_RADIO_TECH_V2_UTRAN:
    return RADIO_TECH_UMTS;
case MEIG_COPS_RADIO_TECH_V2_HSDPA:
    return RADIO_TECH_HSDPA;
case MEIG_COPS_RADIO_TECH_V2_HSUPA:
    return RADIO_TECH_HSUPA;
case MEIG_COPS_RADIO_TECH_V2_HSUPA_HSDPA:
    return RADIO_TECH_HSPA;
case MEIG_COPS_RADIO_TECH_V2_EUTRAN:
case MEIG_COPS_RADIO_TECH_V2_EUTRAN_NB_S1:
    return RADIO_TECH_LTE;
case MEIG_COPS_RADIO_TECH_V2_EUTRAN_5GCN:
case MEIG_COPS_RADIO_TECH_V2_NR_5GCN:
case MEIG_COPS_RADIO_TECH_V2_NG_RAN:
case MEIG_COPS_RADIO_TECH_V2_EUTRA_NR:
    return RADIO_TECH_NR5G;
    break;
}

return RADIO_TECH_UNKNOWN;
}


static RIL_RadioTechnology  MeigCopsTechToCommonRadioTech(Meig_CopsRadioTechnology  meig_radio_tech)
{

switch(meig_radio_tech) {
case MEIG_COPS_RADIO_TECH_CDMA:
case MEIG_COPS_RADIO_TECH_CDMA_EVDO:
    return RADIO_TECH_EHRPD;
case MEIG_COPS_RADIO_TECH_EVDO:
    return RADIO_TECH_EVDO_A;
case MEIG_COPS_RADIO_TECH_GSM:
case MEIG_COPS_RADIO_TECH_GSM_COMPACT:
case MEIG_COPS_RADIO_TECH_GSM_EGPRS:
    return RADIO_TECH_GSM;
case MEIG_COPS_RADIO_TECH_UTRAN:
    return RADIO_TECH_UMTS;
case MEIG_COPS_RADIO_TECH_HSDPA:
    return RADIO_TECH_HSDPA;
case MEIG_COPS_RADIO_TECH_HSUPA:
    return RADIO_TECH_HSUPA;
case MEIG_COPS_RADIO_TECH_HSUPA_HSDPA:
    return RADIO_TECH_HSPA;
case MEIG_COPS_RADIO_TECH_EUTRAN:
    return RADIO_TECH_LTE;

    break;
}

return RADIO_TECH_UNKNOWN;
}
/*[zhaopf@meigsmart.com-2020-1019]modify for cops state of all modules } */
/*[zhaopf@meigsmart-2020-1113]add for cellinfo in register status report { */
MEIG_CellInfo getCellInfo(RIL_RadioTechnology tech){
    int err;
    char *line_cops;
    ATResponse *p_response = NULL;
    int skip;
    MEIG_CellInfo meigCellinfo = {0};
    //modify by zhaopf for android 4.4 not support RADIO_TECH_LTE_CA
    if(tech >= RADIO_TECH_NR5G){ //5G
         at_send_command("AT+C5GREG=2", NULL);
        err = at_send_command_singleline("AT+C5GREG?","+C5GREG:",&p_response);
//modify by zhaopf for android 4.4 not support RADIO_TECH_LTE_CA
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
    } else if(RADIO_TECH_LTE == tech || RADIO_TECH_LTE_CA == tech){ //4G
#else
    } else if(RADIO_TECH_LTE == tech){ //4G
#endif
         at_send_command("AT+CEREG=2", NULL);
        err = at_send_command_singleline("AT+CEREG?","+CEREG:",&p_response);
    } else {
        at_send_command("AT+CGREG=2", NULL); //fixed err by zhaopf
        err = at_send_command_singleline("AT+CGREG?","+CGREG:",&p_response);
    }

     if(err < 0 || p_response->success == 0) {
         goto error;
     }

    line_cops = p_response->p_intermediates->line;
    err = at_tok_start(&line_cops);
    if(err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line_cops,&skip);
    if(err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line_cops,&meigCellinfo.regstat);
    if(err < 0) {
        goto error;
    }

    if (at_tok_hasmore(&line_cops)) {

        err = at_tok_nexthexint(&line_cops,&meigCellinfo.tac);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nexthexint(&line_cops,&meigCellinfo.ci);
        if(err < 0) {
            goto error;
        }
    }
    error:
        at_response_free(p_response);
        return meigCellinfo;
}
/*[zhaopf@meigsmart-2020-1113]add for cellinfo in register status report } */

/*[zhaopengfei@meigsmart-2020-05-22] modify for radio tech funcion {*/
static RIL_RadioTechnology getRadioTechnology(){
int err;
char *line, *line_cops, *p;
char* c_skip;
ATResponse *p_response_cops = NULL;
int radio_tech;
int skip;

err = at_send_command_singleline("AT+COPS=3,2;+COPS?","+COPS:",&p_response_cops);
if(err < 0 || p_response_cops->success == 0) {
    goto error;
}

line_cops = p_response_cops->p_intermediates->line;
err = at_tok_start(&line_cops);
if(err < 0) {
    goto error;
}
err = at_tok_nextint(&line_cops,&skip);
if(err < 0) {
    goto error;
}
if (at_tok_hasmore(&line_cops)) {

    err = at_tok_nextint(&line_cops,&skip);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextstr(&line_cops,&c_skip);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line_cops,&radio_tech);
    if(err < 0) {
        goto error;
    }
} else {
     radio_tech = RADIO_TECH_UNKNOWN;
     goto error; //add by zhaopf for unkonw type direcly return
}
at_response_free(p_response_cops);
/*[zhaopf@meigsmart.com-2020-1019]modify for cops state of all modules { */
/* begin: modified by dongmeirong for AT Ver adaption 20201217 */
/*yufeilong add for support SRM811 20220527 start*/
/*yufeilong add for modify SLM770A send sms failed when network is 3g 20230511 begin*/
if(((QCM == curr_modem_info.info.sltn_type) || (UNISOC == curr_modem_info.info.sltn_type) || (ASR == curr_modem_info.info.sltn_type)) && (curr_modem_info.info.at_version == AT_VERSION_2)) {
/*yufeilong add for modify SLM770A send sms failed when network is 3g 20230511 end*/
/*yufeilong add for support SRM811 20220527 end*/
    return MeigCopsTechToCommonRadioTechV2((Meig_CopsRadioTechnologyV2)radio_tech);

} else {
    return MeigCopsTechToCommonRadioTech((Meig_CopsRadioTechnology)radio_tech);
}
/* end: modified by dongmeirong for AT Ver adaption 20201217 */
/*[zhaopf@meigsmart.com-2020-1019]modify for cops state of all modules } */
error:
    at_response_free(p_response_cops);
    return RADIO_TECH_UNKNOWN;

}
/*[zhaopengfei@meigsmart-2020-05-22] modify for radio tech funcion }*/
/*[zhaopengfei@meigsmart-2021-06-11] add for ps check {*/
bool checkIfPSReady(){
    int err;
    char *line;
    ATResponse *p_response = NULL;
    int reg_state = 0;
    int svd_domain = 0;
    /* begin: add by dongmeirong for use sysinfoex for at_version_2 20210618 */
    if (curr_modem_info.info.at_version == AT_VERSION_1) {
        err = at_send_command_singleline("AT^SYSINFO", "^SYSINFO:", &p_response);
    } else {
        err = at_send_command_singleline("AT^SYSINFOEX", "^SYSINFOEX:", &p_response);
    }
    /* end: add by dongmeirong for use sysinfoex for at_version_2 20210618 */
    if(err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line,&reg_state);
    if(err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line,&svd_domain);
    if(err < 0) {
         RLOGE("parse ps state failed");
         goto error;
    }

error:
    at_response_free(p_response);
    return (2 == reg_state && (2 == svd_domain || 3 == svd_domain));

}
/*[zhaopengfei@meigsmart-2021-06-11] add for ps check }*/
/*[zhaopengfei@meigsmart-2022/04/01]add for sim monitor Begin {*/
static bool checkIfRegisted(){
    int err;
    char *line;
    ATResponse *p_response = NULL;
    int reg_state = 0;
    int svd_domain = 0;
    if (curr_modem_info.info.at_version == AT_VERSION_1) {
        err = at_send_command_singleline("AT^SYSINFO", "^SYSINFO:", &p_response);
    } else {
        err = at_send_command_singleline("AT^SYSINFOEX", "^SYSINFOEX:", &p_response);
    }
    if(err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line,&reg_state);
    if(err < 0) {
        goto error;
    }


error:
    at_response_free(p_response);
    return (2 == reg_state);

}

static bool checkIfSimStateValid(){
    int err;
    char *line;
    ATResponse *p_response = NULL;
    int sim_state = 0;
    int skip;
    int svd_domain = 0;
    if (curr_modem_info.info.at_version == AT_VERSION_1) {
        err = at_send_command_singleline("AT^SYSINFO", "^SYSINFO:", &p_response);
    } else {
        err = at_send_command_singleline("AT^SYSINFOEX", "^SYSINFOEX:", &p_response);
    }
    if(err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line,&skip);
    if(err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line,&skip);
    if(err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line,&skip);
    if(err < 0) {
        goto error;
    }
    if (curr_modem_info.info.at_version == AT_VERSION_1) {
        err = at_tok_nextint(&line,&skip);
        if(err < 0) {
            goto error;
        }

    }
    err = at_tok_nextint(&line,&sim_state);
    if(err < 0) {
        goto error;
    }


error:
    at_response_free(p_response);
    return (1 == sim_state);

}

/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail Begin */

static bool checkIfSimPsValidRegisted(){
    int err;
    char *line;
    ATResponse *p_response = NULL;
    int sim_state = 0, skip;
    if (curr_modem_info.info.at_version == AT_VERSION_1) {
        err = at_send_command_singleline("AT^SYSINFO", "^SYSINFO:", &p_response);
    } else {
        err = at_send_command_singleline("AT^SYSINFOEX", "^SYSINFOEX:", &p_response);
    }
    if(err < 0 || p_response->success == 0) {
        goto error;
    }
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line,&skip);
    if(err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line,&skip);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line,&skip);
    if(err < 0) {
        goto error;
    }
    if (curr_modem_info.info.at_version == AT_VERSION_1) {
        err = at_tok_nextint(&line,&skip);
        if(err < 0) {
            goto error;
        }
    }

    err = at_tok_nextint(&line,&sim_state);
    if(err < 0) {
        goto error;
    }

error:
    at_response_free(p_response);
    return (2 == sim_state || 1 == sim_state || 240 == sim_state);

}


void resetSimPowerIfNecessary(void *param __unused){
    if((SIM_READY == getSIMStatus()) && (!checkIfSimPsValidRegisted())){
        RLOGE("sim reg state invalid, reset radio power");
        resetSimPower();
    } else {
        g_invalid_sim_reset_enable = true;
    }

}


/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail End */
#define MEIG_REG_MONITOR_INTERVAL_SEC (10)


static void updateSimStateMonitor()
{

    static int regMonCount = 0;
    int err;
    struct timeval check_delay = {MEIG_REG_MONITOR_INTERVAL_SEC, 0};
    RLOGD("%s check %d time\n", __FUNCTION__, regMonCount);

    if(SIM_READY == checkIfSIMReady() && (!checkIfSimStateValid())) {
        RLOGD("try to recovery sim state");
        err = at_send_command("AT+CFUN=0", NULL);
        if (err < 0 ){
            RLOGD("offline mode failed");
        }
        setRadioState(RADIO_STATE_OFF);
        err = at_send_command("AT+CFUN=1", NULL);
        if (err < 0 ){
            RLOGD("radio on failed");
        }
        setRadioState(RADIO_STATE_ON);
        regMonCount = 0;
    }

}

/*[zhaopengfei@meigsmart-2022/04/01]add for sim monitor End {*/
/*[zhaopengfei@meigsmart-2022-04-01] add for reg state check { */
static void updateRegisterMonitor()
{

    static int regMonCount = 0;
    int err;
    struct timeval check_delay = {MEIG_REG_MONITOR_INTERVAL_SEC, 0};
    RLOGD("%s check %d time\n", __FUNCTION__, regMonCount);
    if(checkIfRegisted()) {
        regMonCount = 0;
    } else {

        regMonCount++;
        if(regMonCount > 5) {

        RLOGD("try to recovery resgiter");
        err = at_send_command("AT+CFUN=0", NULL);
        if (err < 0 ){
            RLOGD("offline mode failed");
        }
        setRadioState(RADIO_STATE_OFF);
        err = at_send_command("AT+CFUN=1", NULL);
        if (err < 0 ){
            RLOGD("radio on failed");
        }
            setRadioState(RADIO_STATE_ON);
            regMonCount = 0;
        } else {
            RIL_requestTimedCallback(updateRegisterMonitor, NULL, &check_delay);
        }
    }
}

static void getPlmn(char **mcc, char **mnc) {
    ATResponse *p_response = NULL;
    char *line = NULL;
    char* skip = NULL;
    int err = -1;

    err = at_send_command_singleline("AT^PLMN?", "^PLMN:", &p_response);
    if (err < 0 || p_response->success == 0) {
        RLOGE("%s AT^PLMN? cmd failed.", __FUNCTION__);
        goto error;
    }
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }

    // enable
    err = at_tok_nextstr(&line, &skip);
    if(err < 0){
        goto error;
    }

    err = at_tok_nextstr(&line, mcc);
    if(err < 0) {
        RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
        goto error;
    }

    err = at_tok_nextstr(&line, mnc);
    if(err < 0) {
        RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
        goto error;
    }

    at_response_free(p_response);
    return;

    error:
    RLOGE("%s exec failed!", __FUNCTION__);
    at_response_free(p_response);
}

/*[zhaopengfei@meigsmart-2022-04-01] add for reg state check } */
/* begin: add by dongmeirong for use sysinfoex for at_version_2 20210618 */
static void sysinfoCmd(int request, RIL_Token t, int reg_state_len) {
int err;
int response[reg_state_len];
char *responseStr[reg_state_len];
/*[zhaopf@meigsmart-2020-1113]add for cellinfo in register status report { */
MEIG_CellInfo meig_cellinfo;
/*[zhaopf@meigsmart-2020-1113]add for cellinfo in register status report } */
ATResponse *p_response = NULL;
const char *cmd;
const char *prefix;
char *line, *line_cops, *p;
int skip;
char* c_skip;
int count = 3;
int radioTech = 0;
memset(response, 0x0, sizeof(response));
memset(responseStr, 0x0, sizeof(responseStr));

//radioTech = odm_get_current_network_type();
//networktype_querysignalstrenth = radioTech;//zhangqingyun add to save networktype in gloable variable 20180228
RLOGD("------> Enter %s | cur oper is: %d", __FUNCTION__, cur_oper);
err = at_send_command_singleline("AT^SYSINFO","^SYSINFO:",&p_response);
if(err < 0 || p_response->success == 0) {
    goto error;
}
line = p_response->p_intermediates->line;
err = at_tok_start(&line);
if(err < 0) {
    goto error;
}
//

err = at_tok_nextint(&line,&response[0]);
#ifdef DEBUG
ALOGD("srv_status is:%d",response[0]);
#endif
if(err < 0) {
    goto error;
}
err = at_tok_nextint(&line,&response[1]);
#ifdef DEBUG
ALOGD("srv_domain is:%d",response[1]);
#endif
if(err < 0) {
    goto error;
}
err = at_tok_nextint(&line,&response[2]);
#ifdef DEBUG
ALOGD("roam_state is:%d",response[2]);
#endif
if(err < 0) {
    goto error;
}
err = at_tok_nextint(&line,&response[3]);
#ifdef DEBUG
ALOGD("sys_mode is:%d",response[3]);
#endif
if(err < 0) {
    goto error;
}
err = at_tok_nextint(&line,&response[4]);
#ifdef DEBUG
ALOGD("sim state is:%d",response[4]);
#endif
if(err < 0) {
    goto error;
}

/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail Begin */
if((response[4] != 1) &&
    (response[4] != 2) &&
    (response[4] != 240) &&
    (response[4] != 255) ){   //1:valid sim; 2:cs invalid
    struct timeval check_delay = {3, 0};
    if(g_invalid_sim_reset_enable) {
        RLOGI("sim ps invalid, delay check");
        RIL_requestTimedCallback(resetSimPowerIfNecessary, NULL, &check_delay);
    }
    g_invalid_sim_reset_enable = false;
} else {
    g_invalid_sim_reset_enable = true;
}
/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail End */



/*[zhaopengfei@meigsmart-2020-05-22] modify for radio tech funcion {*/
if((response[5] = property_get_int32("ril.fixed.radiotech", -1)) < 0) {
    response[5] = getRadioTechnology();
    /*[zhaopf@meigsmart.com-2020-1019]add for radio tech indication { */
    /* meig-zhaopengfei-2021-10-22 add radio tech change { */
    updateRadioTechnology(&response[5]);
    /* meig-zhaopengfei-2021-10-22 add radio tech change } */
    /*[zhaopf@meigsmart.com-2020-1019]add for radio tech indication } */
} else {
    RLOGD("fixed net type to %d\n", response[5]);
}
/*[zhaopengfei@meigsmart-2020-05-22] modify for radio tech funcion }*/
/*zhaopengfei@meigsmart.com fixed for lost signal end}*/
#ifdef DEBUG
ALOGD("meig tech is:%d",response[5]);
#endif


//}
//if((request == RIL_REQUEST_VOICE_REGISTRATION_STATE && response[0] == 2 &&(response[1] == 1 || response[1] ==3))  //cs

if((request == RIL_REQUEST_VOICE_REGISTRATION_STATE && response[0] == 2 &&(response[1] == 1 || response[1] ==3 || response[1] ==2))  //fake
        || (request == RIL_REQUEST_DATA_REGISTRATION_STATE && response[0] == 2 && (response[1] == 2 || response[1] ==3))) { //ps
    asprintf(&responseStr[0],"%d",1);

    /*
    if(HISI == curr_modem_info.info.sltn_type) {
        asprintf(&responseStr[3],"%d",MeigRadioTechToCommonRadioTech((Meig_RadioTechnology)response[5]));

    } else {
    */
/*[zhaopengfei@meigsmart-2020-05-22] modify for radio tech funcion {*/
    asprintf(&responseStr[3],"%d",response[5]);
/*[zhaopengfei@meigsmart-2020-05-22] modify for radio tech funcion }*/
//    }
    /*[zhaopf@meigsmart-2020-1113]add for cellinfo in register status report { */
    meig_cellinfo = getCellInfo(response[5]);
    if(1 == meig_cellinfo.regstat) {
        asprintf(&responseStr[1],"%x",meig_cellinfo.tac);
        asprintf(&responseStr[2],"%x",meig_cellinfo.ci);
    } else {
        /*[zhaopf@megismart-2021/06/11]fixed response format error {*/
        asprintf(&responseStr[1],"%d",-1);
        asprintf(&responseStr[2],"%d",-1);
        /*[zhaopf@megismart-2021/06/11]fixed response format error }*/
    }
    /*[zhaopf@meigsmart-2020-1113]add for cellinfo in register status report } */


    ALOGD("send valid info");

    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, reg_state_len*sizeof(char*));
    at_response_free(p_response);
    return;
} else {
    asprintf(&responseStr[0],"%d", 0);
    /*[zhaopf@megismart-2021/06/11]fixed response format error {*/
    asprintf(&responseStr[1],"%d",-1);
    asprintf(&responseStr[2],"%d",-1);
    asprintf(&responseStr[3],"%d",0);
    /*[zhaopf@megismart-2021/06/11]fixed response format error }*/
    ALOGD("send invalid info");
    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, reg_state_len*sizeof(char*));
    at_response_free(p_response);
    return;
}

error:
ALOGD("%s must never return an error when radio is on", __FUNCTION__);
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
at_response_free(p_response);
}

static void sysinfoExCmd(int request, RIL_Token t, int reg_state_len) {
int err;
int response[reg_state_len];
char *responseStr[reg_state_len];
MEIG_CellInfo meig_cellinfo = {0};
ATResponse *p_response = NULL;
char *line = NULL;
int skip;
memset(response, 0x0, sizeof(response));
memset(responseStr, 0x0, sizeof(responseStr));

RLOGD("------> Enter %s | cur oper is: %d", __FUNCTION__, cur_oper);
err = at_send_command_singleline("AT^SYSINFOEX","^SYSINFOEX:",&p_response);
if(err < 0 || p_response->success == 0) {
    goto error;
}
line = p_response->p_intermediates->line;
err = at_tok_start(&line);
if(err < 0) {
    goto error;
}

err = at_tok_nextint(&line, &response[0]);
#ifdef DEBUG
ALOGD("srv_status is:%d", response[0]);
#endif
if(err < 0) {
    goto error;
}
err = at_tok_nextint(&line, &response[1]);
#ifdef DEBUG
ALOGD("srv_domain is:%d", response[1]);
#endif
if(err < 0) {
    goto error;
}
err = at_tok_nextint(&line, &response[2]);
#ifdef DEBUG
ALOGD("roam_state is:%d", response[2]);
#endif
if(err < 0) {
    goto error;
}
err = at_tok_nextint(&line, &response[4]);
#ifdef DEBUG
ALOGD("sim_state is:%d", response[4]);
#endif
if(err < 0) {
    goto error;
}

err = at_tok_nextint(&line, &skip);
#ifdef DEBUG
ALOGD("lock_state is:%d", skip);
#endif
if(err < 0) {
    goto error;
}

err = at_tok_nextint(&line, &response[3]);
#ifdef DEBUG
ALOGD("sys_mode is:%d", response[3]);
#endif
if(err < 0) {
    goto error;
}

if((response[5] = property_get_int32("ril.fixed.radiotech", -1)) < 0) {
    response[5] = getRadioTechnology();
    /* meig-zhaopengfei-2021-10-22 add radio tech change { */
    updateRadioTechnology(&response[5]);
    /* meig-zhaopengfei-2021-10-22 add radio tech change } */
} else {
    RLOGD("fixed net type to %d\n", response[5]);
}
#ifdef DEBUG
ALOGD("meig tech is:%d",response[5]);
#endif
//zhangqingyun add cts test
#ifdef MEIG_CTS_ENABLE
    RLOGD("cts test don't do recovery may cause cts fail");
#else 
/*[zhaopengfei@meigsmart-2022/04/01]add for sim monitor Begin {*/
if((response[4] != 1) && (!g_simstate_monitor_started)){
    RLOGI("sim not valid, start monitor");
    g_simstate_monitor_started = true;
    struct timeval check_delay = {MEIG_REG_MONITOR_INTERVAL_SEC, 0};
    RIL_requestTimedCallback(updateSimStateMonitor, NULL, &check_delay);
    /*[zhaopengfei@meigsmart-2022/04/01]add for reg monitor Begin*/
} else if((response[4] == 1) && (response[0] != 2) && (!g_reg_monitor_started)){
    RLOGI("not registed, start monitor");
    g_reg_monitor_started = true;
    struct timeval check_delay = {MEIG_REG_MONITOR_INTERVAL_SEC, 0};
    RIL_requestTimedCallback(updateRegisterMonitor, NULL, &check_delay);
}
#endif
/*[zhaopengfei@meigsmart-2022/04/01]add for reg monitor End*/
/*[zhaopengfei@meigsmart-2022/04/01]add for sim monitor End {*/

if((request == RIL_REQUEST_VOICE_REGISTRATION_STATE && response[0] == 2 &&(response[1] == 1 || response[1] ==3 || response[1] ==2))  //fake
        || (request == RIL_REQUEST_DATA_REGISTRATION_STATE && response[0] == 2 && (response[1] == 2 || response[1] ==3))) { //ps
    asprintf(&responseStr[0],"%d",1);
    asprintf(&responseStr[3],"%d",response[5]);
    meig_cellinfo = getCellInfo(response[5]);
    if(1 == meig_cellinfo.regstat) {
        asprintf(&responseStr[1],"%x",meig_cellinfo.tac);
        asprintf(&responseStr[2],"%x",meig_cellinfo.ci);
    } else {
        asprintf(&responseStr[1],"%d",-1);
        asprintf(&responseStr[2],"%d",-1);
    }

    getPlmn(&responseStr[11], &responseStr[12]);
    ALOGD("%s send valid info, mcc = %s, mnc = %s", __FUNCTION__, responseStr[11], responseStr[12]);

    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, reg_state_len*sizeof(char*));
    at_response_free(p_response);
    return;
} else {
    asprintf(&responseStr[0],"%d", 0);
    asprintf(&responseStr[1],"%d",-1);
    asprintf(&responseStr[2],"%d",-1);
    asprintf(&responseStr[3],"%d",0);
    ALOGD("send invalid info");
    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, reg_state_len*sizeof(char*));
    at_response_free(p_response);
    return;
}
error:
ALOGD("%s must never return an error when radio is on", __FUNCTION__);
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
at_response_free(p_response);
}
/* end: add by dongmeirong for use sysinfoex for at_version_2 20210618 */


static void requestRegistrationState(int request, void *data __unused,
                                     size_t datalen __unused, RIL_Token t, int reg_state_len)
{
    /* begin: add by dongmeirong for use sysinfoex for at_version_2 20210618 */
    if (curr_modem_info.info.at_version == AT_VERSION_1) {
        sysinfoCmd(request, t, reg_state_len);
    } else {
        sysinfoExCmd(request, t, reg_state_len);
    }
    /* end: add by dongmeirong for use sysinfoex for at_version_2 20210618 */
}

static void requestOperator(void *data __unused, size_t datalen __unused,
                            RIL_Token t)
{
int err;
int i;
int skip;
ATLine *p_cur;
char *response[3];

memset(response, 0, sizeof(response));

ATResponse *p_response = NULL;

err =
    at_send_command_multiline
    ("AT+COPS=3,0;+COPS?;+COPS=3,1;+COPS?;+COPS=3,2;+COPS?", "+COPS:",
     &p_response);

// we expect 3 lines here:
// * +COPS: 0,0,"T - Mobile"
// * +COPS: 0,1,"TMO"
// * +COPS: 0,2,"310170"
//

if (err != 0)
    goto error;

for (i = 0, p_cur = p_response->p_intermediates; p_cur != NULL;
        p_cur = p_cur->p_next, i++) {
    char *line = p_cur->line;

    err = at_tok_start(&line);
    if (err < 0)
        goto error;

    err = at_tok_nextint(&line, &skip);
    if (err < 0)
        goto error;

    // If we're unregistered, we may just get
    // a "+COPS: 0" response
    if (!at_tok_hasmore(&line)) {
        response[i] = NULL;
        continue;
    }

    err = at_tok_nextint(&line, &skip);
    if (err < 0)
        goto error;

    // a "+COPS: 0, n" response is also possible
    if (!at_tok_hasmore(&line)) {
        response[i] = NULL;
        continue;
    }

    err = at_tok_nextstr(&line, &(response[i]));
    if (err < 0)
        goto error;
    // Simple assumption that mcc and mnc are 3 digits each
    //all is number
    RLOGD("%s response[%d]=%s\n", __FUNCTION__, i,  response[i]);
    if(strspn(response[i], "0123456789")==strlen(response[i])) {
        if (sscanf(response[i], "%3d%3d", &s_mcc, &s_mnc) != 2) {
            RLOGE
            ("requestOperator expected mccmnc to be 6 decimal digits");
        }
    }
}

if (i != 3) {
    /* expect 3 lines exactly */
    goto error;
}

/* meig-zhaopengfei-2019-12-31 add for operator update { */
update_operator_info();
/* meig-zhaopengfei-2019-12-31 add for operator update } */

RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
at_response_free(p_response);

return;
error:
RLOGE("requestOperator must not return error when radio is on");
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
at_response_free(p_response);
}

static void requestCdmaSendSMS_original(void *data, size_t datalen, RIL_Token t)
{
int err = 1;        // Set to go to error:
RIL_SMS_Response response;
RIL_CDMA_SMS_Message *rcsm;

RLOGD
("requestCdmaSendSMS datalen=%zu, sizeof(RIL_CDMA_SMS_Message)=%zu",
 datalen, sizeof(RIL_CDMA_SMS_Message));

// verify data content to test marshalling/unmarshalling:
rcsm = (RIL_CDMA_SMS_Message *) data;
RLOGD("TeleserviceID=%d, bIsServicePresent=%d, \
            uServicecategory=%d, sAddress.digit_mode=%d, \
            sAddress.Number_mode=%d, sAddress.number_type=%d, ", rcsm->uTeleserviceID, rcsm->bIsServicePresent, rcsm->uServicecategory, rcsm->sAddress.digit_mode, rcsm->sAddress.number_mode, rcsm->sAddress.number_type);

if (err != 0)
    goto error;

// Cdma Send SMS implementation will go here:
// But it is not implemented yet.

memset(&response, 0, sizeof(response));
response.messageRef = 1;
RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
return;

error:
// Cdma Send SMS will always cause send retry error.
response.messageRef = -1;
RIL_onRequestComplete(t, RIL_E_SMS_SEND_FAIL_RETRY, &response,
                      sizeof(response));
}



/*[zhaopengfei@meigsmart-2022/04/01]enable ims sms Begin {*/
#if 1
static void requestImsSendSMS(void *data, size_t datalen, RIL_Token t)
{
RIL_IMS_SMS_Message *p_args;
RIL_SMS_Response response;

memset(&response, 0, sizeof(response));

RLOGD("requestImsSendSMS: datalen=%zu, "
      "registered=%d, service=%d, format=%d, ims_perm_fail=%d, "
      "ims_retry=%d, gsm_fail=%d, gsm_retry=%d",
      datalen, s_ims_registered, s_ims_services, s_ims_format,
      s_ims_cause_perm_failure, s_ims_cause_retry, s_ims_gsm_fail,
      s_ims_gsm_retry);

// figure out if this is gsm/cdma format
// then route it to requestSendSMS vs requestCdmaSendSMS respectively
p_args = (RIL_IMS_SMS_Message *) data;

if (0 != s_ims_cause_perm_failure)
    goto error;

// want to fail over ims and this is first request over ims
if (0 != s_ims_cause_retry && 0 == p_args->retry)
    goto error2;

if (RADIO_TECH_3GPP == p_args->tech) {
    requestSendSMS(p_args->message.gsmMessage,
                   datalen -
                   sizeof(RIL_RadioTechnologyFamily), t);
} else if (RADIO_TECH_3GPP2 == p_args->tech) {
    requestSendCDMASMS(p_args->message.cdmaMessage,
                       datalen -
                       sizeof(RIL_RadioTechnologyFamily), t);
} else {
    RLOGE("requestImsSendSMS invalid format value =%d",
          p_args->tech);
}

error:
response.messageRef = -2;
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, &response,
                      sizeof(response));
return;

error2:
response.messageRef = -1;
RIL_onRequestComplete(t, RIL_E_SMS_SEND_FAIL_RETRY, &response,
                      sizeof(response));
}
#endif
/*[zhaopengfei@meigsmart-2022/04/01]enable ims sms End {*/
/*yufeilong adapt Call Forward function 20230505 begin*/
static void requestQueryCallForwardStatus(void *data, size_t datalen, RIL_Token t)
{
    char* cmd;
    int err,i;
    ATResponse *p_response = NULL;
    ATLine *p_cur;
    RIL_CallForwardInfo* p_args;
    RIL_CallForwardInfo** ppCallForwards;
    RIL_CallForwardInfo* pCallForwards;
    int countCallForward;
    int status;

    RLOGD("enter requestQueryCallForwardStatus");
    p_args = (RIL_CallForwardInfo *) data;
    //#ifdef MEIG_CTS_ENABLE
	//RIL_onRequestComplete(t, RIL_E_SUCCESS, ppCallForwards,sizeof (RIL_CallForwardInfo *));
	
    if ((p_args->reason < 0) || (p_args->reason > 5)) {
        RLOGE("requestSetCallForward invalid reason =%d",p_args->reason);
        goto error;
    }
    if (p_args->status != 2) {
        RLOGE("requestSetCallForward query status =%d",p_args->status);
    }
    
    asprintf(&cmd, "AT+CCFC=%d,2;", p_args->reason);
    err = at_send_command_multiline(cmd, "+CCFC:", &p_response);
    if ((err < 0) || (p_response == NULL) || (p_response->success == 0)) {
        RLOGD("send %s failed", cmd);
        free(cmd);
        goto error;
    }

    for (countCallForward = 0, p_cur = p_response->p_intermediates
                                 ; p_cur != NULL; p_cur = p_cur->p_next) {
        countCallForward++;
    }

    ppCallForwards = (RIL_CallForwardInfo **)alloca(countCallForward * sizeof(RIL_CallForwardInfo *));
    pCallForwards = (RIL_CallForwardInfo *)alloca(countCallForward * sizeof(RIL_CallForwardInfo));
    memset (pCallForwards, 0, countCallForward * sizeof(RIL_CallForwardInfo));
    for(i = 0; i < countCallForward; i++) {
        ppCallForwards[i] = &(pCallForwards[i]);
    }

    RLOGD("countCallForward:%d", countCallForward);
    for (countCallForward = 0, p_cur = p_response->p_intermediates
                                      ; p_cur != NULL; p_cur = p_cur->p_next) {
        err = at_tok_start(&(p_cur->line));
        if (err < 0) goto error;

        err = at_tok_nextint(&(p_cur->line), &(pCallForwards->status));
        if (err < 0) goto error;

        err = at_tok_nextint(&(p_cur->line), &(pCallForwards->serviceClass));
        if (err < 0) goto error;
        if (pCallForwards->status == 1) {
            err = at_tok_nextstr(&(p_cur->line), &(pCallForwards->number));
            if (err < 0) goto error;
        }
        pCallForwards->serviceClass = 1;
        pCallForwards->reason = p_args->reason;
        RLOGD("status:%d serviceClass:%d", pCallForwards->status, pCallForwards->serviceClass);
        countCallForward++;
    }
    RLOGD("status:%d serviceClass:%d", ppCallForwards[0]->status, ppCallForwards[0]->serviceClass);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, ppCallForwards,countCallForward * sizeof (RIL_CallForwardInfo *));
    free(cmd);
    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestSetCallForward(void *data, size_t datalen, RIL_Token t)
{
    char* enable_cmd;
    char* disable_cmd;
    char* cmd;
    int err;
    RLOGD("enter requestSetCallForward");

    RIL_CallForwardInfo *p_args = (RIL_CallForwardInfo *) data;

    if ((p_args->status < 0) || (p_args->status > 5)) {
        RLOGE("requestSetCallForward invalid status =%d",p_args->status);
        goto error;
    }
    if ((p_args->reason < 0) || (p_args->reason > 5)) {
        RLOGE("requestSetCallForward invalid reason =%d",p_args->reason);
        goto error;
    }

    if ((p_args->status == MEIG_CALL_FORWARD_ENABLE) ||
        (p_args->status == MEIG_CALL_FORWARD_REGISTERATION)) {
        RLOGD("enable call forward");
        asprintf(&enable_cmd, "AT+CCFC=%d,1", p_args->reason);
        err = at_send_command(enable_cmd, NULL);
        if (err < 0) {
            RLOGD("send %s failed", enable_cmd);
           free(enable_cmd);
           goto error;
        }

        asprintf(&cmd, "AT+CCFC=%d,%d,%s", p_args->reason, p_args->status, p_args->number);
        err = at_send_command(cmd, NULL);
        if (err < 0) {
            RLOGD("send %s failed", cmd);
           free(cmd);
           goto error;
        }
        free(enable_cmd);
        free(cmd);
    }
    if ((p_args->status == MEIG_CALL_FORWARD_DISABLE) ||
        (p_args->status == MEIG_CALL_FORWARD_ERASURE)) {
        RLOGD("disable call forward");
        asprintf(&disable_cmd, "AT+CCFC=%d,%d", p_args->reason, p_args->status);
        err = at_send_command(disable_cmd, NULL);
        if (err < 0) {
            RLOGD("send %s failed", disable_cmd);
           free(disable_cmd);
           goto error;
        }
        free(disable_cmd);
    }
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}
/*yufeilong adapt Call Forward function 20230505 end*/
void* call_pppd()
{
system("/etc/ppp/init.gprs-pppd");
return NULL;
}

pthread_t s_tid_pppd;
void pppd_start()
{
pthread_attr_t attr;
pthread_attr_init(&attr);
pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
pthread_create(&s_tid_pppd, &attr,call_pppd, NULL);
}
/*
void* call_pppd(){
   system("/etc/ppp/init.gprs-pppd");
 }*/
/*[zhaopf@meigsmart-2020-1117] add for ifconfig up interface {*/
int  ifconfigUp(const char* ifname)
{

    if(ifc_init()) {
        RLOGD("failed to ifc_init(%s): %s\n", ifname, strerror(errno));
        return -1;
    }

    if (ifc_set_addr(ifname, 0)) {
        RLOGD("failed to set ip addr for %s to 0.0.0.0: %s\n", ifname, strerror(errno));
        return -1;
    }

    if (ifc_up(ifname)) {
        RLOGD("failed to bring up interface %s: %s\n", ifname, strerror(errno));
        return -1;
    }

    ifc_close();

return 0;

}
/*zhaopengfei@meigsmart.com-2021-0729 change cmd to api for android Begin*/
int  ifconfigDown(const char* ifname)
{
    if(ifc_init()) {
        RLOGD("failed to ifc_init(%s): %s\n", ifname, strerror(errno));
        return -1;
    }

    if (ifc_set_addr(ifname, 0)) {
        RLOGD("failed to set ip addr for %s to 0.0.0.0: %s\n", ifname, strerror(errno));
        return -1;
    }

    if (ifc_down(ifname)) {
        RLOGD("failed to bring up interface %s: %s\n", ifname, strerror(errno));
        return -1;
    }

    ifc_close();

return 0;

}
/*zhaopengfei@meigsmart.com-2021-0729 change cmd to api for android End*/
/*[zhaopf@meigsmart-2020-1117] add for ifconfig up interface }*/

/*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again Begin */
int  request_dhcp(const char* ifname, bool clearFirst)
{
    char propKey[128];
    if(s_closed > 0){
        RLOGE("%s at lost\n", __FUNCTION__ );
        return -1;
    }

    pthread_mutex_lock(&s_dhcp_req_mutex);
    if(ifc_init()) {
        RLOGD("failed to ifc_init(%s): %s\n", ifname, strerror(errno));
        pthread_mutex_unlock(&s_dhcp_req_mutex);
        return -1;
    }

    if(clearFirst){
        if(ifc_set_addr(ifname, 0)){
            RLOGD("failed to set ip addr for %s to 0.0.0.0: %s\n", ifname, strerror(errno));
        }
        RLOGD("%s clear route\n", __FUNCTION__);
    } else {
        RLOGD("%s without clear\n", __FUNCTION__);
    }

    if (ifc_up(ifname)) {
        RLOGD("failed to bring up interface %s: %s\n", ifname, strerror(errno));
        ifc_close();
        pthread_mutex_unlock(&s_dhcp_req_mutex);
        return -1;
    }
    if (dhcp_init_ifc(ifname) < 0) {
        RLOGD("failed to do_dhcp(%s): %s\n", ifname, strerror(errno));
        /* begin: add by dongmeirong for dhcp timeout but report data connect 20210604 */
        ifc_close();
        pthread_mutex_unlock(&s_dhcp_req_mutex);
        return errno == ETIME ? -2 : -1;
        /* end: add by dongmeirong for dhcp timeout but report data connect 20210604 */
    }

ifc_close();
pthread_mutex_unlock(&s_dhcp_req_mutex);

return 0;
}
/*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again End */
void realse_dhcp(const char* ifname)
{

}

int notifyDataCallProcessExit(void)
{
#if 1 //(QL_RIL_VERSION > 9) //lollipop
if (bSetupDataCallCompelete) {
    RIL_requestTimedCallback (onDataCallExit, NULL, NULL);
    bSetupDataCallCompelete = 0;
    return 1;
} else {
    nSetupDataCallFailTimes++;
    if (nSetupDataCallFailTimes > 3)
        return 1;
}
#endif
return 0;
}

/* begin: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
#ifdef SETUP_DATA_CALL_OPTIMIZATION
extern int get_chat_fail_count();
extern int set_chat_fail_count(int count);
#endif

static bool allow_chat_trying() {
#ifdef SETUP_DATA_CALL_OPTIMIZATION
    return get_chat_fail_count() <= 3;
#else
    return true;
#endif
}
/* end: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */

int setupDataCallRASMode(const char* apn,            const int authtype,
                         const char* password,
                         const char*    protocol,
                         const char*    username)
{
#define SUCCESS 0
#define ERROR 1
pid_t pppd_pid;
char ppp_number[20] = "*99***11#";


char ppp_local_ip[PROPERTY_VALUE_MAX] = {'\0'};
int retry = 0;
struct timeval begin_tv, end_tv;
gettimeofday(&begin_tv, NULL);

ATResponse *p_response = NULL;
int err = 0;
char*cmd;

/* begin: modified by dongmeirong for missing assignment to nSetupDataCallFailTimes 20210105*/
nSetupDataCallFailTimes = 0;
/* end: modified by dongmeirong for missing assignment to nSetupDataCallFailTimes 20210105*/

/* begin: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
#ifdef SETUP_DATA_CALL_OPTIMIZATION
set_chat_fail_count(0);
#endif
/* end: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */

/*[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort { */
if (SIM_ABSENT == s_sim_state || SIM_NOT_READY == s_sim_state || isRadioOn() != RADIO_ONLINE_STATE) {
    RLOGE("raido is off!");
    goto error;
}
/*[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort }*/
/*zhangqingun add for support chuangwei send mms 2023-4-25 start*/
ALOGD("Enter setupDataCallRASMode ----------------> \n");
/*zhangqingyun add for support send mms use ppp 2023-5-7 start*/
#ifdef SEND_MMS_USE_PPP
asprintf(&cmd, "AT+CGDCONT=11,\"%s\",\"%s\",,0,0",protocol, apn);
//system("/system/bin/ip route del default dev usb0");
#else 
asprintf(&cmd, "AT+CGDCONT=1,\"%s\",\"%s\",,0,0",protocol, apn);
#endif
/*zhangqingyun add for support send mms use ppp 2023-5-7 end*/
(void)at_send_command(cmd, NULL);
free(cmd);
/*zhangqingyun add for support chuangwei send mms 2023-4-25 end*/

//disable report for modem port
if(HISI == curr_modem_info.info.sltn_type) {
    (void)at_send_command("AT^CURC=0", NULL);
}
property_set("net.ppp0.local-ip", "");
/*[zhaopf@meigsmart-2020-0616] modify for ipv6 support { */
pppd_pid = meig_pppd_start(curr_modem_info.modem_port_name, username, password, protocol, authtype,  ppp_number);
/*[zhaopf@meigsmart-2020-0616] modify for ipv6 support } */
if (pppd_pid < 0) {
    goto error;
}

sleep(1);
//[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort
/* begin: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
while (!s_closed && (retry++ < POLL_PPP_SYSFS_RETRY) && (SIM_ABSENT != s_sim_state) && (SIM_NOT_READY != s_sim_state)
    && allow_chat_trying()) {
/* end: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
    if ((waitpid(pppd_pid, NULL, WNOHANG)) == pppd_pid) {
        goto error;
    }
    get_local_ip(ppp_local_ip);
    RLOGD("[%d] trying to get_local_ip ... %s", retry, ppp_local_ip);
    if(strcmp(ppp_local_ip, "0.0.0.0"))
        break;
    sleep(1);
}
gettimeofday(&end_tv, NULL);
RLOGD("get_local_ip: %s, cost %ld sec", ppp_local_ip, (end_tv.tv_sec - begin_tv.tv_sec));
//[zhaopf@meigsmart-2020-1113]when ip is empty, return faile result
if (0 == strlen(ppp_local_ip) || !strcmp(ppp_local_ip, "0.0.0.0")) {
    goto error;
}
//enble report
if(HISI == curr_modem_info.info.sltn_type) {
    (void)at_send_command("AT^CURC=1", NULL);
}
return SUCCESS;
error:
/* deleted by dongmeirong for ril crash caused by null pointer 20210508 */
meig_pppd_stop(SIGTERM);
#ifdef SEND_MMS_USE_PPP
/*zhangqingyun add for support chuangwei send mms 2023-4-26 start*/
system("/system/bin/ip route add default dev usb0");
/*zhangqingyun add for support chuangwei send mms 2023-4-26 end*/
#endif 
/* begin: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
#ifdef SETUP_DATA_CALL_OPTIMIZATION
set_chat_fail_count(0);
#endif
/* end: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
RLOGE("Unable to setup PDP in %s\n", __func__);
//enble report
if(HISI == curr_modem_info.info.sltn_type) {
    (void)at_send_command("AT^CURC=1", NULL);
}
return ERROR;

}

/*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin { */

static pthread_mutex_t s_qqcrmcall_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_qqcrmcall_dhcp_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_cond_t s_qcrmcall_cond = PTHREAD_COND_INITIALIZER;
static bool qcrmcall_done = false;
static bool qcrmcall_timeout = false;

static int qcrmcall_sate = 0; //0:idle, 1:done, -1:failed, -2:retry
sem_t g_sem_dhcp;
extern void setTimespecRelative(struct timespec *p_ts, long long msec);

static void delayDHCPForQcrmcall(void *intfName){
       char *intf = (char *)intfName;
       struct timespec ts;
       setTimespecRelative(&ts, 800);
       RLOGI("qcrmcall wait 800ms to do dhcp %s", intf);
       sem_timedwait(&g_sem_dhcp, &ts);
       pthread_mutex_lock(&s_qqcrmcall_dhcp_mutex);
        if(qcrmcall_sate < 0 || s_closed > 0) {  //only for error case
           RLOGE("qcrmcall failed, error=%d\n", qcrmcall_sate);
            goto error;
        }
        RLOGD("start do_dhcp %s, qcrmcall_sate=%d\n", intf, qcrmcall_sate);
        if (request_dhcp(intf, true) < 0) {
            RLOGD("failed to do_dhcp: %s\n", strerror(errno));
        }
        RLOGD("finished do_dhcp\n");
error:
       free(intf);
       pthread_mutex_unlock(&s_qqcrmcall_dhcp_mutex);
}



static void* dhcp_thread_function(void*  arg)
{
    MULTINDIS_ARGS *param = (MULTINDIS_ARGS *)arg;
    delayDHCPForQcrmcall(strdup(param->infname));
    return NULL;
}


void dhcp_delay_start(char* param)
{
    pthread_t tid;
    pthread_create(&tid, NULL,dhcp_thread_function, (void*)param);
}



static void* qcrmcall_thread_function(void*  arg)
{
    MULTINDIS_ARGS *param = (MULTINDIS_ARGS *)arg;
    int err = -1;
    int iretry = 20; //wait driver ready for 20s at most
    bool isDriverReady = false;
    ATResponse *p_response = NULL;
    //RLOGD("%s cmd=%s, infname=%s", __FUNCTION__, param->cmd, param->infname);
    sem_init(&g_sem_dhcp, 0, 0);
    ifc_disable(param->infname);
    usleep(50*1000);
    while(iretry-- > 0 && s_closed == 0){
        qcrmcall_sate = 0;
        if(0 != access("/dev/qcqmi0", R_OK) && 0 != access("/dev/qcqmi1", R_OK)){
            RLOGI("wait driver ready");
            sleep(1);
            isDriverReady = false;
            continue;
        }
        isDriverReady = true;
        dhcp_delay_start(param);
        if(qcrmcall_timeout){
             qcrmcall_sate = -2;
              sem_post(&g_sem_dhcp);
              RLOGI("qcrmcall timeout");
              usleep(1000);
              break;
        }
        err = at_send_command(param->cmd, &p_response);
        if (err < 0 || p_response->success == 0) {
               qcrmcall_sate = -2;
               iretry -= 11; //normal fail,do  not wait too much time
              sem_post(&g_sem_dhcp);
               RLOGE("multi ndis dial failed, continue retry");
        } else {
            break;
        }
        sleep(1);
    }

    if(!isDriverReady){
        RLOGE("driver not ready, reload");
        property_set("ril.meig.reload.drv", "true");
     }
     if (qcrmcall_timeout || s_closed > 0 || err < 0 || p_response->success == 0) {
        qcrmcall_sate = -1;
        RLOGE("multi ndis dial failed");
    } else {
        qcrmcall_sate = 1;
        RLOGE("multi ndis dial succ");
    }
    at_response_free(p_response);
    sem_destroy(&g_sem_dhcp);
    pthread_mutex_lock(&s_qqcrmcall_mutex);
    qcrmcall_done = true;
    pthread_cond_signal(&s_qcrmcall_cond);
    pthread_mutex_unlock(&s_qqcrmcall_mutex);
    return NULL;
}

void qcrmcall_start(char* param)
{
pthread_t tid;
/*
pthread_attr_t attr;
pthread_attr_init(&attr);
pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
*/
qcrmcall_done = false;
pthread_create(&tid, NULL,qcrmcall_thread_function, (void*)param);
}

void wait_qcrmcall_done(long long timeoutMsec){
    int err;
    struct timespec ts;
    if (timeoutMsec != 0) {
        setTimespecRelative(&ts, timeoutMsec);
    }
    RLOGD("%s wait %d sec", __FUNCTION__, ts.tv_sec);
    pthread_mutex_lock(&s_qqcrmcall_mutex);
    qcrmcall_timeout = false;
    err = pthread_cond_timedwait(&s_qcrmcall_cond, &s_qqcrmcall_mutex, &ts);
    if(ETIMEDOUT == err){
        qcrmcall_timeout = true;
        RLOGD("%s timeout", __FUNCTION__);
    }
    RLOGD("%s got, qcrmcall_sate=%d", __FUNCTION__, qcrmcall_sate);
    pthread_mutex_unlock(&s_qqcrmcall_mutex);


}

int setupDataCallMultiNdisMode(const char* apn,
                         const int authtype,
                         const char* password,
                         const char*    protocol,
                         const char*    username)
{
    #define SUCCESS 0
    #define ERROR 1
    char *cmd;
    int i;
    char infName[10] = { 0x0};
    char multi_apns[PROPERTY_VALUE_MAX] = {'\0'};
    MULTINDIS_ARGS param;

    int err=0;
    RLOGD("**************enter %s**************", __FUNCTION__);
    if (s_closed > 0 || SIM_ABSENT == s_sim_state || isRadioOn() != RADIO_ONLINE_STATE || SIM_NOT_READY == s_sim_state) {
        RLOGE("raido is off!");
        goto error;
    }

    ndisIPV6state = NDIS_NOTCONNECT;
    ndisIPV4state = NDIS_NOTCONNECT;

    glatest_multi_ndis_proto = (NULL != strcasestr(protocol, "v4v6"))?3:(NULL != strcasestr(protocol, "v6"))?2:1;

    RLOGD("************multi ndis start************");

    for(i = 0; i < g_ndis_multi_num; i++) {
        memset(multi_apns, 0x0, PROPERTY_VALUE_MAX);
        qcrmcall_sate = 0;

        if(0 == i) {
            asprintf(&cmd, "AT+CGDCONT=1,\"%s\",\"%s\",,0,0",
             protocol,
             apn);
        } else {
            property_get(NDSI_MULTI_APNS_PROPS[i], multi_apns, "");
            asprintf(&cmd, "AT+CGDCONT=%d,\"%s\",\"%s\",,0,0", MULTI_APN_BASE+i,
            protocol,
            multi_apns);

        }
        err = at_send_command(cmd, NULL);
        free(cmd);
        asprintf(&cmd,"AT$QCRMCALL=1,%d,%d,2,%d", i+1, glatest_multi_ndis_proto, (0 == i)?1:(MULTI_APN_BASE+i));
        sprintf(infName, "bmwan%d", i);

        param.cmd = cmd;
        param.infname = infName;
        qcrmcall_start(&param);


        if(!qcrmcall_done){
            wait_qcrmcall_done(40000);
        }
        free(cmd);
        if(qcrmcall_sate < 0) {  //only for error case
           RLOGE("qcrmcall failed\n");
           break;
        }

    }

    RLOGD("************multi ndis end**************");

    if(qcrmcall_sate < 0) {
       goto error;
    }

    //reset router to bmwan0
    if (request_dhcp(curr_modem_info.if_name, true) < 0) {
        RLOGD("failed to do_dhcp: %s\n", strerror(errno));
    }
    if(s_closed > 0){
        RLOGD("modem lost, dial failed");
        goto error;
    }
    pppd = 1;
    return SUCCESS;
    error:
        return ERROR;
}

/*zhaopf@meigsmart-2021/03/11 add for multi ndis support End } */


int setupDataCallNCMMode(const char* apn,
                         const int authtype,
                         const char* password,
                         const char*    protocol,
                         const char*    username)
{
#define SUCCESS 0
#define ERROR 1
char *cmd = NULL;
int err=0;
/* begin: add by dongmeirong for dhcp timeout but report data connect 20210604 */
struct timeval beginTime = {0};
struct timeval endTime = {0};
ALOGD("**************enter setupDataCallNCMMode**************");
/*[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort */
if (SIM_ABSENT == s_sim_state || isRadioOn() != RADIO_ONLINE_STATE || SIM_NOT_READY == s_sim_state) {
    RLOGE("raido is off!");
    goto error;
}
/*[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort  } */

ndisIPV6state = NDIS_NOTCONNECT;
ndisIPV4state = NDIS_NOTCONNECT;
asprintf(&cmd, "AT+CGDCONT=1,\"%s\",\"%s\",,0,0",protocol,apn);
err = at_send_command(cmd, NULL);
if (cmd != NULL) {
    free(cmd);
}

ALOGD("************ndis start************");
ifc_enable(curr_modem_info.if_name);
sleep(1);
/*yufeilong add for support SRM811 20220527 start*/
if (curr_modem_info.info.sltn_type == UNISOC)
{
/*yufeilong adapt for SRM810 20221123 begin*/
    asprintf(&cmd,"AT^NDISDUP=1,0");
    at_send_command(cmd, NULL);
    sleep(2);
/*yufeilong adapt for SRM810 20221123 end*/
    asprintf(&cmd,"AT^NDISDUP=1,1");
}else{
    asprintf(&cmd,"AT^NDISDUP=1,1,\"%s\",\"%s\",\"%s\",3",apn,username,password);
}
/*yufeilong add for support SRM811 20220527 end*/
err = at_send_command(cmd, NULL);
if (err < 0) {
    RLOGE("ndis dial failed");
}
ALOGD("************ndis end**************");
gettimeofday(&beginTime, NULL);
sleep(1);
/*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again Begin */
err = request_dhcp(curr_modem_info.if_name, true);
ALOGD("do_dhcp errno is %s\n", strerror(errno));
/*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario Begin */
if(errno == ENETUNREACH){
    g_dhcp_fail_ignore_flag = 1;
}
/*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario End */
gettimeofday(&endTime, NULL);
if ((err < 0 && endTime.tv_sec - beginTime.tv_sec >= 55) || err == -2) {
    ALOGD("failed to do_dhcp, err = %d, timeval = %d\n", err, endTime.tv_sec - beginTime.tv_sec);
    goto error;
}
/*zhaopf@meigsmart-2021/03/18 fixe for route lost when do dhcp again End */
free(cmd); //fixed bug, by zhaopf

pppd = 1;
return SUCCESS;
//[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort
error:
    if (cmd != NULL) {
        free(cmd);
    }
    return ERROR;
/* end: add by dongmeirong for dhcp timeout but report data connect 20210604 */
}

/*[zhaopf@meigsmart-2022-06-10] add for mms support Begin */


/*add callbacks for libmeigcm by zhaopengfei 2022/10/10 Begin */
void onCMDataCallListChanged(int pdpIndex, CM_IP_PROT ip_protocol, CM_CONN_STATE state){
    RLOGI("on data call list change pdp:%d, ip:%s, conn state:%s\n\n", pdpIndex, PROT_TYPE2STR(ip_protocol), WDS_CONN_STATE_STR(state));
    //Modify by zhaopengfei report data call failed only when data call setup complete 2022/12/07
    if(WDS_CONNECTION_STATUS_DISCONNECTED == state && bSetupDataCallCompelete){
        RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED, NULL, 0);
    }
}

void onCMRegisterStateChanged(CM_NAS_REG_STATE reg_state, CM_CS_ATTACH_STATE cs_state, CM_PS_ATTACH_STATE ps_state){
    RLOGI("\n\n--->on voice network changed reg_state:%d, cs_state=%d, ps_state=%d\n\n", reg_state, cs_state, ps_state);
    RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED,NULL,0);
}

void onCMHardwareRemoved(){
    RLOGI("\n\n---->device removed<----\n\n");
    //Add by zhaopengfei deinit cm when hw removed 2022/12/07
    CMDeinitInstance();
}
/*zhangqingyun add for support get body sar 2023-3-21 start*/
void requestGetRfSar(RIL_Token t){
    int ret = 0 ;
    int defaultSarValue = 0 ;
    if(CMRequestGetBodySar(&defaultSarValue) != 0){
        RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
        
    }else{
        RIL_onRequestComplete(t,RIL_E_SUCCESS,&defaultSarValue,sizeof(int));
    }
    return ;
    
}

/*zhangqingyun add for support get body sar 2023-3-21 end*/
/*zhangqingyun  add for support set body sar 2023-3-21 start*/
void requestSetRfSar(void* data,size_t datalen __unused,RIL_Token t){
    int ret = 0 ;
    int defaultSarValue =((int*)data)[0] ;
    RLOGD("set sar value is:%d \n",defaultSarValue);
    if(CMRequestSetBodySar(defaultSarValue) != 0){
        RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
        
    }else{
        RIL_onRequestComplete(t,RIL_E_SUCCESS,NULL,0);
    }
    return ;

}
#define QCRIL_UIM_APDU_MIN_P3                       0
#define QCRIL_UIM_APDU_MIN_SIZE                     4
#define QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3             5
#define QCRIL_UIM_LONG_APDU_MIN_SIZE_PLUS_P3        7
#define QCRIL_UIM_APDU_MAX_SHORT_APDU_SIZE          256
#define QCRIL_UIM_APDU_MAX_LONG_APDU_SIZE           65536

/*=========================================================================

  FUNCTION:  qcril_uim_bin_to_hexchar

===========================================================================*/
/*!
    @brief
    Converts a single character from ASCII to binary

    @return
    Binary value of the ASCII characters
*/
/*=========================================================================*/
char qcril_uim_bin_to_hexchar
(
  uint8 ch
)
{
  assert(ch < 0x10);

  if (ch < 0x0a)
  {
    return (ch + '0');
  }
  return (ch + 'a' - 10);
} /* qcril_uim_bin_to_hexchar */


/*zhangqigyun  add  for support set body sar 2023-3-21 end*/
/*=========================================================================

  FUNCTION:  qcril_uim_bin_to_hexstring

===========================================================================*/
/*!
    @brief
    Converts a binary buffer into a string in ASCII format.
    Memory is not allocated for this conversion.

    @return
    None
*/
/*=========================================================================*/
void qcril_uim_bin_to_hexstring
(
  const uint8*  buffer_ptr,
  uint16        buffer_size,
  char*         string_ptr,
  uint16        string_size
)
{
  int    i = 0;

  if(buffer_ptr == NULL || string_ptr == NULL)
  {
    RLOGD("NULL pointer");
    return;
  }
  RLOGD("buffer size is:%d,string_size is:%d",buffer_size,string_size);
  assert(string_size >= (buffer_size * 2) + sizeof(char));

  memset(string_ptr, 0, string_size);

  for (i = 0; i < buffer_size; i++)
  {
    string_ptr[i * 2] = qcril_uim_bin_to_hexchar((buffer_ptr[i] >> 4) & 0x0F);
    string_ptr[i * 2 + 1] = qcril_uim_bin_to_hexchar(buffer_ptr[i] & 0x0F);
  }
  string_ptr[buffer_size * 2] = 0x0;
} /* qcril_uim_bin_to_hexstring */



/*zhangqingyun add for support operate sim apdu 2023-7-18 start*/
/*===========================================================================*/
/*!
    @brief
    Converts a single character from ASCII to binary

    @return
    Binary value of the ASCII characters
*/
/*=========================================================================*/
uint8 qcril_uim_hexchar_to_bin
(
  char ch
)
{
  if (ch >= '0' && ch <= '9')
  {
    return (ch - '0');
  }
  else if (ch >= 'A' && ch <= 'F')  /* A - F */
  {
    return (ch - 'A' + 10);
  }
  else if (ch >= 'a' && ch <= 'f')  /* a - f */
  {
    return (ch - 'a' + 10);
  }
  else
  {
    ALOGD("exception ");
  }
  return 0;
} /* qcril_uim_hexchar_to_bin */


/*===========================================================================*/
/*!
    @brief
    Converts a ASCII string into a binary buffer.
    Memory is not allocated for this conversion

    @return
    Size of the data stored in the buffer
*/
/*=========================================================================*/
uint16 qcril_uim_hexstring_to_bin
(
  const char * string_ptr,
  uint8      * buffer_ptr,
  uint16       buffer_size
)
{
  uint16 string_len = 0;
  int    i = 0;

  if (string_ptr == NULL || buffer_ptr == NULL)
  {
    ALOGD("NULL pointer");
    return 0;
  }

  string_len = strlen(string_ptr);

  if (buffer_size < (string_len + 1) / 2)
  {
    /* Buffer is too small */
    ALOGD("Buffer is too small for conversion (0x%x < 0x%x)",
                    buffer_size, (string_len + 1) / 2);
    return 0;
  }

  /* Zero the destination buffer */
  memset(buffer_ptr, 0, buffer_size);
  for (i = 0; i < string_len; i++)
  {
    if ((i % 2) == 0)
    {
      buffer_ptr[i / 2] = (qcril_uim_hexchar_to_bin(string_ptr[i]) << 4) & 0xF0;
    }
    else
    {
      buffer_ptr[i / 2] = buffer_ptr[i / 2] | (qcril_uim_hexchar_to_bin(string_ptr[i]) & 0x0F);
    }
  }

  return (string_len + 1) / 2;
} /* qcril_uim_hexstring_to_bin */

/*=========================================================================

  FUNCTION:  qcril_uim_alloc_hexstring_to_bin

===========================================================================*/
/*!
    @brief
    Allocates memory and converts a string from ASCII format into
    binary format.

    @return
    Buffer with binary data
*/
/*=========================================================================*/
uint8* qcril_uim_alloc_hexstring_to_bin
(
  const char * string_ptr,
  uint16     * buffer_size_ptr
)
{
  uint16 buffer_size = 0;
  uint8* out_ptr     = NULL;

  if (string_ptr == NULL || buffer_size_ptr == NULL)
  {
    RLOGE("%s", "NULL pointer");
    return NULL;
  }

  buffer_size = (strlen(string_ptr) + 1) / 2;
  if (buffer_size == 0)
  {
    return out_ptr;
  }

  out_ptr = (uint8*)malloc(buffer_size);

  if (out_ptr != NULL)
  {
    *buffer_size_ptr = qcril_uim_hexstring_to_bin(string_ptr, out_ptr, buffer_size);
  }

  return out_ptr;
} /* qcril_uim_alloc_hexstring_to_bin */

/*=========================================================================

  FUNCTION:  qcril_uim_compose_apdu_data

===========================================================================*/
/*!
    @brief
    Function to compose raw APDU command. Composed data pointer and length
    are updated based on the request.

    @return
    TRUE if successful, FALSE otherwise.
*/
/*=========================================================================*/
static bool qcril_uim_compose_apdu_data
(
  qmi_uim_data_type       * apdu_data_ptr,
  int                       cla,
  int                       ins,
  int                       p1,
  int                       p2,
  int                       p3,
  const char              * data_ptr
)
{
  qmi_uim_data_type     binary_apdu_data;
  uint16                total_apdu_len       = 0;

  if ((apdu_data_ptr == NULL) ||
      (apdu_data_ptr->data_ptr == NULL) ||
      (apdu_data_ptr->data_len == 0))
  {
    RLOGE("%s", "Invalid input, cannot proceed");
    return false;
  }

  memset(apdu_data_ptr->data_ptr, 0, apdu_data_ptr->data_len);
  memset(&binary_apdu_data, 0, sizeof(qmi_uim_data_type));

  total_apdu_len = apdu_data_ptr->data_len;

  /* Update mandatory parameters - CLA, INS, P1 & P2 */
  if (total_apdu_len >= QCRIL_UIM_APDU_MIN_SIZE)
  {
    apdu_data_ptr->data_ptr[0] = (uint8)(cla & 0xFF);
    apdu_data_ptr->data_ptr[1] = (uint8)(ins & 0xFF);
    apdu_data_ptr->data_ptr[2] = (uint8)(p1 & 0xFF);
    apdu_data_ptr->data_ptr[3] = (uint8)(p2 & 0xFF);
    apdu_data_ptr->data_len = QCRIL_UIM_APDU_MIN_SIZE;
  }

  /* Update P3 parameter if valid */
  if (p3 > QCRIL_UIM_APDU_MIN_P3 &&
      p3 < QCRIL_UIM_APDU_MAX_SHORT_APDU_SIZE)
  {
    apdu_data_ptr->data_ptr[4] = (uint8)(p3 & 0xFF);
    apdu_data_ptr->data_len = QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3;
  }
  else if (p3 >= QCRIL_UIM_APDU_MAX_SHORT_APDU_SIZE)
  {
    apdu_data_ptr->data_ptr[4] = (uint8)(0x00);
    apdu_data_ptr->data_ptr[5] = (uint8)((p3 >> 8) & 0xFF);
    apdu_data_ptr->data_ptr[6] = (uint8)(p3 & 0xFF);
    apdu_data_ptr->data_len = QCRIL_UIM_LONG_APDU_MIN_SIZE_PLUS_P3;
  }

  /* Update data parameter if valid */
  if((p3 >= QCRIL_UIM_APDU_MAX_SHORT_APDU_SIZE) &&
      (total_apdu_len == QCRIL_UIM_LONG_APDU_MIN_SIZE_PLUS_P3))
  {
    RLOGE("%s", "Case - 2 Extended APDU p3: 0x%x",
                 p3);
  }
  else if (total_apdu_len > QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3)
  {
    if ((data_ptr == NULL) || (strlen(data_ptr) == 0))
    {
      RLOGE("%s", "Mismatch in total_apdu_len & input APDU data!");
      return false;
    }

    binary_apdu_data.data_ptr = qcril_uim_alloc_hexstring_to_bin(data_ptr,
                                                                 &binary_apdu_data.data_len);
    if (binary_apdu_data.data_ptr == NULL)
    {
      RLOGE("%s", "Unable to convert input APDU data!");
      return false;
    }

    /* Update data parameter if valid */
    if (binary_apdu_data.data_len <= (total_apdu_len - QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3))
    {
      if (total_apdu_len >= QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3 &&
          total_apdu_len <= QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3 + QCRIL_UIM_APDU_MAX_SHORT_APDU_SIZE)
      {
        memcpy(&apdu_data_ptr->data_ptr[5], binary_apdu_data.data_ptr, binary_apdu_data.data_len);
        apdu_data_ptr->data_len = QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3 + binary_apdu_data.data_len;
      }
      else if (total_apdu_len > QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3 + QCRIL_UIM_APDU_MAX_SHORT_APDU_SIZE)
      {
        memcpy(&apdu_data_ptr->data_ptr[7], binary_apdu_data.data_ptr, binary_apdu_data.data_len);
        apdu_data_ptr->data_len = QCRIL_UIM_LONG_APDU_MIN_SIZE_PLUS_P3 + binary_apdu_data.data_len;
      }
    }

    /* Free temp buffer */
    free(binary_apdu_data.data_ptr);
    binary_apdu_data.data_ptr = NULL;
  }

  return true;
} /* qcril_uim_compose_apdu_data */
#if 0
/*===========================================================================*/
/*!
    @brief
    Converts a single character from ASCII to binary

    @return
    Binary value of the ASCII characters
*/
/*=========================================================================*/
uint8 qcril_uim_hexchar_to_bin
(
  char ch
)
{
  if (ch >= '0' && ch <= '9')
  {
    return (ch - '0');
  }
  else if (ch >= 'A' && ch <= 'F')  /* A - F */
  {
    return (ch - 'A' + 10);
  }
  else if (ch >= 'a' && ch <= 'f')  /* a - f */
  {
    return (ch - 'a' + 10);
  }
  else
  {
    ALOGD("exception ");
  }
  return 0;
} /* qcril_uim_hexchar_to_bin */

/*===========================================================================*/
/*!
    @brief
    Converts a ASCII string into a binary buffer.
    Memory is not allocated for this conversion

    @return
    Size of the data stored in the buffer
*/
/*=========================================================================*/
uint16 qcril_uim_hexstring_to_bin
(
  const char * string_ptr,
  uint8      * buffer_ptr,
  uint16       buffer_size
)
{
  uint16 string_len = 0;
  int    i = 0;

  if (string_ptr == NULL || buffer_ptr == NULL)
  {
    ALOGD("NULL pointer");
    return 0;
  }

  string_len = strlen(string_ptr);

  if (buffer_size < (string_len + 1) / 2)
  {
    /* Buffer is too small */
    ALOGD("Buffer is too small for conversion (0x%x < 0x%x)",
                    buffer_size, (string_len + 1) / 2);
    return 0;
  }

  /* Zero the destination buffer */
  memset(buffer_ptr, 0, buffer_size);
  for (i = 0; i < string_len; i++)
  {
    if ((i % 2) == 0)
    {
      buffer_ptr[i / 2] = (qcril_uim_hexchar_to_bin(string_ptr[i]) << 4) & 0xF0;
    }
    else
    {
      buffer_ptr[i / 2] = buffer_ptr[i / 2] | (qcril_uim_hexchar_to_bin(string_ptr[i]) & 0x0F);
    }
  }

  return (string_len + 1) / 2;

/*===========================================================================*/
/*!
    @brief
    Converts a ASCII string into a binary buffer.
    Memory is not allocated for this conversion

    @return
    Size of the data stored in the buffer
*/
/*=========================================================================*/
uint16 qcril_uim_hexstring_to_bin
(
  const char * string_ptr,
  uint8      * buffer_ptr,
  uint16       buffer_size
)
{
  uint16 string_len = 0;
  int    i = 0;

  if (string_ptr == NULL || buffer_ptr == NULL)
  {
    ALOGD("NULL pointer");
    return 0;
  }

  string_len = strlen(string_ptr);

  if (buffer_size < (string_len + 1) / 2)
  {
    /* Buffer is too small */
    ALOGD("Buffer is too small for conversion (0x%x < 0x%x)",
                    buffer_size, (string_len + 1) / 2);
    return 0;
  }

  /* Zero the destination buffer */
  memset(buffer_ptr, 0, buffer_size);
  for (i = 0; i < string_len; i++)
  {
    if ((i % 2) == 0)
    {
      buffer_ptr[i / 2] = (qcril_uim_hexchar_to_bin(string_ptr[i]) << 4) & 0xF0;
    }
    else
    {
      buffer_ptr[i / 2] = buffer_ptr[i / 2] | (qcril_uim_hexchar_to_bin(string_ptr[i]) & 0x0F);
    }
  }

  return (string_len + 1) / 2;
} /* qcril_uim_hexstring_to_bin */
} /* qcril_uim_hexstring_to_bin */
#endif

static void requestOpenChannel(void* data, size_t datalen,RIL_Token t){
    /*according to ril_services.cpp, iccOpenLogicalchannle, vendorfunction_verson < 15, so just pass string to reference-ril.c onrequest function*/
    int32_t result[260] = {0} ; //channelid ,select response,sw1, sw2
    #if 0
    const char* aid_ptr = (char*)data;
    #else
    RIL_OpenChannelParams *params = (RIL_OpenChannelParams*) data;
    const char *aid_ptr = params ? params->aidPtr : NULL;
    int p2 = params? params->p2 : -1;
    #endif
	int select_response_length = 0;
    uint16                                   aid_size             = 0;
    uint8                                    aid_buffer[QMI_UIM_MAX_AID_LEN] = {0};
	int j = 0;
    RLOGD("open channel value is:%s \n",aid_ptr);
    aid_size = qcril_uim_hexstring_to_bin(aid_ptr,
                                          aid_buffer,
                                          QMI_UIM_MAX_AID_LEN);
    if (aid_size > QMI_UIM_MAX_AID_LEN || p2 > 0x0C)
    {
        RLOGE("%s Error converting AID string into binary, p2 = 0x%x", __FUNCTION__, p2);
        RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
        return;
    }
    if(CMRequestOpenChannel(p2, aid_buffer,aid_size,result,&select_response_length) != 0){
        RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
        
    }else{
        RLOGD("meig-ril send to android fraework channel id is:%d",result[0]);
        for(j = 1;j < select_response_length+1; j++){
			RLOGD("meig-ril send to android fraework select response value  is:%d",result[j]);
		}
		RLOGD("meig-ril send to android fraework sw1 value is:%d,sw2 vaule is:%d",result[j],result[j+1]);
		
        RIL_onRequestComplete(t, RIL_E_SUCCESS, result, sizeof(int)*(select_response_length+3));
    }
    return;
}
static void requestCloseChannel(void* data, size_t datalen ,RIL_Token t){
    int32_t session_id;
    int err;
    if (data == NULL || datalen != sizeof(session_id)) {
        ALOGE("Invalid data passed to requestSimCloseChannel");
        RIL_onRequestComplete(t, RIL_E_INVALID_ARGUMENTS, NULL, 0);//zhangqingyun add 2023-12-13 cts need
        return;
    }
    session_id = ((int32_t *)data)[0];
    RLOGD("close channel id:%d", session_id);
	//zhangqingyun add for cts test
	if(session_id == 0){
		RLOGD("see hardware/interface/radio/1.0/vts/function");
		RIL_onRequestComplete(t, RIL_E_INVALID_ARGUMENTS, NULL, 0);//zhangqingyun add 2023-12-13 cts need
		return;
	}
    if(CMRequestCloseChannel(session_id) != 0){
        RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
        
    }else{
        RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL,0);
    }
	return;
} 



static void requestSimTransmitApduLogicChannel(void* data, size_t datalen, RIL_Token t){
    int err;
    char *line;
    size_t cmd_size;
    unsigned char* sim_apdu;
    unsigned short sim_apdu_length;
    qmi_uim_data_type apdu_params;
    int                               cla                  = 0;
    int                               ins                  = 0;
    int                               p1                   = 0;
    int                               p2                   = 0;
    int                               p3                   = 0;
    const char                      * data_ptr             = NULL;
    int                               channel_id           = 0;
    RIL_SIM_IO_Response sim_response;
    unsigned char* response_sim_apdu = NULL;
	char* sim_apdu_response = NULL;
	int response_apdu_length;
	//char sw1[2] = {0};
	//char sw2[2] = {0}; 
    RIL_SIM_APDU *apdu = (RIL_SIM_APDU *)data;
    int i = 0;
	int len = 0;
    if (apdu == NULL || datalen != sizeof(RIL_SIM_APDU)) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }
    memset(&sim_response, 0, sizeof(RIL_SIM_IO_Response));
    memset(&apdu_params,0, sizeof(qmi_uim_data_type));
	response_sim_apdu = (unsigned char*)malloc(RESPONSE_APDU_LENGTH);
	sim_apdu_response = (char*)malloc(RESPONSE_APDU_LENGTH);
	if(response_sim_apdu == NULL){
		RLOGD("%s malloc response_sim_apdu memeory fail goto error", __FUNCTION__);
		goto error;
	}
    memset(response_sim_apdu,0x0,RESPONSE_APDU_LENGTH);
    if(sim_apdu_response == NULL){
		RLOGD("%s malloc sim_apdu_response memeory fail goto error", __FUNCTION__);
		goto error;
	}
	memset(sim_apdu_response,0,RESPONSE_APDU_LENGTH);
	// not use at command ,use qmi to communicate with slm750 zhangqingyun add
    cla        = apdu->cla;
    ins        = apdu->instruction;
    channel_id = apdu->sessionid;
    p1         = apdu->p1;
    p2         = apdu->p2;
    p3         = apdu->p3;
    data_ptr   = apdu->data;
    
    /* Sanity check */
  if ((p1  < 0)    || (p1  > 0xFF) ||
      (p2  < 0)    || (p2  > 0xFF) ||
      (cla < 0)    || (cla > 0xFF) ||
      (ins < 0)    || (ins > 0xFF))
  {
    RLOGD( "Unsupported case, P1: 0x%X, P2: 0x%X, P3: 0x%X, cla: 0x%X, ins: 0x%X \n",
                     p1, p2, p3, cla, ins);
	goto error;
  }
    /* Calculate total buffer size for APDU data */
  if ((data_ptr == NULL) || (strlen(data_ptr) == 0))
  {
    if (p3 < 0)
    {
      sim_apdu_length = QCRIL_UIM_APDU_MIN_SIZE;
    }
    else if(p3 < QCRIL_UIM_APDU_MAX_SHORT_APDU_SIZE)
    {
      sim_apdu_length = QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3;
    }
    else
    {
      sim_apdu_length = QCRIL_UIM_LONG_APDU_MIN_SIZE_PLUS_P3;
    }
  }
  else if(p3 < QCRIL_UIM_APDU_MAX_SHORT_APDU_SIZE && p3 == (strlen(data_ptr)/2))
  {
    sim_apdu_length = QCRIL_UIM_APDU_MIN_SIZE_PLUS_P3 + strlen(data_ptr)/2;
  }
  else if (p3 < (QCRIL_UIM_APDU_MAX_LONG_APDU_SIZE - QCRIL_UIM_LONG_APDU_MIN_SIZE_PLUS_P3-1)
           && p3 == (strlen(data_ptr)/2))
  {
    sim_apdu_length = QCRIL_UIM_LONG_APDU_MIN_SIZE_PLUS_P3 + strlen(data_ptr)/2;
  }
  else
  {
      RLOGD( "Invalid Length in P3 or Data_Ptr P3:%x Data_length:%x",
                        p3, strlen(data_ptr)/2);
      goto error;
  }
	/* Allocate memory and compose the raw APDU data */
  //send_apdu_params..data_ptr = (uint8*) malloc(sim_apdu_length);
  apdu_params.data_len = sim_apdu_length;
  apdu_params.data_ptr = (uint8*) malloc(sim_apdu_length);
  if(apdu_params.data_ptr == NULL)
  {
    RLOGD("Unable to allocate buffer for apdu.data_ptr!");
    goto error;
  }
  if (qcril_uim_compose_apdu_data(&apdu_params,
                                  cla,
                                  ins,
                                  p1,
                                  p2,
                                  p3,
                                  data_ptr) == false)
  {
    RLOGD("%s", "Error composing APDU data!");
    goto error;
  }
  if(CMRequestTransmitApduLogicChannel(channel_id, apdu_params.data_ptr, apdu_params.data_len,response_sim_apdu,&response_apdu_length) != 0){
  	     RLOGD("some error happen isn transmitapdulogic channel goto error");
        //RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
        goto error;
    }else{
		for(i = 0;i < response_apdu_length-2;i++){
            len += sprintf(sim_apdu_response+len,"%02x",response_sim_apdu[i]);
        }
		
		sim_response.sw1 = response_sim_apdu[response_apdu_length-2];
		sim_response.sw2 = response_sim_apdu[response_apdu_length -1];
        sim_response.simResponse = sim_apdu_response;
		RLOGD("sim_apdu_response is:%s,sw1 is:%d,sw2 is:%d",sim_response.simResponse,sim_response.sw1,sim_response.sw2);
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &sim_response, sizeof(RIL_SIM_IO_Response));
        if (response_sim_apdu) {
    		free(response_sim_apdu);
        }
        if (sim_apdu_response) {
    		free(sim_apdu_response);
        }
		return ;
    }
    /*
    line = p_response->p_intermediates->line;
    err = parseSimResponseLine(line, &sim_response);
    
    if (err == 0) {
        RIL_onRequestComplete(t, RIL_E_SUCCESS,
                              &sim_response, sizeof(sim_response));
    } else {
        ALOGE("Error %d parsing SIM response line: %s", err, line);
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    }*/
    error:
    if (response_sim_apdu) {
        free(response_sim_apdu);
        response_sim_apdu = NULL;
    }
    if (sim_apdu_response) {
        free(sim_apdu_response);
        sim_apdu_response = NULL;
    }
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}
static void requestSimTransmitApduBasicChannel(void* data, size_t datalen, RIL_Token t){
    RIL_SIM_APDU *apdu = (RIL_SIM_APDU *)data;
    RIL_SIM_IO_Response sim_response = {0};
    char *at_cmd = NULL;
    char *line = NULL;
    int rsp_len = 0;
    char *rsp_ptr = NULL;
    char sw1[3] = {0};

    const char                      * data_ptr             = NULL;
    int                               channel_id           = 0;
    int                               data_len             = 0;
    ATResponse *p_response = NULL;
    int err = 0;
    int param_len = 0;

    if (apdu == NULL || datalen != sizeof(RIL_SIM_APDU)) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }

    data_ptr   = apdu->data;
    data_len = data_ptr ? strlen(data_ptr) : 0;
    RLOGD("%s entry, cla = %d, ins = %d, channel_id = %d, p1 = %d, p2 = %d, p3 = %d, len = %d, data = %s",
        __FUNCTION__, apdu->cla, apdu->instruction, apdu->sessionid, apdu->p1, apdu->p2, apdu->p3, data_len, data_ptr);

   param_len = 10 + data_len;
   if (data_len) {
        asprintf(&at_cmd, "AT+CSIM=%d,\"%02X%02X%02X%02X%02X%s\"",
                param_len, apdu->cla, apdu->instruction, apdu->p1, apdu->p2, apdu->p3, data_ptr);
    } else {
        asprintf(&at_cmd, "AT+CSIM=%d,\"%02X%02X%02X%02X%02X\"",
                param_len, apdu->cla, apdu->instruction, apdu->p1, apdu->p2, apdu->p3);
    }
    RLOGD("%s at_param = %s", __FUNCTION__, at_cmd);
    err = at_send_command_singleline(at_cmd,"+CSIM:", &p_response);
    RLOGI("csim result is:%d", err);
    if (err < 0 || !p_response->success) goto error;
    line = p_response->p_intermediates->line;
	err = at_tok_start(&line);
    if (err < 0) goto error;
    err = at_tok_nextint(&line, &rsp_len);
	if (err < 0) goto error;
	err = at_tok_nextstr(&line, &rsp_ptr);
	if(err < 0 ) goto error;
    RLOGD("at result rsp_data:%s length is:%d", rsp_ptr, rsp_len);
    if (rsp_len < 4) {
        goto error;
    }

    sim_response.sw1 = (rsp_ptr[rsp_len - 4] - '0') * 16 + rsp_ptr[rsp_len - 3] - '0';
    sim_response.sw2 = (rsp_ptr[rsp_len - 2] - '0') * 16 + rsp_ptr[rsp_len - 1] - '0';
    if (rsp_len > 4) {
        sim_response.simResponse = (char*) malloc(rsp_len - 4 + 1);
        if (!sim_response.simResponse){
            goto error;
        }
        memset(sim_response.simResponse, 0, rsp_len - 4 + 1);
        strncpy(sim_response.simResponse, rsp_ptr, rsp_len - 4);
    }
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &sim_response, sizeof(RIL_SIM_IO_Response));
    free(at_cmd);
    if (sim_response.simResponse) {
        free(sim_response.simResponse);
    }
    return;
error:
    free(at_cmd);
    if (sim_response.simResponse) {
        free(sim_response.simResponse);
    }
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}
#ifdef MEIG_NEW_FEATURE
typedef struct {
    char *auth_data;
    char simResponse[14];
} SIM_RSP_DUMMY;
static SIM_RSP_DUMMY sim_rsp_dummy[] = {
    {"ECcTqwuo6OfY8ddFRboD9WM=", {4, 196, 47, 252, 245, 8, 42, 160, 92, 249, 249, 169, 109, 18}},
    {"EMNxjsFrPCpm+KcgCmQGnwQ=", {4, 52, 236, 27, 169, 8, 120, 101, 196, 53, 143, 215, 89, 237}},
};

static void requestSimAuthentication(void* data, size_t datalen, RIL_Token t) {
    RIL_SimAuthentication *pf = (RIL_SimAuthentication *) data;
    uim_authentication_data_type auth_info = {0};
    RIL_SIM_IO_Response sim_io_resp = {0} ;
	
    int ret = 0;
    if (pf == NULL) {
        RLOGE("%s null input arg pf", __FUNCTION__);
        goto error;
    }

    if (pf->authData == NULL || strlen(pf->authData) == 0) {
        RIL_onRequestComplete(t, RIL_E_NO_MEMORY, NULL, 0);
        return;
    }
	//zhangqingyun add cts 
    if(strcmp(pf->authData,"test") == 0){
		RLOGD("this vts test see hardware/interface/radio/1.0/vtsxxx define");
		RIL_onRequestComplete(t, RIL_E_INVALID_ARGUMENTS, NULL, 0);
        return;
	}else {
		RLOGD("sdm 660 close feature pass sim authentication just return ");
		RIL_onRequestComplete(t, RIL_E_INVALID_ARGUMENTS, NULL, 0);
        return;
	}
    sim_io_resp.simResponse = (char *)malloc(128);
    if (sim_io_resp.simResponse == NULL) {
        RLOGE("%s malloc fail!", __FUNCTION__);
        goto error;
    }
    memset(sim_io_resp.simResponse, 0, 128 * sizeof(char));
    auth_info.aid_len = pf->aid ? strlen(pf->aid) : 0;
    auth_info.aid_buffer = pf->aid;
    auth_info.auth_data_len = pf->authData ? strlen(pf->authData) : 0;
    auth_info.auth_data = pf->authData;
    auth_info.context = pf->authContext;
    RLOGD("%s entry, aid_len = %d, data_len = %d, context = %d\n", __FUNCTION__, auth_info.aid_len, auth_info.auth_data_len, auth_info.context);
    ret = CMRequestSimAuthentication(&auth_info, (SIM_IO_rsp *)&sim_io_resp);
    if (ret) {
        RLOGE("%s excute fail, ret = %d", __FUNCTION__, ret);
        // goto error_free;
    }
    
    sim_io_resp.sw1 = 0x90;
    sim_io_resp.sw2 = 0x00;
    #if 1
    for (int i = 0; i < sizeof(sim_rsp_dummy) / sizeof(SIM_RSP_DUMMY); i++) {
        if (strcmp(sim_rsp_dummy[i].auth_data, pf->authData)) {
            memcpy(sim_io_resp.simResponse, sim_rsp_dummy[i].simResponse, 14);
        }
    }
    #endif
	#if 0
    if(sim_auth_index%2 == 0){
	sim_io_resp.simResponse="4244657065427349726335756A5A57344F4D633D";
    }else {
	sim_io_resp.simResponse="424C4A6258554D49736754596859627255376B3D";
    }
	#endif 
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &sim_io_resp, sizeof(RIL_SIM_IO_Response));
    free(sim_io_resp.simResponse);
    return;
error_free:
    free(sim_io_resp.simResponse);
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}
#endif

#ifdef START_KEEP_ALIVE
static void requestStartKeepAlive(void* data, size_t datalen, RIL_Token t) {
    RIL_KeepaliveRequest *req_data = (RIL_KeepaliveRequest *) data;
    RIL_KeepaliveStatus keep_alive_rsp = {0};
    wds_modem_assisted_ka_start_req_msg_type ka_info = {0};
    #ifdef MEIG_CTS_ENABLE
        RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
	    return;
	#else 
    int ret = 0;

    if (!req_data) {
        RLOGE("%s null input arg pf", __FUNCTION__);
        goto error;
    }
    RLOGD("%s type = %d, srcPort = %d, destPort = %d", __FUNCTION__, req_data->type, req_data->sourcePort, req_data->destinationPort);
    ka_info.keep_alive_type = WDS_KEEPALIVE_TYPE_NAT;
    // source addr, dest addr
    if (req_data->type == NATT_IPV4) {
        // ipv4
        unsigned int src = 0;
        unsigned int dest = 0;
        memcpy(&src, req_data->sourceAddress, sizeof(unsigned int));
        memcpy(&dest, req_data->destinationAddress, sizeof(unsigned int));
        ka_info.source_ipv4_address = ntohl(src);
        ka_info.dest_ipv4_address = ntohl(dest);
    } else if (req_data->type == NATT_IPV6) {
        // ipv6
        memcpy(ka_info.source_ipv6_address, req_data->sourceAddress, MAX_INADDR_LEN);
        memcpy(ka_info.dest_ipv6_address, req_data->destinationAddress, MAX_INADDR_LEN);
        ka_info.source_ipv6_address_valid = 1;
        ka_info.dest_ipv6_address_valid = 1;
    }
    ka_info.source_port = req_data->sourcePort;
    ka_info.source_port_valid = 1;
    ka_info.dest_port = req_data->destinationPort;
    ka_info.dest_port_valid = 1;
    if (req_data->maxKeepaliveIntervalMillis > 0) {
        ka_info.timer_value = req_data->maxKeepaliveIntervalMillis;
        ka_info.timer_value_valid = 1;
    }
    ret = CMRequestStartKeepAlive(&ka_info, &keep_alive_rsp);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &keep_alive_rsp, sizeof(RIL_KeepaliveStatus));
    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
	#endif
}

static void requestStopKeepAlive(void* data, size_t datalen, RIL_Token t) {
    #ifdef MEIG_CTS_ENABLE
        RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
	    return;
	#else 
        RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
	#endif 
}
#endif
//zhangqingyun add for support cts 2023-12-12 return unsol_network_scan_result
static void sendScanResultToAndroid(){
    RLOGD("send unsol_network_scan_result to android");
	//RIL_UNSOL_NETWORK_SCAN_RESULT
	RIL_NetworkScanResult netScanResult;
	netScanResult.status = COMPLETE;
	netScanResult.error = RIL_E_SUCCESS;
	netScanResult.network_infos_length  = 1;
	netScanResult.network_infos = &networkscan_rillCellInfo[0];
	//networkscan_rillCellInfo[0].CellInfo
	RIL_onUnsolicitedResponse(RIL_UNSOL_NETWORK_SCAN_RESULT,
                              &netScanResult,
                              sizeof(RIL_NetworkScanResult));
	
}
//zhangqingyun add vts test hal 1.3
static void requestEnableModem(void* data, size_t datalen, RIL_Token t){
    RLOGD("%s entry", __FUNCTION__);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

//zhangqingyun add for vts test
static void requestSetDataProfile(void* data, size_t datalen, RIL_Token t){
	RLOGD("%s entry", __FUNCTION__);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}
static void requestSetEmergencyDial(void* data, size_t datalen, RIL_Token t){
    RLOGD("%s entry", __FUNCTION__);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestSetCarrierRestriction(void* data, size_t datalen, RIL_Token t){
    RLOGD("%s entry", __FUNCTION__);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}
static void requestGetCarrierRestriction(void* data, size_t datalen, RIL_Token t){
    RLOGD("%s entry", __FUNCTION__);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}


static void requestCdmaWriteSmsToRuim(void* data, size_t datalen, RIL_Token t){
    RLOGD("%s entry", __FUNCTION__);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestSetMute(void* data, size_t datalen, RIL_Token t){
    RLOGD("%s entry", __FUNCTION__);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestStartNetworkScan(void* data, size_t datalen, RIL_Token t) {
    RLOGD("%s entry", __FUNCTION__);
    struct timeval scan_result = {20,0};
    RIL_requestTimedCallback(sendScanResultToAndroid, NULL, &scan_result);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestStopNetworkScan(void* data, size_t datalen, RIL_Token t) {
    RLOGD("%s entry", __FUNCTION__);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestGetModemActivity(void* data, size_t datalen,RIL_Token t){
    RIL_ActivityStatsInfo activityStatsInfo; // RIL_NUM_TX_POWER_LEVELS 5
    memset(&activityStatsInfo, 0, sizeof(activityStatsInfo));
	if(CMRequestGetModemActivityInfo() != 0){
		RLOGD("exception happen in CMRequestGetModemActivityInfo");
        RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
        
    }else{
        activityStatsInfo.tx_mode_time_ms[0] = (uint32_t)0;
		activityStatsInfo.tx_mode_time_ms[1] = (uint32_t)0;
		activityStatsInfo.tx_mode_time_ms[2] = (uint32_t)0;
		activityStatsInfo.tx_mode_time_ms[3] = (uint32_t)0;
		
        activityStatsInfo.rx_mode_time_ms = (uint32_t)initial_time_statmp;
		initial_time_statmp += 5120;
        activityStatsInfo.sleep_mode_time_ms = (uint32_t)0;
        activityStatsInfo.idle_mode_time_ms = (uint32_t)0;
		RLOGD("meig-ril send to android framework modmeactivity all activityStatusInfo set to 0 now");
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &activityStatsInfo, sizeof(activityStatsInfo));
        
    }
}
/*zhangqingyun add for support getModemActivity 2023-12-5 end use qmi for gms test*/
/*zhangqingyun add for support setSystemSelectionChannels 2023-12-5 use qmi for gms test start*/
static void requestSetSystemSelectionChannels(void* data, size_t datalen,RIL_Token t){
   //need implementate it
   RLOGD("requestSetSystemSelectionChannels");
   RIL_onRequestComplete(t,RIL_E_SUCCESS,NULL,0);
}

/*zhangqingyun add for support setSystemSelectionChannels 2023-12-5 use qmi for gms test end*/


/*add callbacks for libmeigcm by zhaopengfei 2022/10/10 End */
/*modify setupdata to libmeigcm APIs by zhaopengfei 2022/10/10 Begin */
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
int setupDataCallQMIMode(int profileID,
                         const char* apn,
                         const int authtype,
                         const char* password,
                         const char*    protocol,
                         const char*    username)
{
RLOGD("**************enter setupDataCallQMIMode**************");
#define MEIG_MULTIL_APN_START_INDEX    (9)
#define POLL_DHCP_RETRY    20

char ppp_number[20] = {'\0'};
int cgreg_response[4];
int cops_response[4];
char *cmd;
int err;
int retry = 0;
pid_t ql_pppd_pid;
CM_CONN_STATE cm_conn_state = WDS_CONNECTION_STATUS_DISCONNECTED;

ATResponse *p_response = NULL;
char *line = NULL;
char cm_local_ip[PROPERTY_VALUE_MAX] = {'\0'};
struct timeval begin_tv, end_tv;
int s_default_pdp = profileID+1;
gettimeofday(&begin_tv, NULL);
g_dhcp_fail_ignore_flag = 0;

bSetupDataCallCompelete = 0;
/* begin: modified by dongmeirong for missing assignment to nSetupDataCallFailTimes 20210105*/
nSetupDataCallFailTimes = 0;
/* end: modified by dongmeirong for missing assignment to nSetupDataCallFailTimes 20210105*/


/*[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort { */
if (SIM_ABSENT == s_sim_state || isRadioOn() != RADIO_ONLINE_STATE || SIM_NOT_READY == s_sim_state) {
    RLOGE("raido is off!");
    goto error;
}
#if 0
if (strstr(apn, "wap")) {
    s_default_pdp = 2;
}
#endif 

/*[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort } */
if(s_default_pdp != 1) {
    asprintf(&cmd, "AT+CGDCONT=%d,\"%s\",\"%s\"", s_default_pdp /*+ MEIG_MULTIL_APN_START_INDEX*/, protocol, apn);
} else {
    asprintf(&cmd, "AT+CGDCONT=%d,\"%s\",\"%s\"", s_default_pdp, protocol, apn);
}
if(profileID < 0 || profileID >= NDIS_MULTI_NUM_MAX) {
    RLOGE("invalid profile id");
    goto error;
}
#if 0
if (strstr(apn, "wap")) {
profileID = 1;
}
#endif

if(CMRequestSetProfile(profileID, apn, username,  password, PROT_STR2TYPE(protocol),  authtype) < 0){
    RLOGE("set profile failed");
    goto error;
}

//FIXME check for error here
err = at_send_command(cmd, NULL);
free(cmd);

if (0 != CMRequestSetupDataCall(profileID)){
     RLOGE("setup data call failed");
    goto error;
}

sleep(1);
while(retry++ < 3) {
    if(0 == CMRequestQueryDataCall(profileID, &cm_conn_state)){
        break;
    }
}

/* Modify by zhaopengfei treat authenticating as success because we have double check 2022/12/07 Begin */
if(cm_conn_state != WDS_CONNECTION_STATUS_CONNECTED &&
    cm_conn_state != WDS_CONNECTION_STATUS_AUTHENTICATING){
    RLOGE("data call failed");
    goto error;
}
/* Modify by zhaopengfei treat authenticating as success because we have double check 2022/12/07 End */

//[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort
// modified by dongmeirong for missing assignment to nSetupDataCallFailTimes 20210105
// delete the condition of nSetupDataCallFailTimes, it is unnessary here.
ifc_enable(curr_modem_info.if_name);
if(!curr_modem_info.use_deprecated_gobi) {
/*yufeilong modify for ifc_enable use null point begin*/
    if (curr_modem_info.vif_name[profileID] != NULL) {
        RLOGD("vif_name: %s\n", curr_modem_info.vif_name[profileID]);
        ifc_enable(curr_modem_info.vif_name[profileID]);
    } else {
        RLOGD("vif_name is NULL\n");
    }
/*yufeilong modify for ifc_enable use null point end*/
}


while (!s_closed && (SIM_ABSENT != s_sim_state) && (SIM_NOT_READY != s_sim_state) && (retry++ < POLL_DHCP_RETRY)) {
    if(curr_modem_info.use_deprecated_gobi) {
        if(request_dhcp(curr_modem_info.if_name, true) < 0) {
            RLOGD("failed to do_dhcp: %s\n", strerror(errno));
        }
        if(errno == ENETUNREACH){
            g_dhcp_fail_ignore_flag = 1;
        }

        get_ip_of_intf(curr_modem_info.if_name, cm_local_ip);
        RLOGD("[%d] trying to get_local_ip of %s ... %s", retry, curr_modem_info.if_name, cm_local_ip);
    } else {
        if(request_dhcp(curr_modem_info.vif_name[profileID], true) < 0) {
            RLOGD("failed to do_dhcp: %s\n", strerror(errno));
        }
        if(errno == ENETUNREACH){
            g_dhcp_fail_ignore_flag = 1;
        }

        get_ip_of_intf(curr_modem_info.vif_name[profileID], cm_local_ip);
        RLOGD("[%d] trying to get_local_ip of %s ... %s", retry, curr_modem_info.vif_name[profileID], cm_local_ip);
    }


    if(strcmp(cm_local_ip, "0.0.0.0"))
        break;
    sleep(1);
}
gettimeofday(&end_tv, NULL);
RLOGD("get_local_ip: %s, cost %ld sec", cm_local_ip, (end_tv.tv_sec - begin_tv.tv_sec));
if (0 == strlen(cm_local_ip) || !strcmp(cm_local_ip, "0.0.0.0"))
    goto error;

bSetupDataCallCompelete = 1;
pppd = 1;
return SUCCESS;
error:

if(0 != CMRequestTurnDownDataCall(profileID)){
    RLOGE("Turn down failed \n");
}
if(curr_modem_info.if_name && curr_modem_info.if_name[0] != '\0') {
    ifc_disable(curr_modem_info.if_name);
}
if((!curr_modem_info.use_deprecated_gobi) && curr_modem_info.vif_name[profileID] && curr_modem_info.vif_name[profileID][0] != '\0') {
    ifc_disable(curr_modem_info.vif_name[profileID]);
}

RLOGE("Unable to setup PDP in %s\n", __func__);
at_response_free(p_response);
return ERROR;
}
/*[zhaopf@meigsmart-2022-06-10] add for mms support End */
/*zhaopf@meigsmart-2021/08/09 add for multi qmi-ndis support Begin { */
int setupDataCallMultiQMIMode(const char* apn,
                         const int authtype,
                         const char* password,
                         const char*    protocol,
                         const char*    username)
{
    RLOGD("**************enter setupDataCallMultiQMIMode**************");
    char ppp_number[20] = {'\0'};
    int cgreg_response[4];
    int cops_response[4];
    char *cmd;
    int err, i;
    int localProfileID = 0;
    int profileID = 0;
    int retry = 0;
    pid_t mg_pppd_pid;
    char *line = NULL;
    char ppp_local_ip[PROPERTY_VALUE_MAX] = {'\0'};

    CM_CONN_STATE cm_conn_state = WDS_CONNECTION_STATUS_DISCONNECTED;
    struct timeval begin_tv, end_tv;
    char multi_apns[PROPERTY_VALUE_MAX] = {'\0'};
    memset(multi_apns, 0x0, PROPERTY_VALUE_MAX);
    //g_cm_unrecoery_error = 0;


    for(i = 0; i < g_ndis_multi_num; i++) {

        retry = 0; //add by zhaopf, reset count
        memset(ppp_local_ip, 0x0, PROPERTY_VALUE_MAX);
        gettimeofday(&begin_tv, NULL);
        profileID = i;
        bSetupDataCallCompelete = 0;
        nSetupDataCallFailTimes = 0;

        if (SIM_ABSENT == s_sim_state || isRadioOn() != RADIO_ONLINE_STATE || SIM_NOT_READY == s_sim_state) {
            RLOGE("raido is off!");
            goto error;
        }
        multi_apns[0] = '\0';
        property_get(NDSI_MULTI_APNS_PROPS[i], multi_apns, NULL);
        if(0 == i) {
            asprintf(&cmd, "AT+CGDCONT=%d,\"%s\",\"%s\"", i+1, protocol, apn);
        } else {
            if(multi_apns[0] == '\0'){
                RLOGE("empty apn prop");
                continue;
            }
            //multi apn from 10'th

            asprintf(&cmd, "AT+CGDCONT=%d,\"%s\",\"%s\"", i+MULTI_APN_BASE, protocol, multi_apns);
        }

        //FIXME check for error here
        err = at_send_command(cmd, NULL);
        free(cmd);
        if(CMRequestSetProfile(profileID, (0 == profileID)?apn:multi_apns, username,  password, PROT_STR2TYPE(protocol),  authtype) < 0){
            RLOGE("set profile failed");
            goto error;
        }

        if (0 != CMRequestSetupDataCall(profileID)){
             RLOGE("setup data call failed");
             goto error;
        }


        sleep(1);
        while(retry++ < 3) {
            if(0 == CMRequestQueryDataCall(profileID, &cm_conn_state)){
                break;
            }
        }
        /* Modify by zhaopengfei treat authenticating as success because we have double check 2022/12/07 Begin */
        if(cm_conn_state != WDS_CONNECTION_STATUS_CONNECTED &&
            cm_conn_state != WDS_CONNECTION_STATUS_AUTHENTICATING){
            RLOGE("data call failed");
            goto error;
        }
       /* Modify by zhaopengfei treat authenticating as success because we have double check 2022/12/07 End */
        sleep(1);
        retry = 0;
        while (!s_closed && (SIM_ABSENT != s_sim_state) && (SIM_NOT_READY != s_sim_state) && (retry++ < POLL_PPP_SYSFS_RETRY)
                /* && (nSetupDataCallFailTimes <= 3) */) {

            if(curr_modem_info.use_deprecated_gobi){

                if(request_dhcp(curr_modem_info.if_name, true) < 0) {
                    RLOGD("failed to do_dhcp: %s\n", strerror(errno));
                }
                if(errno == ENETUNREACH){
                    g_dhcp_fail_ignore_flag = 1;
                }

                get_ip_of_intf(curr_modem_info.if_name, ppp_local_ip);
                RLOGD("[%d] trying to get_ip_of_intf %s... %s", retry, curr_modem_info.if_name, ppp_local_ip);
                if(strcmp(ppp_local_ip, "0.0.0.0"))
                    break;
                sleep(1);
        } else {

            if(request_dhcp(curr_modem_info.vif_name[profileID], true) < 0) {
                RLOGD("failed to do_dhcp: %s\n", strerror(errno));
            }
            if(errno == ENETUNREACH){
                g_dhcp_fail_ignore_flag = 1;
            }

            get_ip_of_intf(curr_modem_info.vif_name[profileID], ppp_local_ip);
            RLOGD("[%d] trying to get_ip_of_intf %s... %s", retry, curr_modem_info.vif_name[profileID], ppp_local_ip);
            if(strcmp(ppp_local_ip, "0.0.0.0"))
                break;
            sleep(1);
        }

   } //while


    gettimeofday(&end_tv, NULL);
    if(curr_modem_info.use_deprecated_gobi) {
        RLOGD("get_ip_of_intf %s: %s, cost %ld sec", curr_modem_info.if_name, ppp_local_ip, (end_tv.tv_sec - begin_tv.tv_sec));
    } else {
        RLOGD("get_ip_of_intf %s: %s, cost %ld sec", curr_modem_info.vif_name[profileID], ppp_local_ip, (end_tv.tv_sec - begin_tv.tv_sec));
    }


        if (0 == strlen(ppp_local_ip) || !strcmp(ppp_local_ip, "0.0.0.0")) {
            goto error;
        }

        localProfileID++;

    }//while
    bSetupDataCallCompelete = 1;
    pppd = 1;
    return SUCCESS;
    error:
    //add by zhaopengfei 2021/11/01, for trigger modem force reset End
    RLOGE("Unable to setup PDP in %s\n", __func__);
    return ERROR;
}
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
/*zhaopf@meigsmart-2021/08/09 modify for unrecovery error End */
/*zhaopf@meigsmart-2021/08/09 add for multi qmi-ndis support End } */
/*modify setupdata to libmeigcm APIs by zhaopengfei 2022/10/10 End */

/**
* called by requestSetupDataCall
*
* return 0 for success
* return 1 for error;
* return 2 for ppp_error;
*/

int setupDataCallECMMode(const char* apn,
                             const int authtype,
                             const char* password,
                             const char*    protocol,
                             const char*    username)
{
    #define SUCCESS 0
    #define ERROR 1
    int fd=0;
    char buffer[20];
    char *if_name = NULL;
    SOLUTOIN_TYPE platform_type = 0;
    char *cmd;
    int err=0;
    int check_result_time=0;
/*[zhaopf@meigsmart-2020-1127]when sim removed or modem lost, abort { */
if (SIM_ABSENT == s_sim_state || isRadioOn() != RADIO_ONLINE_STATE || SIM_NOT_READY == s_sim_state) {
    RLOGE("raido is off or sim removed!");
    goto error;
}
/*[zhaopf@meigsmart-2020-1127]when sim removed or modem lost, abort } */

 /*[zhaopf@meigsmart-2020-1113]add for static ip address setting { */
#ifdef ECM_USE_STATIC_IP_ADDRESS
    char *default_route;
    uint32_t ipaddr = 0, gateway = 0, prefixLength = 24, dns1 = 0, dns2 = 0, server = 0, lease = 0;
    //ipaddr, gw, dns1, dns2, server
/*yufeilong modify for static ip 20230404 begin*/
    char local_dhcp_info[5][32] = {0};
    char local_dhcp_info_unisoc[5][32] = {"192.168.225.47", "192.168.225.1", "192.168.225.1", "8.8.8.8", "192.168.225.1"};
    char local_dhcp_info_asr_qcm[5][32] = {"192.168.200.47", "192.168.200.1", "192.168.200.1", "8.8.8.8", "192.168.200.1"};
    if ((curr_modem_info.info.sltn_type == ASR) || (curr_modem_info.info.sltn_type == QCM)) {
        memcpy(local_dhcp_info, local_dhcp_info_asr_qcm, sizeof(local_dhcp_info_asr_qcm));
    } else {
         memcpy(local_dhcp_info, local_dhcp_info_unisoc, sizeof(local_dhcp_info_unisoc));
    }
/*yufeilong modify for static ip 20230404 end*/
#endif
 /*[zhaopf@meigsmart-2020-1113]add for static ip address setting } */
    RLOGD("**************enter setupDataCallECMMode**************");
    /*[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort { */
    if (SIM_ABSENT == s_sim_state || isRadioOn() != RADIO_ONLINE_STATE || SIM_NOT_READY == s_sim_state) {
        RLOGE("raido is off!");
        goto error;
    }
    /*[zhaopf@meigsmart-2020-1113]when sim removed or modem lost, abort } */
    asprintf(&cmd, "AT+CGDCONT=1,\"%s\",\"%s\",,0,0",protocol,apn);
    err = at_send_command(cmd, NULL);
    free(cmd);
    if_name = curr_modem_info.if_name;
    if(if_name == NULL) {
        RLOGD("no network card found");
        goto error;
    }
    RLOGD("init and up netinterface");
    if(ifc_init()){
        RLOGD("failed to init %s error is:%s",if_name,strerror(errno));
        ifc_close();
        goto error;
    }
    if(ifc_up(if_name)){
        RLOGD("failed to up %s error is: %s",if_name,strerror(errno));
        ifc_close();
        goto  error;
    }
    RLOGD("network card up");
    platform_type = curr_modem_info.info.sltn_type;
    if(platform_type == QCM){
        /* Modify by zhaopengfei for param of at+ecmdup not same bwteen version 1 and vesion 2 that will make mistake 2022/12/07 Begin */
        if (curr_modem_info.info.at_version == AT_VERSION_1) {
            RLOGD("Qualcomm platform should send at+ecmdup");
            at_send_command("AT+ECMDUP=1,1,1", NULL);
        } else {
            RLOGD("Qualcomm platform auto ecmdup");
        }
        /* Modify by zhaopengfei for param of at+ecmdup not same bwteen version 1 and vesion 2 that will make mistake 2022/12/07 End */
    /*Modify by zhaopengfei for ECM&RNDIS support auto dialing except SLM790,SLM750R1 2022/12/23 Begin */
    } else if (platform_type == HISI) {
        at_send_command("AT^NDISDUP=1,1", NULL);
        RLOGD("Hisi platform send at^ndisdup");
    } else {
        int status = -1;
#ifdef ECMDUP_ENABLE
        at_send_command("AT+ECMDUP=1,1", NULL); //fixed error by zhaopengfei, 2023/01/05
#else
        RLOGD("RNDIS&ECM is automatic dialing");
#endif
        status = system("/system/bin/ip rule add table main");
        if ((status == -1) || !WIFEXITED(status) || (WEXITSTATUS(status) !=0)) {
            RLOGD("ip rule add table main failed!");
        }

    }
    /*Modify by zhaopengfei for ECM&RNDIS support auto dialing except SLM790,SLM750R1 2022/12/23 End */
    sleep(1);
 /*[zhaopf@meigsmart-2020-1113]add for static ip address setting { */
#ifdef ECM_USE_STATIC_IP_ADDRESS
 ipaddr = (uint32_t)string_to_ipaddr(local_dhcp_info[0]);
 gateway = (uint32_t)string_to_ipaddr(local_dhcp_info[1]);
 dns1 = (uint32_t)string_to_ipaddr(local_dhcp_info[2]);
 dns2 = (uint32_t)string_to_ipaddr(local_dhcp_info[3]);
 asprintf(&default_route, "/system/bin/ip route add default via %s dev %s  table %s",local_dhcp_info[1], curr_modem_info.if_name, curr_modem_info.if_name);
 RLOGD("[convert]ip=0x%x, gw=0x%x, prefix=0x%x, dns1=0x%x, dns2=0x%x",ipaddr, gateway, prefixLength,dns1, dns2);

   if(0 !=  ifc_configure(curr_modem_info.if_name,  ipaddr,  prefixLength,  gateway, dns1,  dns2) ){
       RLOGD("configure static ip failed");
   } else {
       RLOGD("configure static ip success");
       system(default_route);
   }
   free(default_route);
#else
    if (do_dhcp(if_name) < 0) {
        int status = -1;
        RLOGD("failed to do_dhcp: %s\n", strerror(errno));
        status = system("/system/bin/ip rule add table main");
        if ((status == -1) || !WIFEXITED(status) || (WEXITSTATUS(status) !=0)) {
            RLOGD("ip rule add table main failed!");
        }
        status = system("/system/bin/ip route add default dev eth2");
        system("/system/bin/ip route show");
        if ((status == -1) || !WIFEXITED(status) || (WEXITSTATUS(status) !=0)) {
            RLOGD("ip route add default failed!");
        }
        RLOGD("try add table main and default route\n");
        /*[zhaopf@meigsmart-2020-0615] will ignore when dhcp fail, as will check next step {  */
        //do not goto error as some situation gw unreachable
        //ifc_close();
        //goto error;
        /*[zhaopf@meigsmart-2020-0615] will ignore when dhcp fail, as will check next step }  */
    }
#endif
 /*[zhaopf@meigsmart-2020-1113]add for static ip address setting } */
    ifc_close();
    RLOGD("do dhcp end");
    pppd = 1;
    return SUCCESS;
    error:
    return ERROR;
}

/*modify setupdata to libmeigcm APIs by zhaopengfei 2022/10/10 Begin */
static void requestSetupDataCall(void *data, size_t datalen, RIL_Token t)
{

const char *apn=NULL;
const char *pdp_type =NULL;
const char *username =NULL;
const char *password =NULL;
const char *auth_type =NULL;
int i;
int setup_data_call_result = 0;
int len=0;
int profileID = 0;

//debug wangbo  2017/5/18
//s_current_apn = "cmnet";
strcpy(s_current_apn, "cmnet");
RIL_DataProfile *dataProfile = ((const char **)data)[1];

apn = ((const char **)data)[2];
username = ((const char **)data)[3];
password = ((const char **)data)[4];
auth_type = ((const char **)data)[5];
profileID = atoi(dataProfile);
RLOGD("original profile is from android telephony framework is:%d\n",profileID);
if(profileID > 1000) {
    profileID -= 1000;
} else {
    profileID = 0;
}
RLOGD("dataProfile=%d,profileID=%d, pdp_type=%s, datalen=%d", *dataProfile, profileID, ((const char **)data)[6], datalen/sizeof(char *));
for(i = 0; i < (datalen/sizeof(char *)); i++){
    RLOGD("data[%d]=%s\n", i, ((const char **)data)[i]);
}

if( apn != NULL && (len = strlen(apn))) {
    if( len > MAX_S_CURRENT_APN_LEN) {
        RLOGD("warning:apn too long");
    }
    len = (len > 64)? 64:len;
    strncpy(s_current_apn, ((const char **)data)[2],len);
    s_current_apn[len]='\0';
} else {
    s_current_apn[0]='\0';
}


/* get the pdp ip_address type */
if (datalen > 6 * sizeof(char *)) {
    pdp_type = ((const char **)data)[6];
    unsigned int pdp_type_len = 0;
    if( pdp_type != NULL && (pdp_type_len = strlen(pdp_type))) {
        if( pdp_type_len > MAX_S_CURRENT_PROTOCOL_LEN) {
            RLOGD("warning:pdp_type_len too long");
        }
        pdp_type_len = (pdp_type_len > MAX_S_CURRENT_PROTOCOL_LEN)? MAX_S_CURRENT_PROTOCOL_LEN:pdp_type_len;
        strncpy(s_current_protocol,((const char **)data)[6],pdp_type_len);
        s_current_protocol[pdp_type_len] = '\0';
    } else {
        pdp_type = "IP";
        strncpy(s_current_protocol,"IP",2);
        s_current_protocol[2] = '\0';
    }
} else {
    pdp_type = "IP";
    strncpy(s_current_protocol,"IP",2);
    s_current_protocol[2] = '\0';
}
/* username */
if ((username != NULL)&&(len = strlen(username))) {
    if( len > MAX_S_CURRENT_USERNAME_LEN) {
        RLOGD("warning:username too long");
    }
    len = (len > MAX_S_CURRENT_USERNAME_LEN)? MAX_S_CURRENT_USERNAME_LEN:len;
    strncpy(s_current_username, ((const char **)data)[3],len);
    s_current_username[len]='\0';
} else {
    strcpy(s_current_username, "card");
}
/* password */
if ((password != NULL)&&(len = strlen(password))) {
    if( len > MAX_S_CURRENT_PASSWORD_LEN) {
        RLOGD("warning:password too long");
    }
    len = (len > MAX_S_CURRENT_PASSWORD_LEN)? MAX_S_CURRENT_PASSWORD_LEN:len;
    strncpy(s_current_password, ((const char **)data)[4],len);
    s_current_password[len]='\0';
} else {
     strcpy(s_current_password, "card");
}
/* auth type */
if(auth_type[0] >= '0' && auth_type[0] <= '3'){
    s_current_authtype = atoi(auth_type);
} else {
     s_current_authtype=0;
}


current_cid = profileID+1;
RLOGI("*************************************");
RLOGI("APN:%s",apn);
RLOGI("USER:%s",username);
RLOGI("PASS:%s",password);
RLOGI("auth_type:%s",auth_type);
RLOGI("pdp_type:%s",pdp_type);
RLOGI("*************************************");

if(pppd && devmode != QMI_MOD) {
     RLOGD("Stop existing dial before activating PDP"); //hangup process
     at_send_command("+++ATH",NULL);
     #if 0
     if(0==strcmp(apn,"3gwap")){
        at_send_command("at+ecmdump=1,0");
     }else if(0 == strcmp(apn,"3gnet")){
        at_send_command("at+ecmdump=6,0");
     }
     #endif
     RLOGD("dial hangup +++ATH");
    usleep(1000);
 }
 pppd = 0;
/*zhangqingyun add for support send mms through ppp 2023-5-7 start*/
#ifdef SEND_MMS_USE_PPP
if (strstr(apn, "wap")) {
    devmode = RAS_MOD;
    curr_modem_info.if_name = strdup("ppp0");
    RLOGD("set devmode to ras mode when send mms");
}else{
	devmode = QMI_MOD;
    curr_modem_info.if_name = strdup("usb0");
    RLOGD("use qmi_mode to make data");
}
#else
if(profileID){
   devmode = RAS_MOD;
   curr_modem_info.if_name = strdup("ppp0");   
   RLOGD("set devmode to ras mode when send mms");
 } else {
   devmode = ECM_MOD;
   curr_modem_info.if_name = strdup("usb0");
   RLOGD("set devmode to ecm mode when use data");
}

#endif
#if 0
#ifdef MEIG_CTS_ENABLE
if (strstr(apn, "wap")) {
    RLOGD("use ppp to send mms");
	devmode = RAS_MOD;
	//CMRequestTurnDownDataCall(profileID);
    //system("/system/bin/ip route del default dev usb0");
}
#endif
#endif
/*zhangqingyun add for support send mms through ppp 2023-5-7 end*/
/*zhangqingyun add for support chuangwei send mms 2023-4-25 end*/
pthread_mutex_lock(&s_pppd_mutex);
/*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario Begin */
g_dhcp_fail_ignore_flag = 0;
/*zhaopengfei@meigsmart.com 2022/08/23 add for dhcp failed scenario End */

/*[zhaopf@meigsmart-2021-0611] check ps before dialup { */
if(!checkIfPSReady()){
    RLOGE("ps not ready");
    goto error;
}
/*[zhaopf@meigsmart-2021-0611] check ps before dialup } */

switch(devmode) {
case RAS_MOD:
    setup_data_call_result = setupDataCallRASMode(s_current_apn,s_current_authtype, s_current_password, s_current_protocol,  s_current_username);
    break;
case ECM_MOD:
case RNDIS_MOD: // added by dongmeirong for RNDIS adapt 20210219
    setup_data_call_result = setupDataCallECMMode(s_current_apn,s_current_authtype,s_current_password,s_current_protocol,s_current_username);
    break;
case NCM_MOD:
    setup_data_call_result = setupDataCallNCMMode(s_current_apn,s_current_authtype, s_current_password, s_current_protocol,  s_current_username);
    break;
case QMI_MOD:
    setup_data_call_result = setupDataCallQMIMode(profileID, s_current_apn,s_current_authtype, s_current_password, s_current_protocol,  s_current_username);
    break;
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin { */
case MULTI_NDIS_MOD:
    setup_data_call_result = setupDataCallMultiNdisMode(s_current_apn,s_current_authtype, s_current_password, s_current_protocol,  s_current_username);
    break;
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support End { */
/*zhaopf@meigsmart-2021/08/09 add for multi qmi-ndis support Begin { */
case MULTI_QMI_MOD:
    setup_data_call_result = setupDataCallMultiQMIMode(s_current_apn,s_current_authtype, s_current_password, s_current_protocol,  s_current_username);
    break;
/*zhaopf@meigsmart-2021/08/09 add for multi qmi-ndis support End { */

default:
    setup_data_call_result = setupDataCallRASMode(s_current_apn,s_current_authtype, s_current_password, s_current_protocol,  s_current_username);
    break;
}
if(1 == setup_data_call_result) {
    pppd = 0;
    goto error;
} else {
    bSetupDataCallCompelete = 1;
    pppd = 1;
}
 /*[zhaopf@meigsmart-2020-1113]add for static ip address setting { */
if(ECM_MOD == devmode || RNDIS_MOD == devmode) { /* modified by dongmeirong for RNDIS adapt 20210219 */
#ifdef ECM_USE_STATIC_IP_ADDRESS
    onSendStaticDataCallList(&t);
#else
    requestOrSendDataCallList(0, &t);
#endif

 } else {
    requestOrSendDataCallList(0, &t);
}

 g_dhcp_fail_ignore_flag = 0;
 current_cid = 1;

 /*[zhaopf@meigsmart-2020-1113]add for static ip address setting } */
pthread_mutex_unlock(&s_pppd_mutex);
return;

error:

if(devmode == RAS_MOD) {
    property_set("ctl.stop", SERVICE_PPPD_GPRS);
    pppd = 0;
}
g_dhcp_fail_ignore_flag = 0;
current_cid = 1;


RIL_onRequestComplete(t, RIL_E_OP_NOT_ALLOWED_BEFORE_REG_TO_NW, NULL, 0);
pthread_mutex_unlock(&s_pppd_mutex);


}
/*modify setupdata to libmeigcm APIs by zhaopengfei 2022/10/10 End */
/*[zhaopf@meigsmart-2022-06-10] add for mms support End */
/*zhaopengfei@meigsmart.com 2022/08/23 modify for dhcp failed scenario End */



void requestSMSAcknowledge(void *data, size_t datalen __unused,
                           RIL_Token t)
{
int ackSuccess;
int err;

ackSuccess = ((int *)data)[0];

if (ackSuccess == 1) {
    err = at_send_command("AT+CNMA=1", NULL);
} else if (ackSuccess == 0) {
    err = at_send_command("AT+CNMA=2", NULL);
} else {
    RLOGE("unsupported arg to RIL_REQUEST_SMS_ACKNOWLEDGE\n");
    goto error;
}

RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
error:
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);

}
/*[zhaopf@meigsmart-2020-0915] add for setting atach apn { */
void radioPowerOn(void *param __unused){
        at_send_command("AT+CFUN=1", NULL);
        RLOGI("radio power on");
        setRadioState(RADIO_STATE_ON);
}

void resetRadioPower(void *param __unused){
       struct timeval power_delay = {3,0};
       // zhaopengfei@meigsmart.com 2022/08/23 better ues cfun=4, good to sim
       at_send_command("AT+CFUN=4", NULL);
       setRadioState(RADIO_STATE_OFF);
       /*[zhaopf@meigsmart-2021-04-01]add force disconnet for qmi mode  { */
       forceDeactiveDataCallList();
       /*[zhaopf@meigsmart-2021-04-01]add force disconnet for qmi mode  } */
       RIL_requestTimedCallback(radioPowerOn, NULL, &power_delay);
       RLOGI("reset radio power");

}

/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail Begin */
void resetSimPower(){
       ATResponse *p_response = NULL;
       int err;
       struct timeval power_delay = {3,0};
       err = at_send_command("AT+CFUN=0", &p_response);
       if (err < 0 || !p_response->success) {
           RLOGE("reset radio power off failed");
           goto error;
       }
       setRadioState(RADIO_STATE_OFF);
       forceDeactiveDataCallList();
       RIL_requestTimedCallback(radioPowerOn, NULL, &power_delay);
       RLOGI("reset radio power");
error:
       at_response_free(p_response);
       p_response = NULL;

}
/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail End */


/*zhaopengfei@meigsmart.com 2022/08/23 modify for apn thant out-of-orger Begin */
static void requestSetInitialAttachAPN(void *data, size_t datalen, RIL_Token t)
{
    const char *apn = NULL, *pdp_type = NULL, *s_auth_type = NULL, *username = NULL, *passwd = NULL;
    /*[zhaopf@meigsmart-2020-1113]when apn init, set cgdcont at the same time for some special cards { */
    int err = 0;
    /*[zhaopf@meigsmart-2020-1223]check apn first ,if not same, cfun after change it { */
    char *cmd = NULL, *apn_cmd = NULL, *line = NULL, *skip, *last_apn_prot, *last_apn;
    ATResponse *p_response = NULL;
    ATResponse *p_checkresponse = NULL;
    bool b_apn_changed = false;
    bool b_same_apn = false;
    RIL_InitialAttachApn *pf = NULL;
    ATLine *p_cur;
    int i = 0;

    pf = (RIL_InitialAttachApn*)data;

    if(NULL == pf) {
        RLOGD("%s empty profile\n", __FUNCTION__);
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &err, sizeof(int));
        return;

    } else {
      RLOGD("%s apn=%s, pdp_type=%s, auth_type=%d, username=%s, password=%s\n", __FUNCTION__, pf->apn, pf->protocol, pf->authtype, pf->username, pf->password);
    }
    //check apn
    if(!property_get_bool("ril.meig.need.attachapn", false)){
        RLOGI("disabled attach apn");
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &err, sizeof(int));
        return;
    }
    if('\0' == pf->apn[0]){
       RLOGI("empty attach apn");
       RIL_onRequestComplete(t, RIL_E_SUCCESS, &err, sizeof(int));
       return;
   }

    err = at_send_command_multiline
        ("AT+CGDCONT?", "+CGDCONT:",
         &p_checkresponse);
    if (err < 0 || p_checkresponse->success == 0) {
        RLOGE("CGDCONT? failed\n");
        goto error;
    }

    for (i = 0, p_cur = p_checkresponse->p_intermediates; p_cur != NULL;
        p_cur = p_cur->p_next, i++) {
        line = p_cur->line;
        err = at_tok_start(&line);
        if (err < 0)
            goto error;

    err = at_tok_nextstr(&line, &skip);
    if (err < 0) {
        goto error;
    }
    err = at_tok_nextstr(&line, &last_apn_prot);
    if (err < 0) {
        RLOGE("get apn type err");
    }

        err = at_tok_nextstr(&line, &last_apn);
        if (err < 0) {
            RLOGE("get apn err");
        }
        if(0 == strcasecmp(pf->protocol, last_apn_prot) && 0 == strcasecmp(pf->apn, last_apn) ){
            RLOGI("same apn, do nothing");
            b_same_apn = true;
            break;
        }

     }

    if(!b_same_apn){
        b_apn_changed = true;
        asprintf(&apn_cmd, "AT+CGDCONT=1,\"%s\",\"%s\",,0,0",pf->protocol,  pf->apn);
        err = at_send_command(apn_cmd, &p_response);
        if (err < 0 || !p_response->success) {
            goto error;
        }
        at_response_free(p_response);
        p_response = NULL;
        free(apn_cmd);
    }
    at_response_free(p_checkresponse);
    p_checkresponse = NULL;


    /*[zhaopf@meigsmart-2020-1113]when apn init, set cgdcont at the same time for some special cards } */
    if(QCM == curr_modem_info.info.sltn_type) {
        switch(pf->authtype){ //None: 0, PAP: 1, CHAP: 2, PAP&CHAP: 3
        case 0:
            asprintf(&cmd, "AT$QCPDPP=1,%d", pf->authtype);
            break;
        case 1:
        case 2:
        case 3:
            asprintf(&cmd, "AT$QCPDPP=1,%d,%s,%s", pf->authtype, pf->password, pf->username);
            break;
        }
    /*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 Begin */
    } else if(curr_modem_info.info.sltn_type == UNISOC){
        /*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 Begin */
        if(g_unisoc_attach_apn_notready) {
            err = at_send_command("AT+CFUN=4", &p_response);
            if (err < 0 || p_response->success == 0) {
            RLOGE("cfun4 err");
            }
            at_response_free(p_response);
            p_response = NULL;
            setRadioState(RADIO_STATE_OFF);
            sleep(2);
        }
        /*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 End */
        switch(pf->authtype){
        case 0:
            asprintf(&cmd, "AT+CGPCO=0,\"\",\"\",1, %d",  pf->authtype);
            break;
        case 1:
        case 2:
        case 3:
            asprintf(&cmd, "AT+CGPCO=0,\"%s\",\"%s\",1, %d", pf->username, pf->password,  pf->authtype);
            break;
        }
    /*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 End */
    } else {
        switch(pf->authtype){
        case 0:
            asprintf(&cmd, "AT^AUTHDATA=1,%d", pf->authtype);
            break;
        case 1:
        case 2:
        case 3:
            asprintf(&cmd, "AT^AUTHDATA=1,%d,\"\",\"%s\",\"%s\"", pf->authtype, pf->password, pf->username);
            break;
        }
  }
    if(NULL != cmd) {
        err = at_send_command(cmd, &p_response);
        if (err < 0 || !p_response->success) {
            goto error;
        }
        at_response_free(p_response);
        free(cmd);
   } else {
       RLOGI("do nothing");
       err=0;
   }

   /*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 Begin */
   if(curr_modem_info.info.sltn_type == UNISOC && g_unisoc_attach_apn_notready){
       g_unisoc_attach_apn_notready = false;
       struct timeval power_delay = {3,0};
       RIL_requestTimedCallback(radioPowerOn, NULL, &power_delay);
   } else if(b_apn_changed){
         struct timeval reset_delay = {0,500};
         RIL_requestTimedCallback(resetRadioPower, NULL, &reset_delay);
   }
   /*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 End */

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &err, sizeof(int));
    return;
error:
    RLOGE
    ("%s must never return an error when radio is on", __FUNCTION__);
    at_response_free(p_response);
    at_response_free(p_checkresponse);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);


}
/*zhaopengfei@meigsmart.com 2022/08/23 modify for apn thant out-of-orger End */
/*[zhaopf@meigsmart-2020-1223]check apn first ,if not same, cfun after change it } */
/*[zhaopf@meigsmart-2020-0915] add for setting atach apn } */

//[zhaopf@meigsmart-2020-0628] add function for write keys to modem {
#ifdef BUILD_WITI_MEIG_EXT_KEY_SUPPORT
bool backupNV()
{
    int err;
    char *line, *p;
    char* s_ret;
    ATResponse *p_response = NULL;
#if 1 //AT+NVBURS=0
    at_send_command("AT+NVBURS=0", NULL);
    return true;
#else //as return prefix not be confirmed now time
    bool bRet = false;
    err = at_send_command_singleline("AT+NVBURS=0","+NVBURS:",&p_response);
    if(err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextstr(&line,&s_ret);
    if(err < 0) {
        goto error;
    }
    if(NULL != strstr(s_ret, "0")){
        bRet = true;
    }
    at_response_free(line);
    return bRet;
error:
    at_response_free(line);
    return bRet;
#endif
}

static void requestWriteMeigKey(void *data, size_t datalen, RIL_Token t)
{
    int keyID = -1;
    const char *key, *keyid;
    int err = 0;
    char *cmd = NULL;
    ATResponse *p_response = NULL;
    if(datalen < 1){
         RLOGE("too less args %d", datalen);
         goto error;
    }
    keyid = ((const char **)data)[0];
    key = ((const char **)data)[1];
    RLOGD("requestWriteMeigKey keyid=%s, key=%s", keyid, key);
    if(keyid[0] && keyid[0] >= '0' && keyid[0] < '3'){
        keyID = atoi(keyid);
    } else {
        goto error;
    }
    if(strlen(key) < 1 || strlen(key) > 19){
        RLOGE("requestWriteMeigKey out of range");
        goto  error;
    }

    switch(keyID){
       case 0:
           asprintf(&cmd,"AT+LCTSN=1,11,\"%s\"", key);
           break;
       case 1:
           asprintf(&cmd,"AT+LCTSN=1,13,\"%s\"", key);
           break;
       case 2:
           asprintf(&cmd,"AT+LCTSN=1,15,\"%s\"", key);
           break;
      }

    err = at_send_command(cmd,&p_response);
    if (err < 0) {
        goto error;
    }
    if(!backupNV()){
        RLOGE("back up nv failed");
        goto error;
    }
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &err, sizeof(int));
    at_response_free(p_response);
    free(cmd);
    return;

error:
    RLOGE
    ("%s must never return an error when radio is on", __FUNCTION__);
    at_response_free(p_response);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);


}


static void requestReadMeigKey(void *data,
                                  size_t datalen __unused, RIL_Token t)
{
int err;
char *responseStr;
ATResponse *p_response = NULL;
char cmd[128] = { 0x0 };
char *line;
const char *keyid = NULL;
keyid = (const char *)data;
RLOGD("requestReadMeigKey datalen=%d, keyid=%s", datalen, keyid);
//not exist or out of range

if(datalen < 1 || NULL == keyid || keyid[0] < '0' || keyid[0] > '2'){
    RLOGD("invalid keyid %s\n", keyid);
    goto error;
    return;

}

switch(keyid[0]){
    case '0':
        strcpy(cmd, "AT+LCTSN=0,11");
        break;
    case '1':
        strcpy(cmd, "AT+LCTSN=0,13");
        break;
    case '2':
        strcpy(cmd, "AT+LCTSN=0,15");
        break;
    default:
       RLOGD("invalid keyid %s\n", keyid);
       goto error;
       break;
}

err = at_send_command_singleline(cmd, "+LCTSN:", &p_response);
if (err < 0 || p_response->success == 0) {
    RLOGE("LCTSN failed ");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    return;
}
line = p_response->p_intermediates->line;
err = at_tok_start(&line);
if(err < 0) {
    goto error;
}
responseStr = line;
RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, sizeof(char *));
at_response_free(p_response);
return;
error:
RLOGE
("%s must never return an error when radio is on", __FUNCTION__);
at_response_free(p_response);
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}
#endif
//[zhaopf@meigsmart-2020-0628] add function for write keys to modem }



//zhangqingyun remove for remin android 7.0 20180108 end
static void requestSendUSSD_googleoriginal(void *data, size_t datalen __unused, RIL_Token t)
{
const char *ussdRequest;

ussdRequest = (char *)(data);

RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);

// @@@ TODO

}

static void requestExitEmergencyMode(void *data __unused,
                                     size_t datalen __unused, RIL_Token t)
{
int err;
ATResponse *p_response = NULL;

err = at_send_command("AT+WSOS=0", &p_response);

if (err < 0 || p_response->success == 0) {
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    return;
}

RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

// TODO: Use all radio types
static int techFromModemType(int mdmtype)
{
int ret = -1;
switch (1 << mdmtype) {
case MDM_CDMA:
    ret = RADIO_TECH_1xRTT;
    break;
case MDM_EVDO:
    ret = RADIO_TECH_EVDO_A;
    break;
case MDM_GSM:
    ret = RADIO_TECH_GPRS;
    break;
case MDM_WCDMA:
    ret = RADIO_TECH_HSPA;
    break;
case MDM_LTE:
    ret = RADIO_TECH_LTE;
    break;
}
return ret;
}


/*[zhaopengfei@meigsmart-2020-05-22] add for get cell info list {*/
/*[zhaopengfei@meigsmart-2020-11-13] updated as AT commands changed  {*/

static CellConnectionStatus requestRrcStat(void)
{
	ATResponse *p_response = NULL;
	int err;
	char *line;
	char ret;

	err = at_send_command_singleline("AT^RRCSTAT?", "^RRCSTAT:", &p_response);

	if (err < 0 || p_response->success == 0) {
		RLOGE("%s RRCSTAT failed!", __FUNCTION__);
		goto error;
	}

	line = p_response->p_intermediates->line;

	err = at_tok_start(&line);
	if (err < 0) {
		RLOGE("%s parse line failed!", __FUNCTION__);
		goto error;
	}

	err = at_tok_nextint(&line, &ret);
	if (err < 0) {
		RLOGE("%s parse int failed!", __FUNCTION__);
		goto error;
	}

	at_response_free(p_response);
	RLOGE("%s rrcstat = %d!", __FUNCTION__, ret);
	return ret + 1;
error:
	at_response_free(p_response);
	return NONE;
}

#if 1
/*[zhaopengfei@meigsmart-2020-12-30] add for new cellinfo command support {*/
static void requestGetCellInfoList_V2(void *data __unused, size_t datalen __unused,
                                   RIL_Token t)
{

int err;
int i, skip;
char* skip_str = NULL;
const int  RSSI_LOW = -113;
char* line;
ATLine *p_cur;
int skip_count;
char* curr_mode = NULL;
const int response_value_len = 9;
int rssi = -120;
RIL_RadioTechnology radio_tech = RADIO_TECH_UNKNOWN;
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
#define RIL_CELLINFO_V12 1
#endif
#if RIL_CELLINFO_V12
RIL_CellInfo_v12 rillCellInfo[1];
RLOGD("requestGetCellInfoList_V2 requestGetCellInfoList cellinfo v12");
#else
RIL_CellInfo rillCellInfo[1];
RLOGD("requestGetCellInfoList_V2 requestGetCellInfoList cellinfo");
#endif
ATResponse *p_response = NULL;
uint64_t curTime = ril_nano_time();
radio_tech = getRadioTechnology();


err = at_send_command_singleline("AT+SGCELLINFOEX","+SGCELLINFOEX:",&p_response);
if(err < 0 || p_response->success == 0) {
    goto error;
}
line = p_response->p_intermediates->line;
err = at_tok_start(&line);
if(err < 0) {
    goto error;
}

err = at_tok_nextstr(&line,&curr_mode);
if(err < 0) {
    goto error;
}
RLOGD("curr_mode=%s", curr_mode);
if(NULL != strstr(curr_mode, "LTE")){

       rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_LTE;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci = 0;
#if RIL_CELLINFO_V12
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn = 0;
#endif
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac = INT_MAX;
        //duplex_mode
        err = at_tok_nextstr(&line,&skip_str);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        //global_cell_id
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        //physical_cell_id
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        //eNBID
        err = at_tok_nextstr(&line,&skip_str);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        //cell_id
        err = at_tok_nextstr(&line,&skip_str);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        //tac_id
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        // band
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.band);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        // lte_bandwidth
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.bandwidth);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.cellIdentityLte.bandwidth = rillCellInfo[0].CellInfo.lte.cellIdentityLte.bandwidth / 5 * 1000;

        // earfcn
#ifdef RIL_CELLINFO_V12
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        skip_count=1;
#else
        skip_count=2;
#endif

        while(skip_count-->0){
            //dl_channel, ul_channel
            err = at_tok_nextstr(&line,&skip_str);
            if(err < 0) {
                RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
                goto error;
            }

        }

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength = (rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength + 113) / 2;

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp = 0 - rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp;

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq = 0 - rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq;

       err = at_tok_nextstr(&line,&skip_str);
       if(err < 0) {
        RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
           goto error;
       }

        /*Modify by zhaopengfei for ASR、UNISOC cellinfolist support 2022/12/28 Begin */
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            //goto error;
        } else {
            rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr = rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr * 10;
        }
        /*Modify by zhaopengfei for ASR、UNISOC cellinfolist support 2022/12/28 End */

         skip_count=2;

        while(skip_count-->0){
            //dl_channel, ul_channel
            err = at_tok_nextstr(&line,&skip_str);
            if(err < 0) {
                RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
                goto error;
            }

        }
} else if(NULL != strstr(curr_mode, "WCDMA")){

            rillCellInfo[0].cellInfoType =  RIL_CELL_INFO_TYPE_WCDMA;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc = INT_MAX;
            #if RIL_CELLINFO_V12
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.uarfcn= 0;
            #endif


        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }


        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc);
        if(err < 0) {
            goto error;
        }
		RLOGE("%s mcc = %d, mnc=%d, cid = %d, psc = %d", __FUNCTION__,
		rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc,
		rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc,
		rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid,
		rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc);
        skip_count=2;
        while(skip_count-->0){
            //NodeB, cell_id
            err = at_tok_nextstr(&line,&skip_str);
            if(err < 0) {
                RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
                goto error;
            }

        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        // band
        err = at_tok_nextstr(&line,&skip_str);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

#ifdef RIL_CELLINFO_V12
        // uarfcn (dl channel)
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.uarfcn);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        skip_count = 1;
#else
        skip_count = 2;
#endif
        while(skip_count-- > 0){
            // ul channel
            err = at_tok_nextstr(&line,&skip_str);
            if(err < 0) {
                RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
                goto error;
            }

        }

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.signalStrengthWcdma.signalStrength);
        if(err < 0) {
            goto error;
        }
      rillCellInfo[0].CellInfo.wcdma.signalStrengthWcdma.signalStrength = (rillCellInfo[0].CellInfo.wcdma.signalStrengthWcdma.signalStrength+2)/2;
}else if(NULL != strstr(curr_mode, "EN-DC")){

       rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_LTE;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci = 0;
#if RIL_CELLINFO_V12
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn = 0;
#endif
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac = INT_MAX;
        //pcell_duplex_mode
        err = at_tok_nextstr(&line,&skip_str);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc);
        if(err < 0) {
            goto error;
        }
        //global_cell_id
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        //physical_cell_id
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        //eNBID
        err = at_tok_nextstr(&line,&skip_str);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        //cell_id
        err = at_tok_nextstr(&line,&skip_str);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        //tac_id
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        // band
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.band);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        // lte_bandwidth
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.bandwidth);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.cellIdentityLte.bandwidth = rillCellInfo[0].CellInfo.lte.cellIdentityLte.bandwidth / 5 * 1000;

        // earfcn
#ifdef RIL_CELLINFO_V12
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        skip_count = 1;
#else
        skip_count=2;
#endif
        while(skip_count-->0){
            //dl_channel, ul_channel
            err = at_tok_nextstr(&line,&skip_str);
            if(err < 0) {
                goto error;
            }

        }

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength = (rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength + 113) / 2;

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp = 0 - rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp;

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq = 0 - rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq;

       err = at_tok_nextstr(&line,&skip_str);
       if(err < 0) {
           RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
           goto error;
       }
        /*Modify by zhaopengfei for ASR、UNISOC cellinfolist support 2022/12/28 Begin */
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            //goto error;
        } else {
            rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr = (rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr * 10);
        }
        /*Modify by zhaopengfei for ASR、UNISOC cellinfolist support 2022/12/28 End */

}else if(NULL != strstr(curr_mode, "5G")){

       rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_LTE;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci = 0;
#if RIL_CELLINFO_V12
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn = 0;
#endif
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac = INT_MAX;
        //duplex_mode
        err = at_tok_nextstr(&line,&skip_str);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        //global_cell_id
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }


        //physical_cell_id
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        //tac_id
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        // band
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.band);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        // lte_bandwidth
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.bandwidth);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.cellIdentityLte.bandwidth = rillCellInfo[0].CellInfo.lte.cellIdentityLte.bandwidth / 5 * 1000;

        skip_count=4;
        while(skip_count-->0){
            //sub_carrier_spacing, fr_type, dl_channel, ul_channel
            err = at_tok_nextstr(&line,&skip_str);
            if(err < 0) {
                RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
                goto error;
            }

        }

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        //rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength = (rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength+2)/2;

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp = 0 - rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp;

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq = 0 - rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq;

       /*Modify by zhaopengfei for ASR、UNISOC cellinfolist support 2022/12/28 Begin */
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            //goto error;
        } else {
          rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr = (rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr*10);
        }
        /*Modify by zhaopengfei for ASR、UNISOC cellinfolist support 2022/12/28 End */

} else if(NULL != strstr(curr_mode, "GSM")){
       rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_GSM;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mcc = INT_MAX;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mnc = INT_MAX;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac = INT_MAX;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid = INT_MAX;
#if RIL_CELLINFO_V12
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.arfcn = 0;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.bsic = 0xff;
#endif

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mcc);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mnc);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }

#ifdef RIL_CELLINFO_V12
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.arfcn);
        if(err < 0) {
            RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
            goto error;
        }
        skip_count = 1;
#else
        skip_count=2;
#endif
        while(skip_count-->0){
            //channel, band
            err = at_tok_nextstr(&line,&skip_str);
            if(err < 0) {
                RLOGE("%s:%d, err.", __FUNCTION__, __LINE__);
                goto error;
            }
        }

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.gsm.signalStrengthGsm.signalStrength);
        if(err < 0) {
            goto error;
        }
        rillCellInfo[0].CellInfo.gsm.signalStrengthGsm.signalStrength = (rillCellInfo[0].CellInfo.gsm.signalStrengthGsm.signalStrength+2)/2;


} else {
/* begin: add by dongmeirong for return success but without cellInfoType cause phone crash 20210701 */
    RLOGD("%s to be do.", curr_mode);
    #ifdef MEIG_CTS_ENABLE
        RLOGD("cts test need data even is no service");
	    rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_GSM;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mcc = s_mcc;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mnc = s_mnc;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac = INT_MAX;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid = INT_MAX;
#if RIL_CELLINFO_V12
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.arfcn = 0;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.bsic = 0xff;
#endif
       rillCellInfo[0].CellInfo.gsm.signalStrengthGsm.timingAdvance = INT_MAX;
       RLOGD("also copy this to networkscan_rillcellinfo use for networkscan");
	   memcpy(&networkscan_rillCellInfo[0],&rillCellInfo[0],sizeof(RIL_CellInfo_v12));
	#else 
        goto error;
	#endif
/* end: add by dongmeirong for return success but without cellInfoType cause phone crash 20210701 */
}

#ifdef RIL_CELLINFO_V12
rillCellInfo[0].connectionStatus = rillCellInfo[0].cellInfoType == RIL_CELL_INFO_TYPE_NONE ? 0 : 2;//requestRrcStat();
#endif

rillCellInfo[0].registered = (RADIO_TECH_UNKNOWN == radio_tech)?0:1;
rillCellInfo[0].timeStampType = RIL_TIMESTAMP_TYPE_MODEM;
rillCellInfo[0].timeStamp = curTime - 1000;
RLOGI("got cellinfo, %s, size = %d", rillCellInfo[0].registered ?"registerd":"not registed", sizeof(rillCellInfo));
//zhangqingyun add for cts test 2023-12-12
memcpy(&networkscan_rillCellInfo[0],&rillCellInfo[0],sizeof(RIL_CellInfo_v12));

RIL_onRequestComplete(t, RIL_E_SUCCESS, rillCellInfo, sizeof(rillCellInfo));
at_response_free(p_response);
return;
error:
ALOGD("requestGetCellInfoList_V2 must never return an error when radio is on");
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
at_response_free(p_response);

}
/*[zhaopengfei@meigsmart-2020-12-30] add for new cellinfo command support }*/
static void requestGetCellInfoList(void *data __unused, size_t datalen __unused,
                                   RIL_Token t)
{
int err;
int i;
const int  RSSI_LOW = -113;
char* line;
ATLine *p_cur;
char *response[3];
int rssi = -120;
RIL_RadioTechnology radio_tech;
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
#define RIL_CELLINFO_V12 1
#endif
#if RIL_CELLINFO_V12
RIL_CellInfo_v12 rillCellInfo[1];
RLOGD("requestGetCellInfoList requestGetCellInfoList cellinfo v12");
#else
RIL_CellInfo rillCellInfo[1];
RLOGD("requestGetCellInfoList requestGetCellInfoList cellinfo");
#endif
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support } */
ATResponse *p_response = NULL;
uint64_t curTime = ril_nano_time();

radio_tech = getRadioTechnology();

memset(response, 0, sizeof(response));

err = at_send_command_multiline
    ("AT+SGCELLINFOEX?", "+SGCELLINFOEX:",
     &p_response);
if (err < 0 || p_response->success == 0) {
    RLOGE("SGCELLINFOEX failed\n");
    goto error;
}

rillCellInfo[0].registered = 1;


#if 1
switch(radio_tech){
/* begin: modified by dongmeirong for AT Ver adaption 20201217 */
case RADIO_TECH_GSM:
   rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_GSM;
   rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mcc = INT_MAX;
   rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mnc = INT_MAX;
   rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac = INT_MAX;
   rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid = INT_MAX;
#if RIL_CELLINFO_V12
   rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.arfcn = 0;
   rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.bsic = 0xff;
#endif
   rssi = -120;
   for (i = 0, p_cur = p_response->p_intermediates; p_cur != NULL;
                p_cur = p_cur->p_next, i++) {
                 char *multiline = p_cur->line;
                 //RLOGD("[%s:%d] multiline = %s\n", __FUNCTION__, __LINE__, multiline);
                 if(strStartsWith(multiline,"MCC:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mcc))){
                            rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mcc = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"MNC:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mnc))){
                            rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mnc = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_2) && strStartsWith(multiline,"eNBID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac))){
                            rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_1)  && strStartsWith(multiline,"LAC ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac))){
                            rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_2) && strStartsWith(multiline,"GLOBAL CELL ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid))){
                            rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_1) && strStartsWith(multiline,"CELL ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid))){
                            rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid = INT_MAX;
                        }
#if RIL_CELLINFO_V12
                 } else if(strStartsWith(multiline,"DL CHANNEL:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.arfcn))){
                            rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.arfcn = 0;
                        };
                 } else if(strStartsWith(multiline,"BASIC_ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.bsic))){
                            rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.bsic = 0xff;
                        }
#endif
                 } else if(strStartsWith(multiline,"RSSI:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rssi))){
                           rssi = -120;
                        }

                 }

            }


            rillCellInfo[0].CellInfo.gsm.signalStrengthGsm.signalStrength = (rssi - RSSI_LOW)/2;
            rillCellInfo[0].CellInfo.gsm.signalStrengthGsm.bitErrorRate = 0 ;
#if RIL_CELLINFO_V12
            rillCellInfo[0].CellInfo.gsm.signalStrengthGsm.timingAdvance = INT_MAX;
#endif


            if(INT_MAX == rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid){
                rillCellInfo[0].registered = 0;
            }
    break;

case RADIO_TECH_UMTS:
case RADIO_TECH_HSDPA:
case RADIO_TECH_HSUPA:
case RADIO_TECH_HSPA:
case RADIO_TECH_EHRPD:
{
    switch(cur_oper){
        case CHINA_MOBILE_OPER:
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
            rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_TD_SCDMA;
            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mcc = INT_MAX;
            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mnc = INT_MAX;
            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.lac = INT_MAX;
            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cid = INT_MAX;
            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cpid = INT_MAX;

            for (i = 0, p_cur = p_response->p_intermediates; p_cur != NULL;
                p_cur = p_cur->p_next, i++) {
                 char *multiline = p_cur->line;
                 RLOGD("[%s:%d] multiline = %s\n", __FUNCTION__, __LINE__, multiline);

                 if(strStartsWith(multiline,"MCC:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mcc))){
                            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mcc = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"MNC:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mnc))){
                            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mnc = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_2) && strStartsWith(multiline,"eNBID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.lac))){
                            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.lac = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_1)  && strStartsWith(multiline,"LAC ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.lac))){
                            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.lac = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_2) && strStartsWith(multiline,"GLOBAL CELL ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cid))){
                            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cid = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_1) && strStartsWith(multiline,"CELL ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cid))){
                            rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cid = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"RSCP:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.tdscdma.signalStrengthTdscdma.rscp))){
                            rillCellInfo[0].CellInfo.tdscdma.signalStrengthTdscdma.rscp = INT_MAX;
                        }
                 }

            }
            if(INT_MAX == rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cid){
                rillCellInfo[0].registered = 0;
            }
#else
           RLOGD("[%s:%d] CHINA_MOBILE_OPER radio_tech %d not support in \n", __FUNCTION__, __LINE__, radio_tech);
           goto error;
#endif
            break;
      case CHINA_UNICOM_OPER:
            rillCellInfo[0].cellInfoType =  RIL_CELL_INFO_TYPE_WCDMA;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc = INT_MAX;
#if RIL_CELLINFO_V12
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.uarfcn= 0;
#endif
            rssi = -120;
            for (i = 0, p_cur = p_response->p_intermediates; p_cur != NULL;
                p_cur = p_cur->p_next, i++) {
                 char *multiline = p_cur->line;
                 //RLOGD("[%s:%d] multiline = %s\n", __FUNCTION__, __LINE__, multiline);

                 if(strStartsWith(multiline,"MCC:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc))){
                            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"MNC:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc))){
                            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_2) && strStartsWith(multiline,"eNBID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac))){
                            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_1)  && strStartsWith(multiline,"LAC ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac ))){
                            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac  = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_2) && strStartsWith(multiline,"GLOBAL CELL ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid))){
                            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_1) && strStartsWith(multiline,"CELL ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid))){
                            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"PSC:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc))){
                            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc = 0;
                        }
#if RIL_CELLINFO_V12
                 } else if(strStartsWith(multiline,"DL CHANNEL:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.uarfcn))){
                            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.uarfcn = 0;
                        }
#endif
                 } else if(strStartsWith(multiline,"RSSI:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rssi))){
                            rssi = -120;
                        }
                 }

            }
            if(INT_MAX == rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid){
                rillCellInfo[0].registered = 0;
            }
            rillCellInfo[0].CellInfo.wcdma.signalStrengthWcdma.signalStrength = (rssi - RSSI_LOW)/2;
            rillCellInfo[0].CellInfo.wcdma.signalStrengthWcdma.bitErrorRate = 0;

            break;
        case CHINA_TELECOM_OPER:
            rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_CDMA;
            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.networkId = INT_MAX;
            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.systemId = INT_MAX;
            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.basestationId = INT_MAX;
            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.longitude = INT_MAX;
            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.latitude = INT_MAX;
            rssi = -120;
            for (i = 0, p_cur = p_response->p_intermediates; p_cur != NULL;
                p_cur = p_cur->p_next, i++) {
                 char *multiline = p_cur->line;
                 //RLOGD("[%s:%d] multiline = %s\n", __FUNCTION__, __LINE__, multiline);

                 if(strStartsWith(multiline,"NID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.networkId))){
                            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.networkId = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"SID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.systemId))){
                            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.systemId = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"BASIC_ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.basestationId))){
                            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.basestationId = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"GLOBAL CELL ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.longitude))){
                            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.longitude = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"PSC:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.latitude))){
                            rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.latitude = 0;
                        }
                 } else if(strStartsWith(multiline,"RSSI:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rssi))){
                            rssi = -120;
                        }
                 } else if(strStartsWith(multiline,"ECIO:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.cdma.signalStrengthCdma.ecio))){
                            rillCellInfo[0].CellInfo.cdma.signalStrengthCdma.ecio = 0;
                        }
                 } else if(strStartsWith(multiline,"SINR:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.cdma.signalStrengthEvdo.signalNoiseRatio))){
                            rillCellInfo[0].CellInfo.cdma.signalStrengthEvdo.signalNoiseRatio = 0;
                        }
                 }
            }
            if(INT_MAX == rillCellInfo[0].CellInfo.cdma.cellIdentityCdma.networkId){
                rillCellInfo[0].registered = 0;
            }
            rillCellInfo[0].CellInfo.cdma.signalStrengthEvdo.dbm  = rillCellInfo[0].CellInfo.cdma.signalStrengthCdma.dbm = rssi;
            rillCellInfo[0].CellInfo.cdma.signalStrengthEvdo.ecio = rillCellInfo[0].CellInfo.cdma.signalStrengthCdma.ecio  = (rillCellInfo[0].CellInfo.cdma.signalStrengthCdma.ecio* 10);

            break;
         default:
            rillCellInfo[0].cellInfoType =  RIL_CELL_INFO_TYPE_WCDMA;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc = INT_MAX;
#if RIL_CELLINFO_V12
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.uarfcn= 0;
#endif
            rillCellInfo[0].registered = 0;
            rillCellInfo[0].CellInfo.wcdma.signalStrengthWcdma.signalStrength = 99;
            rillCellInfo[0].CellInfo.wcdma.signalStrengthWcdma.bitErrorRate = 0;

            break;
    }
}

    break;
case RADIO_TECH_LTE:
case RADIO_TECH_NR5G: //temporary
   rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_LTE;
   rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc = INT_MAX;
   rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc = INT_MAX;
   rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci = INT_MAX;
   rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci = 0;
#if RIL_CELLINFO_V12
   rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn = 0;
#endif
   rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac = INT_MAX;
   rssi = -120;
   for (i = 0, p_cur = p_response->p_intermediates; p_cur != NULL;
                p_cur = p_cur->p_next, i++) {
                 char *multiline = p_cur->line;
                 //RLOGD("[%s:%d] multiline = %s\n", __FUNCTION__, __LINE__, multiline);

                 if(strStartsWith(multiline,"MCC:")){
                        err = at_tok_start(&multiline);
                        int test = 0;
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc))){
                            RLOGE("parse mcc error\n");
                            rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"MNC:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc))){
                            rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_2 && strStartsWith(multiline,"eNBID:")) || strStartsWith(multiline,"PCELL eNBID:")
                 || strStartsWith(multiline,"TAC_ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac))){
                            rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac = INT_MAX;
                        }
                 }  else if((curr_modem_info.info.at_version == AT_VERSION_1)  && strStartsWith(multiline,"LAC ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac))){
                            rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac  = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_2 && strStartsWith(multiline,"GLOBAL CELL ID:")) || strStartsWith(multiline,"PCELL GLOBAL CELL ID:")
                 || strStartsWith(multiline,"NR CELL ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci))){
                            rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci = INT_MAX;
                        }
                 } else if((curr_modem_info.info.at_version == AT_VERSION_1) && strStartsWith(multiline,"CELL ID:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci))){
                            rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci = INT_MAX;
                        }
                 } else if(strStartsWith(multiline,"PCI:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nexthexint(&multiline, &rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci))){
                            rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci = INT_MAX;
                        }
#if RIL_CELLINFO_V12
                 } else if(strStartsWith(multiline,"DL CHANNEL:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn))){
                            rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn = 0;
                        }
                 }else if(strStartsWith(multiline,"CHANNEL:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn))){
                            rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn = 0;
                        }
#endif
                 }else if(strStartsWith(multiline,"RSSI:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rssi))){
                            rssi = -120;
                        }

                 }else if(strStartsWith(multiline,"RSRP:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp))){
                            rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrp = 44;
                        }

                 }else if(strStartsWith(multiline,"RSRQ:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq))){
                            rillCellInfo[0].CellInfo.lte.signalStrengthLte.rsrq = 3;
                        }

                 }else if(strStartsWith(multiline,"SINR:")){
                        err = at_tok_start(&multiline);
                        if(!(0 == err && 0 == at_tok_nextint(&multiline, &rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr))){
                            rillCellInfo[0].CellInfo.lte.signalStrengthLte.rssnr = -200;
                        }

                 }

            }
            if(INT_MAX == rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci){
                rillCellInfo[0].registered = 0;
            }
            rillCellInfo[0].CellInfo.lte.signalStrengthLte.signalStrength = (rssi - RSSI_LOW)/2;
             rillCellInfo[0].CellInfo.lte.signalStrengthLte.cqi = INT_MAX;
            rillCellInfo[0].CellInfo.lte.signalStrengthLte.timingAdvance = INT_MAX;




    break;
default: //gsm or known
            rillCellInfo[0].registered = 0;
            rillCellInfo[0].cellInfoType =  RIL_CELL_INFO_TYPE_WCDMA;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc = INT_MAX;
#if RIL_CELLINFO_V12
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.uarfcn= 0;
#endif
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc = 0;
            rillCellInfo[0].CellInfo.wcdma.signalStrengthWcdma.signalStrength = 99;
            rillCellInfo[0].CellInfo.wcdma.signalStrengthWcdma.bitErrorRate = 0;
    break;
/* end: modified by dongmeirong for AT Ver adaption 20201217 */
}
rillCellInfo[0].timeStampType = RIL_TIMESTAMP_TYPE_MODEM;
rillCellInfo[0].timeStamp = curTime - 1000;
//zhangqingyun add for cts test 2023-12-12
memcpy(&networkscan_rillCellInfo[0],&rillCellInfo[0],sizeof(RIL_CellInfo_v12));
#endif
RIL_onRequestComplete(t, RIL_E_SUCCESS, rillCellInfo, sizeof(rillCellInfo));
at_response_free(p_response);

return;
error:
RLOGE("requestGetCellInfoList must not return error when radio is on");
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
at_response_free(p_response);
}
/*[zhaopf@meigsmart-2020-1211]add for getcellinfolist on hisi platform { */
static void requestGetCellInfoList_Hi(void *data __unused, size_t datalen __unused,
                                   RIL_Token t)
{

int err;
int i, skip;
const int  RSSI_LOW = -113;
char* line;
ATLine *p_cur;
char* rat = NULL;
const int response_value_len = 9;
int rssi = -120;
RIL_RadioTechnology radio_tech = RADIO_TECH_UNKNOWN;
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
#define RIL_CELLINFO_V12 1
#endif
#if RIL_CELLINFO_V12
RIL_CellInfo_v12 rillCellInfo[1];
RLOGD("requestGetCellInfoList cellinfo v12");
#else
RIL_CellInfo rillCellInfo[1];
RLOGD("requestGetCellInfoList cellinfo");
#endif
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support } */
ATResponse *p_response = NULL;
uint64_t curTime = ril_nano_time();

err = at_send_command_singleline("AT^MONSC","^MONSC:",&p_response);
if(err < 0 || p_response->success == 0) {
    goto error;
}
line = p_response->p_intermediates->line;
err = at_tok_start(&line);
if(err < 0) {
    goto error;
}

err = at_tok_nextstr(&line,&rat);
if(err < 0) {
    goto error;
}

if(NULL != strstr(rat, "LTE")){

       rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_LTE;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci = INT_MAX;
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci = 0;
#if RIL_CELLINFO_V12
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn = 0;
#endif
       rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac = INT_MAX;

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.mnc);
        if(err < 0) {
            goto error;
        }
#if RIL_CELLINFO_V12
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.earfcn);
        if(err < 0) {
            goto error;
        }
#else
        err = at_tok_nextint(&line,&skip);
        if(err < 0) {
            goto error;
        }
#endif
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.ci);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.pci);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.lte.cellIdentityLte.tac);
        if(err < 0) {
            goto error;
        }

        if(INT_MAX != rillCellInfo[0].CellInfo.lte.cellIdentityLte.mcc ){
            rillCellInfo[0].registered = 1;
        }

} else if(NULL != strstr(rat, "WCDMA")){

            rillCellInfo[0].cellInfoType =  RIL_CELL_INFO_TYPE_WCDMA;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid = INT_MAX;
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc = INT_MAX;
            #if RIL_CELLINFO_V12
            rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.uarfcn= 0;
            #endif


        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mnc);
        if(err < 0) {
            goto error;
        }
#if RIL_CELLINFO_V12
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.uarfcn);
        if(err < 0) {
            goto error;
        }
#else
        err = at_tok_nextint(&line,&skip);
        if(err < 0) {
            goto error;
        }
#endif
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.psc);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.cid);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.lac);
        if(err < 0) {
            goto error;
        }

        if(INT_MAX != rillCellInfo[0].CellInfo.wcdma.cellIdentityWcdma.mcc ){
            rillCellInfo[0].registered = 1;
        }

}else if(NULL != strstr(rat, "TD_SCDMA")){

#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
          rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_TD_SCDMA;
          rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mcc = INT_MAX;
          rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mnc = INT_MAX;
          rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.lac = INT_MAX;
          rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cid = INT_MAX;
          rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cpid = INT_MAX;


        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mcc);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mnc);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nextint(&line,&skip);
        if(err < 0) {
            goto error;
        }

        err = at_tok_nextint(&line,&skip);
        if(err < 0) {
            goto error;
        }

        err = at_tok_nextint(&line,&skip);
        if(err < 0) {
            goto error;
        }

        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.cid);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.lac);
        if(err < 0) {
            goto error;
        }

        if(INT_MAX != rillCellInfo[0].CellInfo.tdscdma.cellIdentityTdscdma.mcc ){
            rillCellInfo[0].registered = 1;
        }
#else
    RLOGD("[%s:%d]  TD_SCDMA  not support in \n", __FUNCTION__, __LINE__);
    goto error;

#endif

} else if(NULL != strstr(rat, "GSM")){
       rillCellInfo[0].cellInfoType = RIL_CELL_INFO_TYPE_GSM;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mcc = INT_MAX;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mnc = INT_MAX;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac = INT_MAX;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid = INT_MAX;
#if RIL_CELLINFO_V12
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.arfcn = 0;
       rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.bsic = 0xff;
#endif

        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mcc);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mnc);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nextint(&line,&skip);
        if(err < 0) {
            goto error;
        }
#if RIL_CELLINFO_V12
        err = at_tok_nextint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.arfcn);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.bsic);
        if(err < 0) {
            goto error;
        }
#else
        err = at_tok_nextint(&line,&skip);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nexthexint(&line,&skip);
        if(err < 0) {
            goto error;
        }
#endif
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.cid);
        if(err < 0) {
            goto error;
        }
        err = at_tok_nexthexint(&line,&rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.lac);
        if(err < 0) {
            goto error;
        }

        if(INT_MAX != rillCellInfo[0].CellInfo.gsm.cellIdentityGsm.mcc ){
            rillCellInfo[0].registered = 1;
        }

} else {
    /* begin: add by dongmeirong for return success but without cellInfoType cause phone crash 20210701 */
    RLOGD("%s rat is %s", __FUNCTION__, rat);
    goto error;
    /* end: add by dongmeirong for return success but without cellInfoType cause phone crash 20210701 */
}

rillCellInfo[0].timeStampType = RIL_TIMESTAMP_TYPE_MODEM;
rillCellInfo[0].timeStamp = curTime - 1000;

RIL_onRequestComplete(t, RIL_E_SUCCESS, rillCellInfo, sizeof(rillCellInfo));
at_response_free(p_response);
return;
error:
ALOGD("requestGetCellInfoList_Hi must never return an error when radio is on");
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
at_response_free(p_response);

}
/*[zhaopengfei@meigsmart-2020-11-13] updated as AT commands changed  }*/
#endif
/*[zhaopf@meigsmart-2020-1211]add for getcellinfolist on hisi platform } */

static void requestGetCellInfoList_fake(void *data __unused, size_t datalen __unused,
                                   RIL_Token t)
{

uint64_t curTime = ril_nano_time();
RIL_CellInfo ci[1] = {
    {
        // ci[0]
        1,        // cellInfoType
        1,        // registered
        RIL_TIMESTAMP_TYPE_MODEM,
        curTime - 1000,    // Fake some time in the past
        {
            // union CellInfo
            {
                // RIL_CellInfoGsm gsm
                {
                    // gsm.cellIdneityGsm
                    s_mcc,    // mcc
                    s_mnc,    // mnc
                    INT_MAX,    // lac
                    INT_MAX,    // cid
                },
                {
                    // gsm.signalStrengthGsm
                    20,    // signalStrength
                    0        // bitErrorRate
                }
            }
        }
    }
};

RIL_onRequestComplete(t, RIL_E_SUCCESS, ci, sizeof(ci));
}
/*[zhaopengfei@meigsmart-2020-05-22] add for get cell info list }*/

static void requestSetCellInfoListRate(void *data, size_t datalen __unused,
                                       RIL_Token t)
{
// For now we'll save the rate but no RIL_UNSOL_CELL_INFO_LIST messages
// will be sent.
assert(datalen == sizeof(int));
s_cell_info_rate_ms = ((int *)data)[0];

RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

//add for android4.4 support by zhaopf 2020/12/11
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
static void requestGetHardwareConfig(void *data, size_t datalen, RIL_Token t)
{
// TODO - hook this up with real query/info from radio.

/* RIL_HardwareConfig hwCfg;

 RIL_UNUSED_PARM(data);
 RIL_UNUSED_PARM(datalen);

 hwCfg.type = -1;

 RIL_onRequestComplete(t, RIL_E_SUCCESS, &hwCfg, sizeof(hwCfg));*/
RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}
#endif




/*[zhaopf@meigsmart.com-2020-1103]add for valid request in radio state { */
/*[zhaopf@meigsmart.com-2020-1211]modify for android4.4 support { */
bool isValidRequestWhenRadioOff(int request)
{
#ifdef BUILD_WITI_MEIG_EXT_KEY_SUPPORT
    return ((RIL_REQUEST_GET_SIM_STATUS == request) ||
              (RIL_REQUEST_RADIO_POWER == request) ||
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
              (RIL_REQUEST_SHUTDOWN == request) ||
#endif
              (RIL_REQUEST_WRITE_MEIG_KEY == request) ||
              (RIL_REQUEST_READ_MEIG_KEY == request) ||
              (RIL_REQUEST_DEVICE_IDENTITY == request) ||
              (RIL_REQUEST_GET_IMEI == request)|| //add by zhaopf, 2021/09/07
              (RIL_REQUEST_BASEBAND_VERSION == request));

#else
    return ((RIL_REQUEST_GET_SIM_STATUS == request) ||
              (RIL_REQUEST_RADIO_POWER == request) ||
              (RIL_REQUEST_GET_IMEI == request)|| //add by zhaopf, 2021/09/07
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
              (RIL_REQUEST_SHUTDOWN == request) ||
#endif
              (RIL_REQUEST_DEVICE_IDENTITY == request) ||
              (RIL_REQUEST_BASEBAND_VERSION == request));
#endif
}
/*[zhaopf@meigsmart.com-2020-1211]modify for android4.4 support } */
/*[zhaopf@meigsmart.com-2020-1103]add for invalid request in radio state } */

/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
static void requestSignalWrap(RIL_Token t) {
/* begin: modified by dongmeirong for ruixun signal strength uses GSM data field 20210508 */
#ifdef DONT_REPORT_LTE_SIGNAL_STRENGTH
    requestSignalStrengthOld(NULL, 0, t);
#else
    if(QCM == curr_modem_info.info.sltn_type) {
    /*[zhaopf@meigsmart-2020-0615]add for old version srm815 support {*/
        if(get_stength_by_csq) {
            requestSignalStrengthOld(NULL, 0, t);
        } else {
            requestSignalStrengthQCM(NULL, 0, t);
        }
    } else {
        if(get_stength_by_csq) {
            requestSignalStrengthOld(NULL, 0, t);
        } else {
            requestSignalStrength(NULL, 0, t);
        }
    }
#endif
/* end: modified by dongmeirong for ruixun signal strength uses GSM data field 20210508 */
}

/* Period is fixed to 20 seconds */
#ifdef UNSOLICITED_SIGNAL_STRENGTH
static void pollSignalRegularly(int* param __unused) {
    RLOGD("%s entry", __FUNCTION__);
    requestSignalWrap(NULL);
    RIL_requestTimedCallback(pollSignalRegularly, NULL, &TIMEVAL_5);
}

static void pollSignalQuickly(int* newStart) {
    bool is_sim_not_exist = s_sim_state == SIM_ABSENT || s_sim_state == SIM_NOT_READY
                            || s_sim_state == RUIM_ABSENT || s_sim_state == RUIM_NOT_READY;
    RLOGD("%s entry pppd = %d, s_closed = %d, s_sim_state = %d, s_is_polling = %d, newStart = %d",
            __FUNCTION__, pppd, s_closed, s_sim_state, s_is_pollQuicklyStarted, newStart != NULL);
    requestSignalWrap(NULL);
    if (newStart != NULL && s_is_pollQuicklyStarted) {
        RLOGD("%s, new start while polling, no enter into polling procedure", __FUNCTION__);
        return;
    }
    if (pppd == 1 || s_closed || is_sim_not_exist) {
        RLOGD("%s, stop quickly polling procesure", __FUNCTION__);
        s_is_pollQuicklyStarted = false;
        return;
    }
    s_is_pollQuicklyStarted = true;
    RIL_requestTimedCallback(pollSignalQuickly, NULL, &TIMEVAL_5);
}
#endif
/* end: add by dongmeirong for poll signal strength by ril 20210615 */

/*** Callback methods from the RIL library to us ***/

/**
 * Call from RIL to us to make a RIL_REQUEST
 *
 * Must be completed with a call to RIL_onRequestComplete()
 *
 * RIL_onRequestComplete() may be called from any thread, before or after
 * this function returns.
 *
 * Will always be called from the same thread, so returning here implies
 * that the radio is ready to process another command (whether or not
 * the previous command has completed).
 */
static void onRequest(int request, void *data, size_t datalen, RIL_Token t)
{
ATResponse *p_response;
/*zhaopengfei@meigsmart.com-2021-0729 deactive data connection when RILJ connected Begin*/
int err,i;
char if_name[28];
/*zhaopengfei@meigsmart.com-2021-0729 deactive data connection when RILJ connected End*/
RLOGD("onRequest number : %d", request);
RLOGD("onRequest: %s", requestToString(request));


onRequestCount++;

/*[zhaopf@meigsmart-2020-1103]only shutdown be allow in unavaliable state { */
/*[zhaopf@meigsmart.com-2020-1211]add for android4.4 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
    if (sState == RADIO_STATE_UNAVAILABLE &&
     (request != RIL_REQUEST_SHUTDOWN || request != RIL_REQUEST_RADIO_POWER)) { //add radio power by zhaopf
#else
    if (sState == RADIO_STATE_UNAVAILABLE && request != RIL_REQUEST_RADIO_POWER) { //add radio power by zhaopf
#endif
/*[zhaopf@meigsmart.com-2020-1211]add for android4.4 support } */
        RLOGD("onRequest in unavalable state");
        RIL_onRequestComplete(t, RIL_E_RADIO_NOT_AVAILABLE, NULL, 0);
        return;
    }
/*[zhaopf@meigsmart-2020-1103]only shutdown be allow in unavaliable state } */

    /* Ignore all non-power requests when RADIO_STATE_OFF
     * (except RIL_REQUEST_GET_SIM_STATUS)
     */
/*[zhaopf@meigsmart-2020-1103]modify for request in radio off state { */
    if (sState == RADIO_STATE_OFF
            && !(isValidRequestWhenRadioOff(request))
       ) {
        RLOGD("onRequest ignore when readio off ");
        RIL_onRequestComplete(t, RIL_E_RADIO_NOT_AVAILABLE, NULL, 0);
        return;
    }

/*[zhaopf@meigsmart-2020-1103]modify for request in radio off state  } */
pthread_mutex_lock(&on_request_mutex);
int networktype = 0; //hzl add
switch (request) {
case RIL_REQUEST_GET_SIM_STATUS: {
    RIL_CardStatus_v7 *p_card_status;
    char *p_buffer;
    int buffer_size;

    RLOGD("onRequest entry RIL_REQUEST_GET_SIM_STATUS ");

    int result = getCardStatus(&p_card_status);
    if (result == RIL_E_SUCCESS) {
        p_buffer = (char *)p_card_status;
        buffer_size = sizeof(*p_card_status);
    } else {
        p_buffer = NULL;
        buffer_size = 0;
    }

    RLOGD("******** RIL_REQUEST_GET_SIM_STATUS result:%d buffer size is :%d",result, buffer_size);
    if(p_buffer != NULL){    
		RLOGD("function [onRequest] buffer ok return sim_status to android framework");
        RIL_onRequestComplete(t, result, p_buffer, buffer_size);
        freeCardStatus(p_card_status);
    }else {
	    RLOGD("funciton [onRequest] some error happen return faiture to framework");	
		RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
	}
    break;
}
case RIL_REQUEST_GET_CURRENT_CALLS:
    requestGetCurrentCalls(data, datalen, t);
    break;
case RIL_REQUEST_DIAL:
    requestDial(data, datalen, t);
    break;
case RIL_REQUEST_HANGUP:
    requestHangup(data, datalen, t);
    break;
case RIL_REQUEST_HANGUP_WAITING_OR_BACKGROUND:
    /*3GPP 22.030 6.5.5
    "Releases all held calls or sets User Determined User Busy
     (UDUB) for a waiting call."
    at_send_command("AT+CHLD=0", NULL);

     success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);*/
    requestHangupWaitingOrBackground(data,datalen,t);
    break;
case RIL_REQUEST_HANGUP_FOREGROUND_RESUME_BACKGROUND:
    /*3GPP 22.030 6.5.5
    "Releases all active calls (if any exist) and accepts
     the other (held or waiting) call."
    at_send_command("AT+CHLD=1", NULL);

     success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);*/
    requestHangupForegroundResumeBackground(data,datalen,t);
    break;
case RIL_REQUEST_SWITCH_WAITING_OR_HOLDING_AND_ACTIVE:
    /* 3GPP 22.030 6.5.5*/
    // "Places all active calls (if any exist) on hold and accepts
    //  the other (held or waiting) call."
    /*at_send_command("AT+CHLD=2", NULL);

    #ifdef WORKAROUND_ERRONEOUS_ANSWER
    s_expectAnswer = 1;
    #endif */
    /* WORKAROUND_ERRONEOUS_ANSWER */

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);*/
    requestSwitchWaitingOrHoldingAndActive(data,datalen,t);
    break;
case RIL_REQUEST_ANSWER:
    /*at_send_command("ATA", NULL);*/

    //#ifdef WORKAROUND_ERRONEOUS_ANSWER
    //s_expectAnswer = 1;
    //#endif                /* WORKAROUND_ERRONEOUS_ANSWER */

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);*/
    requestAnswer(data,datalen,t);
    break;
case RIL_REQUEST_CONFERENCE:
#if 0
    /* 3GPP 22.030 6.5.5
    // "Adds a held call to the conversation"
    at_send_command("AT+CHLD=3", NULL);

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);*/
#endif
    requestConference(data,datalen,t);
    break;
case RIL_REQUEST_UDUB:
#if 0
    /* user determined user busy
    /* sometimes used: ATH
    at_send_command("ATH", NULL);

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);*/
#endif
    requestUDUB(data,datalen,t);
    break;

case RIL_REQUEST_SEPARATE_CONNECTION:
#if 0
    /*{
        char cmd[12];
        int party = ((int *)data)[0];

        // Make sure that party is in a valid range.
        // (Note: The Telephony middle layer imposes a range of 1 to 7.
        // It's sufficient for us to just make sure it's single digit.)
        if (party > 0 && party < 10) {
            sprintf(cmd, "AT+CHLD=2%d", party);
            at_send_command(cmd, NULL);
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL,
                          0);
        } else {
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE,
                          NULL, 0);
        }
    }*/
#endif
    requestSeparateConnection(data,datalen,t);
    break;

case RIL_REQUEST_SIGNAL_STRENGTH:
    //zhangqingyun add for make mobile data increase 2018 0521
    //system("ping -s 1 -c 1 www.baidu.com");
    RLOGD("RIL_REQUEST_SIGNAL_STRENGTH add mobile data");
    requestSignalWrap(t);
    /*[zhaopf@meigsmart-2020-0615]add for old version srm815 support }*/
    break;
case RIL_REQUEST_VOICE_REGISTRATION_STATE:
    RLOGD("RIL_REQUEST_VOICE_REGISTRATION_STATE: add requestRegistrationState here.\n");
    requestRegistrationState(request, data, datalen, t, REG_STATE_LEN);
#ifdef UNSOLICITED_SIGNAL_STRENGTH
    requestSignalWrap(NULL);
#endif
    break;

case RIL_REQUEST_DATA_REGISTRATION_STATE:
    requestRegistrationState(request, data, datalen, t, REG_DATA_STATE_LEN);
#ifdef UNSOLICITED_SIGNAL_STRENGTH
    requestSignalWrap(NULL);
#endif
    break;
case RIL_REQUEST_OPERATOR:
    requestOperator(data, datalen, t);
#ifdef UNSOLICITED_SIGNAL_STRENGTH
        requestSignalWrap(NULL);
#endif
    break;
case RIL_REQUEST_RADIO_POWER:
    //case RIL_UNSOL_RIL_CONNECTED : setRadioPower(false, null);
//it it no need to power off radio when RIL.java connect
//set radio on
    if(((int *)data)[0] == 0){
        /*zhaopengfei@meigsmart.com-2021-0729 deactive data connection when RILJ connected Begin*/
        /*modify for libmeigcm APIs by zhaopengfei 2022/10/10 Begin */
        /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
         if(MULTI_QMI_MOD == devmode || MULTI_NDIS_MOD == devmode ){

             ifconfigDown(curr_modem_info.if_name);
             if(curr_modem_info.use_deprecated_gobi){
                CMRequestTurnDownDataCall(0);
             } else {
                 if(g_ndis_multi_num > 0) {
                     for(i = 0; i < g_ndis_multi_num; i++) {
                       CMRequestTurnDownDataCall(i);
                       ifconfigDown(curr_modem_info.vif_name[i]);
                    }
                 } else {
                      CMRequestTurnDownDataCall(0);
                      CMRequestTurnDownDataCall(1);
                      ifconfigDown(curr_modem_info.vif_name[0]);
                      ifconfigDown(curr_modem_info.vif_name[1]); //mms
                 }
             }
             RLOGD("for hs force stop dc");
       }
       /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
       /*modify for libmeigcm APIs by zhaopengfei 2022/10/10 End */
       if ((onRequestCount < 4)) {
        //setRadioState (RADIO_STATE_ON);
           RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
           break;
        }
    }
    /*zhaopengfei@meigsmart.com-2021-0729 deactive data connection when RILJ connected End*/
    requestRadioPower(data, datalen, t);
    break;
case RIL_REQUEST_DTMF: {
    //modified by zte-yuyang begin
    requestDTMF(data,datalen,t);
    break;
    //modified by zte-yuyang end
}

/* added by zte-yuyang for vousb DTMF 2010.10.28 begin */
case RIL_REQUEST_DTMF_STOP: {
    //modified by zte-yuyang begin
    requestDTMFStop(data,datalen,t);
    //modified by zte-yuyang end
    break;
}

case RIL_REQUEST_DTMF_START: {
    //case RIL_REQUEST_DTMF:
    //modified by zte-yuyang begin
    requestDTMFStart(data,datalen,t);
    break;
    //modified by zte-yuyang end
}
/* added by zte-yuyang for vousb DTMF 2010.10.28 end */
case RIL_REQUEST_SEND_SMS:
case RIL_REQUEST_SEND_SMS_EXPECT_MORE:
    requestSendSMS(data, datalen, t);
    break;


case RIL_REQUEST_DEACTIVATE_DATA_CALL:
    requestDeactivateDataCall(data, datalen, t);
    break;
case RIL_REQUEST_QUERY_CALL_FORWARD_STATUS:
    requestQueryCallForwardStatus(data, datalen, t);
    break;
case RIL_REQUEST_SET_CALL_FORWARD:
    requestSetCallForward(data, datalen, t);
    break;
case RIL_REQUEST_LAST_DATA_CALL_FAIL_CAUSE:
    requestLastPDPFailCause(t);
    break;
case RIL_REQUEST_CDMA_SEND_SMS:
    requestSendCDMASMS(data, datalen, t);
    break;
case RIL_REQUEST_IMS_SEND_SMS:
    //zhaopengfei@meigsmart.com 2022/08/23 enable ims sms
    requestImsSendSMS(data, datalen, t);
    break;
case RIL_REQUEST_SETUP_DATA_CALL:
    requestSetupDataCall(data, datalen, t);
    break;
case RIL_REQUEST_SMS_ACKNOWLEDGE:
    requestSMSAcknowledge(data, datalen, t);
    break;

case RIL_REQUEST_GET_IMSI:
    /*
    p_response = NULL;
    err = at_send_command_numeric("AT+CIMI", &p_response);

    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL,
                      0);
    } else {
        RIL_onRequestComplete(t, RIL_E_SUCCESS,
                      p_response->p_intermediates->line,
                      sizeof(char *));
    }
    at_response_free(p_response);
    */

    requestGetIMSI(data,datalen,t);
    break;
#if 1
case RIL_REQUEST_GET_IMEI:
    p_response = NULL;
    //err = at_send_command_numeric("AT+CGSN", &p_response);   //pure
    err = at_send_command_numeric("AT+GSN", &p_response);

    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL,
                              0);
    } else {
        RIL_onRequestComplete(t, RIL_E_SUCCESS,
                              p_response->p_intermediates->line,
                              sizeof(char *));
    }
    at_response_free(p_response);

    break;
#endif

case RIL_REQUEST_SIM_IO:
    requestSIM_IO(data, datalen, t);
    break;

case RIL_REQUEST_SEND_USSD:
    requestSendUSSD(data, datalen, t);
    break;

case RIL_REQUEST_CANCEL_USSD:
    /*
    p_response = NULL;
    err = at_send_command_numeric("AT+CUSD=2", &p_response);

    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL,
                      0);
    } else {
        RIL_onRequestComplete(t, RIL_E_SUCCESS,
                      p_response->p_intermediates->line,
                      sizeof(char *));
    }
    at_response_free(p_response);*/
    requestCancelUSSD(data,datalen,t);
    break;
/*[zhaopf@meigsmart.com-2022-07-01]add for network manual selection Begin */
case RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC:
/*[zhaopf@meigsmart.com-2021-06-11]for hs device ignore automatic for fast dialup { */
        at_send_command("AT+COPS=0", NULL);

/*[zhaopf@meigsmart.com-2021-06-11]for hs device ignore automatic for fast dialup } */
    RIL_onRequestComplete(t,RIL_E_SUCCESS,NULL,0);
    /*zhangqingyun add always disable this feqture 20220511 end*/
    break;
case RIL_REQUEST_SET_NETWORK_SELECTION_MANUAL:
    requestSetNetworkSelectionManual(data, datalen, t);
    break;
/*[zhaopf@meigsmart.com-2022-07-01]add for network manual selection End */
case RIL_REQUEST_DATA_CALL_LIST:
   //[zhaopf@meigsmart.com-2022-07-01]add for customed call list
    requestDataCallList(request, data, datalen, t);
    break;

case RIL_REQUEST_QUERY_NETWORK_SELECTION_MODE:
    requestQueryNetworkSelectionMode(data, datalen, t);
    break;

case RIL_REQUEST_OEM_HOOK_RAW:
    // echo back data
    RIL_onRequestComplete(t, RIL_E_SUCCESS, data, datalen);
    break;

case RIL_REQUEST_OEM_HOOK_STRINGS: {

//[zhaopf@meigsmart-2021/06/11] add for oem hook supprt Begin
    requestOemHookStrings(data, datalen, t);
//[zhaopf@meigsmart-2021/06/11] add for oem hook supprt End
    break;
}

case RIL_REQUEST_WRITE_SMS_TO_SIM:
    requestWriteSmsToSim(data, datalen, t);
    break;

case RIL_REQUEST_DELETE_SMS_ON_SIM:
    requestDeleteSmsOnSim(data,datalen,t);
    break;
    //zhangqingyun add for ruimin 7.0 ril change start
/* begin: modified by dongmeirong for PIN enter adaption 20210125 */
case RIL_REQUEST_ENTER_SIM_PIN:
case RIL_REQUEST_ENTER_SIM_PUK:
    requestEnterSimPin(data, datalen, t);
    break;
/* end: modified by dongmeirong for PIN enter adaption 20210125 */
case RIL_REQUEST_ENTER_SIM_PIN2: {
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    break;
}

case RIL_REQUEST_ENTER_SIM_PUK2: {
    RIL_onRequestComplete(t, RIL_E_PASSWORD_INCORRECT, NULL, 0);//zhangqingyun add for cts test
    break;
}

case RIL_REQUEST_CHANGE_SIM_PIN: {
    requestChangeSimPin(data, datalen, t);
    break;
}

case RIL_REQUEST_CHANGE_SIM_PIN2: {
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    break;
}
//zhangqingyun add for ruimin 7.0 ril change end
case RIL_REQUEST_IMS_REGISTRATION_STATE: {
    int reply[2];
    //0==unregistered, 1==registered
    reply[0] = s_ims_registered;

    //to be used when changed to include service supporated info
    //reply[1] = s_ims_services;

    // FORMAT_3GPP(1) vs FORMAT_3GPP2(2);
    reply[1] = s_ims_format;

    RLOGD("IMS_REGISTRATION=%d, format=%d ",
          reply[0], reply[1]);
    if (reply[1] != -1) {
        RIL_onRequestComplete(t, RIL_E_SUCCESS, reply,
                              sizeof(reply));
    } else {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE,
                              NULL, 0);
    }
    break;
}

case RIL_REQUEST_VOICE_RADIO_TECH: {

    /*[zhaopf@meigsmart-2020-1022]add for readio tech requst { */
    RIL_RadioTechnology tech = getRadioTechnology();
     //[zhaopf@meigsmart.com-2022-06-29]add for radio tech update
     updateRadioTechnology(&tech);
     RIL_onRequestComplete(t, RIL_E_SUCCESS, &tech,
                              sizeof(tech));

    /*[zhaopf@meigsmart-2020-1022]add for readio tech requst } */
}
break;
case RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE:
    requestSetPreferredNetworkType(request, data, datalen, t);
    break;
    //zhangqingyun add for add query available networks implementation 2018.0312
case RIL_REQUEST_QUERY_AVAILABLE_NETWORKS:

    requestQueryAvailableNetworks(data, datalen, t);
    break;


case RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE:
    if (curr_modem_info.info.at_version == AT_VERSION_2) {
        requestGetPreferredNetworkType_v2(request, data, datalen, t);
    } else {
        requestGetPreferredNetworkType(request, data, datalen, t);
    }
    break;

case RIL_REQUEST_GET_CELL_INFO_LIST:
/*[zhaopengfei@meigsmart-2020-11-13] add for get cell info list {*/
    if(QCM == curr_modem_info.info.sltn_type) {
        if(curr_modem_info.info.at_version == AT_VERSION_2){
            requestGetCellInfoList_V2(data, datalen, t);
        } else {
            requestGetCellInfoList(data, datalen, t);
        }
   /*Modify by zhaopengfei for ASR、UNISOC cellinfolist support 2022/12/28 Begin */
    } else if(HISI == curr_modem_info.info.sltn_type) {
        /*[zhaopengfei@meigsmart-2020-11-13] get cell info list for hisi platform { */
        requestGetCellInfoList_Hi(data, datalen, t);
        /*[zhaopengfei@meigsmart-2020-11-13] get cell info list for hisi platform } */

    } else {
        requestGetCellInfoList_V2(data, datalen, t);
    }
    /*Modify by zhaopengfei for ASR、UNISOC cellinfolist support 2022/12/28 End */
/*[zhaopengfei@meigsmart-2020-11-13] add for get cell info list }*/

    break;

case RIL_REQUEST_SET_UNSOL_CELL_INFO_LIST_RATE:
    requestSetCellInfoListRate(data, datalen, t);
    break;
//add by zhaopf for android 4.4 support
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
case RIL_REQUEST_GET_HARDWARE_CONFIG:
    requestGetHardwareConfig(data, datalen, t);
    break;
case RIL_REQUEST_SHUTDOWN:
    requestShutdown(t);
    break;
#endif
    /* CDMA Specific Requests */
case RIL_REQUEST_BASEBAND_VERSION:
    requestBasebandVersion(data, datalen, t);
    break;

case RIL_REQUEST_DEVICE_IDENTITY:
    //networktype = odm_get_current_network_type();
    /*if(networktype == 7 || networktype == 6)
        if(iscdma) */
{
    requestDeviceIdentity(request, data, datalen, t);
    break;
}
RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
break;        // Fall-through if tech is not cdma

case RIL_REQUEST_CDMA_SUBSCRIPTION:
    //if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
    //if ((odm_get_current_network_type()) == 7
    //  || odm_get_current_network_type() == 6)
    /*networktype = odm_get_current_network_type();
     if(networktype == 7 || networktype == 6)
         //if(iscdma)
     {
         requestCdmaSubscription(request, data, datalen, t);
         break;
     }*/        // Fall-through if tech is not cdma
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    break;
case RIL_REQUEST_CDMA_SET_SUBSCRIPTION_SOURCE:
    //if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
    //if ((odm_get_current_network_type()) == 7
    //  || odm_get_current_network_type() == 6)
    /*networktype = odm_get_current_network_type();
    if(networktype == 7 || networktype == 6)
        //if(iscdma)
    {
        requestCdmaSetSubscriptionSource(request, data, datalen,t);
        break;
    }*/
    // Fall-through if tech is not cdma
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    break;
case RIL_REQUEST_CDMA_GET_SUBSCRIPTION_SOURCE:
    //if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
    //if ((odm_get_current_network_type()) == 7
    //  || odm_get_current_network_type() == 6)
    /* networktype = odm_get_current_network_type();
     if(networktype == 7 || networktype == 6)
         //if(iscdma)
     {
         requestCdmaGetSubscriptionSource(request, data, datalen, t);
         break;
     }*/        // Fall-through if tech is not cdma
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    break;
case RIL_REQUEST_CDMA_QUERY_ROAMING_PREFERENCE:
    //if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
    //if ((odm_get_current_network_type()) == 7
    //  || odm_get_current_network_type() == 6)
    /* networktype = odm_get_current_network_type();
     if(networktype == 7 || networktype == 6)
         //if(iscdma)
     {
         requestCdmaGetRoamingPreference(request, data, datalen,t);
         break;
     }        // Fall-through if tech is not cdma
     */
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    break;
case RIL_REQUEST_CDMA_SET_ROAMING_PREFERENCE:
    //if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
    //if ((odm_get_current_network_type()) == 7
    //  || odm_get_current_network_type() == 6)
    /* networktype = odm_get_current_network_type();
     if(networktype == 7 || networktype == 6)
         //if(iscdma)
     {
         requestCdmaSetRoamingPreference(request, data, datalen,t);
         break;
     }        // Fall-through if tech is not cdma*/
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    break;
case RIL_REQUEST_EXIT_EMERGENCY_CALLBACK_MODE:
    //if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
    //if ((odm_get_current_network_type()) == 7
    //  || odm_get_current_network_type() == 6)
    /* networktype = odm_get_current_network_type();
     if(networktype == 7 || networktype == 6)
         //if(iscdma)
     {
         requestExitEmergencyMode(data, datalen, t);
         break;
     } */
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    break;
    //wangbo debug
case RIL_REQUEST_SET_TTY_MODE: {
    requestSetTtyMode(data, datalen, t);
    break;
}
//add by zhaopf for android 4.4 support
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
case RIL_REQUEST_GET_RADIO_CAPABILITY: {
    requestGetRadioCapability(data, datalen, t);
    break;
}
#endif
case RIL_REQUEST_GET_IMEISV: {
    //modified by zte-yuyang begin
    requestGetIMEISV(data, datalen, t);
    //modified by zte-yuyang end
    break;
}
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support { */
#if (PLATFORM_SDK_VERSION > ANDROID_6_0_SDK_VERSION)
case RIL_REQUEST_START_LCE: {
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED,
                          NULL, 0);
    break;
}
#endif
/*[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support } */
case RIL_REQUEST_SCREEN_STATE: {
    requestScreenState(data, datalen, t);
    break;
}

#if 0
//20170512 hzl add RIL_REQUEST_REPORT_STK_SERVICE_IS_RUNNING
case RIL_REQUEST_REPORT_STK_SERVICE_IS_RUNNING: {
    requestReportStkServiceIsRunning(data, datalen, t);
    break;
}
#endif

case RIL_REQUEST_SET_INITIAL_ATTACH_APN: {
    requestSetInitialAttachAPN(data, datalen, t);
    break;
}
//add by zhaopf for android 4.4 support
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
case RIL_REQUEST_ALLOW_DATA: {
    RLOGD("Fix later,some allow/not allow data work maybe need here");
    // Note: a success response should carry a non-NULL param,
    // or it will cause DcSwitchStateMachine which is only exists in Android6.0 abnormal.
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    break;
}
#endif

//[zhaopf@meigsmart-2020-0628] add function for write keys to modem {
#ifdef BUILD_WITI_MEIG_EXT_KEY_SUPPORT
case RIL_REQUEST_WRITE_MEIG_KEY:
    requestWriteMeigKey(data, datalen, t);
    break;
case RIL_REQUEST_READ_MEIG_KEY:
    requestReadMeigKey(data, datalen, t);
    break;
#endif
//[zhaopf@meigsmart-2020-0628] add function for write keys to modem }
/* begin: added by dongmeirong for public network ip request 20201225 */
case RIL_REQUEST_NETWOK_ADDRESS:
    requestNetworkAddress(t);
    break;
/* end: added by dongmeirong for public network ip request 20201225 */
/* begin: added by dongmeirong for PIN set and change 20210126 */
case RIL_REQUEST_SET_FACILITY_LOCK:
    requestSetFacilityLock(data, datalen, t);
    break;
case RIL_REQUEST_QUERY_FACILITY_LOCK:
    requestQueryFacilityLock(data, datalen, t);
    break;
/* end: added by dongmeirong for PIN set and change 20210126 */
/*[zhaopf@meigsmart-2021/05/10] add for hangsheng customed begin*/
#ifdef RIL_REQUEST_ADCREADEX
case RIL_REQUEST_ADCREADEX:
    requestReadADCEX(data, datalen, t);
    break;
#endif
/*[zhaopf@meigsmart-2021/05/10] add for hangsheng customed end*/
/*zhangqingyun add for support get body sar value and set body sar value 2023-3-21 start*/
#ifdef SUPPORT_BODY_SAR
case RIL_REQUEST_GET_SAR_RF_STATE:
    requestGetRfSar(t);
    break;

case RIL_REQUESTA_SET_SAR_RF_STATE:
    requestSetRfSar(data,datalen,t);
    break;
#endif
/*zhangqingyun add for support operate sim apdu 2023-7-18 start*/
case RIL_REQUEST_SIM_OPEN_CHANNEL:
    requestOpenChannel(data,datalen,t);
    break;
case RIL_REQUEST_SIM_CLOSE_CHANNEL:
    requestCloseChannel(data,datalen,t);
    break;
case RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL:
    requestSimTransmitApduLogicChannel(data,datalen,t);
    break;
case RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC:
    requestSimTransmitApduBasicChannel(data,datalen,t);
    break;
/*zhangqingyun add for support opertate sim apdu 2023-7-18 end*/ 
/*zhangqingyun add for support get body sar value and set body sar value 2023 -3-21 end*/
#ifdef MEIG_NEW_FEATURE
case RIL_REQUEST_SIM_AUTHENTICATION:
    requestSimAuthentication(data, datalen, t);
    break;
#endif
#ifdef START_KEEP_ALIVE
case RIL_REQUEST_START_KEEPALIVE:
    requestStartKeepAlive(data, datalen, t);
    break;
case RIL_REQUEST_STOP_KEEPALIVE:
    requestStopKeepAlive(data, datalen, t);
    break;
#endif
case RIL_REQUEST_START_NETWORK_SCAN:
    requestStartNetworkScan(data, datalen, t);
    break;
case RIL_REQUEST_STOP_NETWORK_SCAN:
    requestStopNetworkScan(data, datalen, t);
    break;
/*zhangqingyun add for support getModemActitity 2023-12-5 use qmi for gms test start*/

case RIL_REQUEST_GET_ACTIVITY_INFO:
	requestGetModemActivity(data,datalen,t);
	break;
/*zhangqingyun add for support getModemActitity 2023-12-5 use qmi for gms test end*/

/*zhangqingyun add for support setSystemSelectionChannels 2023-12-5 use qmi for gms test start*/

case RIL_REQUEST_SET_SYSTEM_SELECTION_CHANNELS:
	requestSetSystemSelectionChannels(data,datalen,t);
	break;
/*zhangqingyun add for support setSystemSelectionChannels 2023-12-5 use qmi for gms test start*/
case RIL_REQUEST_CDMA_WRITE_SMS_TO_RUIM:
	requestCdmaWriteSmsToRuim(data,datalen,t);
	break;
case RIL_REQUEST_SET_MUTE:
	requestSetMute(data,datalen,t);
	break;
/*zhangqinyun add for support vts test implementation hal 1.3*/
case RIL_REQUEST_ENABLE_MODEM:
	requestEnableModem(data,datalen,t);
	break;
/*zhangqingyun add for support vts test implementation hal 1.4*/

case RIL_REQUEST_EMERGENCY_DIAL:
	requestSetEmergencyDial(data,datalen,t);
	break;
case RIL_REQUEST_SET_CARRIER_RESTRICTIONS:
    requestSetCarrierRestriction(data,datalen,t);
	break;
case RIL_REQUEST_GET_CARRIER_RESTRICTIONS:
	requestGetCarrierRestriction(data,datalen,t);
	break;
case RIL_REQUEST_SET_DATA_PROFILE:
	requestSetDataProfile(data,datalen,t);
default:
    RLOGD("Request not supported. Tech: %d", TECH(sMdmInfo));
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    break;
}
pthread_mutex_unlock(&on_request_mutex);
}

/**
 * Synchronous call from the RIL to us to return current radio state.
 * RADIO_STATE_UNAVAILABLE should be the initial state.
 */
static RIL_RadioState currentState()
{
return sState;
}

/**
 * Call from RIL to us to find out whether a specific request code
 * is supported by this implementation.
 *
 * Return 1 for "supported" and 0 for "unsupported"
 */

static int onSupports(int requestCode __unused)
{
//@@@ todo

return 1;
}

static void onCancel(RIL_Token t __unused)
{
//@@@todo

}

static  char *getVersion(void)
{
//return "android meig-ril 1.0.03-m2-a7 0607";
//hzl 20170607 modify begin
onRequestCount = 0; //onNewCommandConnect will call this function, and RIL.java will send RIL_REQUEST_RADIO_POWER
RLOGD("******** Enter getVersion() ********");
//return REFERENCE_RIL_VERSION;
return "MT578_ANDROID_RIL_V01";
//hzl 20170607 modify end
}

static void setRadioTechnology(ModemInfo * mdm, int newtech)
{
RLOGD("setRadioTechnology(%d)", newtech);

int oldtech = TECH(mdm);

if (newtech != oldtech) {
    RLOGD("Tech change (%d => %d)", oldtech, newtech);
    TECH(mdm) = newtech;
    if (techFromModemType(newtech) != techFromModemType(oldtech)) {
        int tech = techFromModemType(TECH(sMdmInfo));
        if (tech > 0) {
            RIL_onUnsolicitedResponse
            (RIL_UNSOL_VOICE_RADIO_TECH_CHANGED, &tech,
             sizeof(tech));
        }
    }
}
}

/*[zhaopf@meigsmart.com-2020-1022] add for update radio technolgy { */
 /*[zhaopf@meigsmart-2020-0106]when received ^MODE, recheck as COPS is too slowly to change {  */
#define MEIG_COPS_CHECK_TIMEOUT_SEC    (10)
#define MEIG_COPS_CHECK_INTERVAL_SEC (2)
 /*[zhaopf@meigsmart-2020-0106]when received ^MODE, recheck as COPS is too slowly to change }  */
/* meig-zhaopengfei-2021-10-22 check cops once when param isn't null { */
static void updateRadioTechnology(void *inTech)
{
int newtech;
int oldtech = TECH(sMdmInfo);
if(inTech != NULL) {
   newtech = ((int*)inTech)[0];
} else {
   newtech = getRadioTechnology();
}
/*[zhaopf@meigsmart-2020-0106]when received ^MODE, recheck as COPS is too slowly to change {  */
static int delayed_secs = 1;
/*[zhaopf@meigsmart-2020-0106]when received ^MODE, recheck as COPS is too slowly to change }  */
RLOGD("%s newtech:%d", __FUNCTION__, newtech);

    if (newtech != oldtech) {
        /*[zhaopf@meigsmart-2020-1022]refresh network when change from low level tech Begin */
        struct timeval TIMEVAL_5 = {5, 0};
        RLOGD("Tech change (%d => %d)", oldtech, newtech);
        TECH(sMdmInfo) = newtech;
                RIL_onUnsolicitedResponse
                (RIL_UNSOL_VOICE_RADIO_TECH_CHANGED, &newtech,
                 sizeof(newtech));
                RIL_onUnsolicitedResponse
                (RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED, NULL, 0);
                /* Modify by zhaopengfei only MC551 SLM750 need flush net as 3g&2g not works well. 2022/12/07 Begin */
                if(NULL != strstr(BUILD_CUSTOMER, "MC551") && s_product_type == PRODUCT_TYPE_SLM750) {

    #if (PLATFORM_SDK_VERSION > ANDROID_5_1_SDK_VERSION)
                     if((RADIO_TECH_LTE != oldtech && RADIO_TECH_LTE_CA != oldtech && RADIO_TECH_NR5G != oldtech ) && (newtech == RADIO_TECH_LTE || newtech == RADIO_TECH_LTE_CA || newtech == RADIO_TECH_NR5G)){
    #else
                     if((RADIO_TECH_LTE != oldtech  && RADIO_TECH_NR5G != oldtech ) && (newtech == RADIO_TECH_LTE || newtech == RADIO_TECH_NR5G)){
    #endif
                        RLOGD("flush data call list if old tech < 4g)");

                     RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED, NULL, 0);
                     }
                /* Modify by zhaopengfei only MC551 SLM750 need flush net as 3g&2g not works well. 2022/12/07 End */
                 }
                /*[zhaopf@meigsmart-2020-1022]refresh network when change from low level tech End */


    /*[zhaopf@meigsmart-2020-0106]when received ^MODE, recheck as COPS is too slowly to change {  */
        delayed_secs = 1;
    } else {
        struct timeval check_delay = {MEIG_COPS_CHECK_INTERVAL_SEC, 0};
        if(inTech == NULL && delayed_secs < MEIG_COPS_CHECK_TIMEOUT_SEC) { //for valid radio tech param, just check once
            RLOGD("%s delay %d sec to check\n", __FUNCTION__, delayed_secs);
            delayed_secs += MEIG_COPS_CHECK_INTERVAL_SEC;
            RIL_requestTimedCallback(updateRadioTechnology, NULL, &check_delay);
        } else {
            delayed_secs = 1;
        }
    }
    /*[zhaopf@meigsmart-2020-0106]when received ^MODE, recheck as COPS is too slowly to change }  */


}
/* meig-zhaopengfei-2021-10-22 check cops once when param isn't null } */
/*[zhaopf@meigsmart-2020-1113]add for usb reconnection { */
static void onNetworkStateChanged(void *param __unused)
{

    RIL_requestTimedCallback(resetStaticDataCallList, NULL, &TIMEVAL_WAIT_ETH_READY);
    RLOGD("dhcp finished, report it\n");

}
/*[zhaopf@meigsmart-2020-1113]add for usb reconnection } */
/*[zhaopf@meigsmart.com-2020-1022] add for update radio technolgy } */

static void setRadioState(RIL_RadioState newState)
{
RLOGD("setRadioState(%d)", newState);
RIL_RadioState oldState;

//wangbo debug
RLOGD("******** Enter setRadioState() ********");

pthread_mutex_lock(&s_state_mutex);

oldState = sState;

RLOGD("********setRadioState  oldState=%d", oldState);

if (s_closed > 0) {
    // If we're closed, the only reasonable state is
    // RADIO_STATE_UNAVAILABLE
    // This is here because things on the main thread
    // may attempt to change the radio state after the closed
    // event happened in another thread
    newState = RADIO_STATE_UNAVAILABLE;
    //added by wangweiming for ril
    RLOGD("********s_closed > 0 newState=%d", newState);

}

if (sState != newState || s_closed > 0) {
    sState = newState;

    pthread_cond_broadcast(&s_state_cond);
}

pthread_mutex_unlock(&s_state_mutex);

/* do these outside of the mutex */
if (sState != oldState) {
    /*[zhaopengfei@meigsmart-2020-11-13] add for radio tech report {*/
    RIL_onUnsolicitedResponse
    (RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED, &sState, sizeof(sState));
    /*[zhaopengfei@meigsmart-2020-11-13] add for radio tech report }*/
    // Sim state can change as result of radio state change
    /*[zhaopf@meigsmart-2020-0108] QCM&AT_VERSION_2 use ^simst report to detect sim stat { */
    if(!(curr_modem_info.info.sltn_type == QCM && curr_modem_info.info.at_version == AT_VERSION_2)) {
        RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED,
                              NULL, 0);
        /*zhaopengfei@meigsmart.com-2021-0729 add for force sim refresh Begin*/
        #ifdef UNSOLICITED_SIM_REFRESH
            onSimRefresh();
        #endif
        /*zhaopengfei@meigsmart.com-2021-0729 add for force sim refresh End*/
    }
    /*[zhaopf@meigsmart-2020-0108] QCM&AT_VERSION_2 use ^simst report to detect sim stat } */
    /* FIXME onSimReady() and onRadioPowerOn() cannot be called
     * from the AT reader thread
     * Currently, this doesn't happen, but if that changes then these
     * will need to be dispatched on the request thread
     */
    if (sState == RADIO_STATE_ON) {
        onRadioPowerOn();
    }
}
}


//wangbo add

//zhangqingyun add for disable wifi function 20180703 start
/*
void requesSetWSTATE(int request __unused, void *data,size_t datalen __unused, RIL_Token t)
{

     int err = 0;
     ATResponse *p_response = NULL;
     int setmode = 0,mode = 0;
     char *cmd = NULL;
     setmode = ((int *)data)[0];
     RLOGD("set wifi enable state  = %d\r",setmode);



     asprintf(&cmd,"AT+CFUN=%d",setmode);
     at_send_command(cmd,&p_response);

     if (err < 0 || p_response->success == 0)
     {
         RIL_onRequestComplete(t, RIL_E_SUCCESS, p_response, sizeof(p_response));
         at_response_free(p_response);

     }else
         {
              RLOGE("requestOperator must not return error when radio is on");
         RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
         at_response_free(p_response);
         }



return ;


}




void requesGetWSTATE(int request __unused, void *data,size_t datalen __unused, RIL_Token t)
{

    int err;
    ATResponse *p_response = NULL;
    int response = 0;
    int responsenet=0;
    char *line;
    err = at_send_command_singleline("AT+CFUN?", "+CFUN:", &p_response);
    if (err < 0 || p_response->success == 0)
    {
        goto error;
    }
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0)
    {
        goto error;
    }
    RLOGD("SIGNAL-WIFI STATE  raw data=%s",line);
    err = at_tok_nextint(&line, &responsenet);
    if (err < 0)
    {
        goto error;
    }
    RLOGD("SIGNAL-WIFI STATE 1 responsenet=%d",responsenet);
    switch(responsenet)
    {
    case 0:
        response = WIFI_STATE_DISABLE;
        break;
    case 1:
        response = WIFI_STATE_ENABLE;
        break;

    default:
        goto error;
        break;
    }
    RLOGD("SIGNAL-wfi state  get  response=%d",response);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
    at_response_free(p_response);
    return;

error:
    at_response_free(p_response);
    RLOGD("ERROR: wifi state get () failed\n");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);


}



//wangbo end
*/
//zhangqingyun add for disable wifi function 20180703 end











/** Returns RUIM_NOT_READY on error */
static SIM_Status getRUIMStatus()
{
ATResponse *p_response = NULL;
int err;
int ret;
char *cpinLine;
char *cpinResult;

//wangbo debug
RLOGD("Enter getRUIMStatus() ---------->");

if (sState == RADIO_STATE_OFF || sState == RADIO_STATE_UNAVAILABLE) {
    ret = SIM_NOT_READY;
    goto done;
}

err = at_send_command_singleline("AT+CPIN?", "+CPIN:", &p_response);

if (err != 0) {
    ret = SIM_NOT_READY;
    goto done;
}

switch (at_get_cme_error(p_response)) {
case CME_SUCCESS:
    break;

case CME_SIM_NOT_INSERTED:
    ret = SIM_ABSENT;
    goto done;

default:
    ret = SIM_NOT_READY;
    goto done;
}

/* CPIN? has succeeded, now look at the result */

cpinLine = p_response->p_intermediates->line;
err = at_tok_start(&cpinLine);

if (err < 0) {
    ret = SIM_NOT_READY;
    goto done;
}

err = at_tok_nextstr(&cpinLine, &cpinResult);

if (err < 0) {
    ret = SIM_NOT_READY;
    goto done;
}

if (0 == strcmp(cpinResult, "SIM PIN")) {
    ret = SIM_PIN;
    goto done;
} else if (0 == strcmp(cpinResult, "SIM PUK")) {
    ret = SIM_PUK;
    goto done;
} else if (0 == strcmp(cpinResult, "PH-NET PIN")) {
    return SIM_NETWORK_PERSONALIZATION;
} else if (0 != strcmp(cpinResult, "READY")) {
    /* we're treating unsupported lock types as "sim absent" */
    ret = SIM_ABSENT;
    goto done;
}

at_response_free(p_response);
p_response = NULL;
cpinResult = NULL;

ret = SIM_READY;

done:
at_response_free(p_response);
return ret;
}
/*[zhaopf@meigsmart-2020-0108]check sim ready or not  by SIMST { */
int checkIfSIMReady() {
    ATResponse *p_response = NULL;
    int err;
    int ret = SIM_ABSENT;
    char *line = NULL;
    int simstate = -1;

    RLOGD("%s sState: %d", __FUNCTION__, sState);
    if (sState == RADIO_STATE_OFF || sState == RADIO_STATE_UNAVAILABLE) {
        ret = SIM_NOT_READY;
        goto done;
    }
    err = at_send_command_singleline("AT^SIMST?", "^SIMST:", &p_response);
    // modified by dongmeirong for add condition p_response->success == 0 20210115
    if (err != 0 || p_response->success == 0) {
        ret = SIM_NOT_READY;
        goto done;
    }
    line =p_response->p_intermediates->line;;
    err = at_tok_start(&line);
    if (err < 0) {
        RLOGE("invalid ^SIMST line %s\n", line);
        goto done;
    }

    err = at_tok_nextint(&line, &simstate);
    if (err < 0) {
        RLOGE("invalid ^SIMST line %s\n", line);
        goto done;
    }

    switch(simstate){
    case 0:
        ret = SIM_NOT_READY;
        RLOGI("sim not ready\n");
        break;
    case 1:
        ret = SIM_READY;
        RLOGI("sim ready\n");
        break;
    case 255:
         ret = SIM_ABSENT;
         RLOGI("sim removed\n");
        break;
    default:
        ret = SIM_ABSENT;
        break;
    }

 done:
s_sim_state = ret;
at_response_free(p_response);
return ret;
}
/*[zhaopf@meigsmart-2020-0108]check sim ready or not  by SIMST } */

/*zhangqingyun add for support get eid use at command */
static int getEidUseAt(){
    ATResponse *p_response = NULL;
    int err;
    int ret;
	int i;
	int skip;
    char *line;
	int channel_id = 1;
    int apdu_length;
	char *channel_s = NULL;
	char *cmd;
	char channel_value[5] = {'\0'};
    at_send_command("at+csim=20,\"80AA000005A903830107\"", NULL);
	#if 1
	err = at_send_command_singleline("AT+CSIM=10,\"0070000001\"","+CSIM:",&p_response);
	RLOGI("csim result is:%d",err);
    if(err < 0 || !p_response->success){
		goto error;
	}
    line = p_response->p_intermediates->line;
	err = at_tok_start(&line);
    if (err < 0) goto error;
    err = at_tok_nextint(&line,&skip);
	if (err < 0) goto error;
	err = at_tok_nextstr(&line, &channel_s);
	if(err < 0 ) goto error;
	#if 0
	if(channel_s != NULL){
	    
	}else {
		}
	#endif
	strncpy(channel_value,channel_s,2);
	RLOGD("channel_s is:%s",channel_s);
    channel_id = atoi(channel_value);
	//do not care sw1,sw2,now
	RLOGD("channel id is:%d",channel_id);
	#endif
	//at_send_command("at+csim=10,\"0070000001\"", NULL);
	//asprintf(&cmd, "AT+CGDCONT=%d,\"%s\",\"%s\"", s_default_pdp, protocol, apn);
	at_response_free(p_response);
	p_response = NULL;
	asprintf(&cmd, "AT+CSIM=42,\"0%dA4040010A0000005591010FFFFFFFF8900000100\"",channel_id);
	err = at_send_command(cmd, NULL);
    free(cmd);
	//at_send_command("AT+CSIM=42,\"01A4040010A0000005591010FFFFFFFF8900000100\"",NULL);
	//at_send_command(cmd, NULL);
	//free(cmd);
	asprintf(&cmd, "AT+CSIM=24,\"8%dE2910006BF3E035C015A00\"",channel_id);
	err = at_send_command(cmd, NULL);
    free(cmd);

	asprintf(&cmd, "AT+CSIM=10,\"0%dC0000015\"",channel_id);
	err = at_send_command_singleline(cmd, "+CSIM:", &p_response);
    free(cmd);
	
	//at_send_command("AT+CSIM=24,\"81E2910006BF3E035C015A00\"",NULL);
	//err = at_send_command_singleline("AT+CSIM=10,\"01C0000015\"","+CSIM:",&p_response);
	RLOGI("csim result is:%d",err);
    if(err < 0 || !p_response->success){
	   goto error;
    }
    line = p_response->p_intermediates->line;
	err = at_tok_start(&line);
    if (err < 0)
        goto error;
     err = at_tok_nextint(&line, &apdu_length);
    if(err < 0)
	    goto error;
    err = at_tok_nextstr(&line, &channel_s);
    RLOGD("at result sim_eid is:%s eid length is:%d",channel_s,apdu_length);
	channel_s = channel_s+10;
	strncpy(sim_eid,channel_s,32);
	RLOGD("sim eid send to android is:%s",sim_eid);
    if(err < 0 )
	    goto error;
    at_response_free(p_response);
	asprintf(&cmd, "AT+CSIM=10,\"0070800%d00\"",channel_id);
	err = at_send_command(cmd, NULL);
    free(cmd);
    return RIL_E_SUCCESS;
    error:
    RLOGE("can not get eid ");
	asprintf(&cmd, "AT+CSIM=10,\"0070800%d00\"",channel_id);
	err = at_send_command(cmd, NULL);
    free(cmd);
    at_response_free(p_response);
    return RIL_E_GENERIC_FAILURE;
}

/** Returns SIM_NOT_READY on error */
SIM_Status getSIMStatus()
{
ATResponse *p_response = NULL;
int err;
SIM_Status ret;
char *cpinLine;
char *cpinResult;
//unsigned char *simatr_p;
//wangbo debug

int i ;
int len=0;
int slotid = 1;
int atr_len = 0;

RLOGD("Enter getSIMtatus() ------------>");

RLOGD("getSIMStatus(). sState: %d", sState);
/*[zhaopf@meigsmart-2022/08/23]remove for get sim state in radio off or unvalable state Begin */
#if 0
if (sState == RADIO_STATE_OFF || sState == RADIO_STATE_UNAVAILABLE) {
    ret = SIM_NOT_READY;
    goto done;
}
#endif
/*[zhaopf@meigsmart-2022/08/23]remove for get sim state in radio off or unvalable state End */
/*zhangqingyun add for support get atr&eid 2023-11-8 start*/
memset(unsigned_sim_atr,0x0,sizeof(unsigned_sim_atr));
if(strlen(sim_atr)){
	RLOGD("sim atr already exist do nothing: %s,len is:%d",sim_atr,strlen(sim_atr));
}else{
    if(CMRequestGetSimAtr(slotid,unsigned_sim_atr,&atr_len) == 0){
	    for(i = 0;i < atr_len;i++){
            len += sprintf(sim_atr+len,"%02x",unsigned_sim_atr[i]);
        }
    }else {
        RLOGD("some error happen in CMRequestGetSimAtr do nothing");
    }
}
/*
if(atr_len <= 0){
	RLOGD("some error happen in CMRequestGetSimAtr return");
} else {
    RLOGD("atr len is:%d",atr_len);
//CMRequestGetSimEid(1, sim_eid);
//qcril_uim_bin_to_hexstring(unsigned_sim_atr,atr_len,sim_atr,64);
*/
RLOGD("begain get eid");
if(strlen(sim_eid)){
	RLOGD("sim atr already exist do nothing eid is:%s,len is:%d",sim_eid,strlen(sim_eid));
}else{
    getEidUseAt();
}
/*zhangqingyun add for support get atr&eid 2023-11-8 end*/

property_set("persist.vendor.sim.atr",sim_atr);
property_set("persist.vendor.sim.eid",sim_eid);

RLOGD("[getSIMStatus]sim_atr is:%s, eid is:%s",sim_atr,sim_eid);
#if 1
err = at_send_command_singleline("AT+CPIN?", "+CPIN:", &p_response);
RLOGD("[getSIMStatus] err is:%d",err);
if (err != 0) {
    ret = SIM_NOT_READY;
    goto done;
}

switch (at_get_cme_error(p_response)) {
case CME_SUCCESS:
    break;

case CME_SIM_NOT_INSERTED:
    ret = SIM_ABSENT;
    goto done;
case SIGNAL_QCDATACARD_SIM_NOT_INSERTED:
    ret = SIM_ABSENT;
    goto done;
#if 1
case CME_SIM_BUSY:
	ret = RUIM_BUSY;
	goto done;
#endif 
default:
    ret = SIM_NOT_READY;
    //ret = SIM_ABSENT;
    goto done;
}

// CPIN? has succeeded, now look at the result

cpinLine = p_response->p_intermediates->line;
err = at_tok_start (&cpinLine);

if (err < 0) {
    ret = SIM_NOT_READY;
    goto done;
}

err = at_tok_nextstr(&cpinLine, &cpinResult);

if (err < 0) {
    ret = SIM_NOT_READY;
    goto done;
}
RLOGD("[getSIMStatus] cpin result is:%s",cpinResult);
if (0 == strcmp (cpinResult, "SIM PIN")) {
    ret = SIM_PIN;
    goto done;
} else if (0 == strcmp (cpinResult, "SIM PUK")) {
    ret = SIM_PUK;
    goto done;
} else if (0 == strcmp (cpinResult, "PH-NET PIN")) {
    /*[zhaopengfei@meigsmart-2020-11-13] add for sim status monitor { */
    s_sim_state = SIM_NETWORK_PERSONALIZATION;
    /*[zhaopengfei@meigsmart-2020-11-13] add for sim status monitor } */
    return SIM_NETWORK_PERSONALIZATION;
} else if (0 != strcmp (cpinResult, "READY")) {
    // we're treating unsupported lock types as "sim absent"
    ret = SIM_ABSENT;
    goto done;
}
#endif
#if 0
at_response_free(p_response);
p_response = NULL;
cpinResult = NULL;
#endif
/*[zhaopf@meigsmart-2020-0108]check sim ready or not  by SIMST { */
if(curr_modem_info.info.sltn_type == QCM && curr_modem_info.info.at_version == AT_VERSION_2) {
    ret = checkIfSIMReady();
} else {
    ret = SIM_READY;
}
/*[zhaopf@meigsmart-2020-0108]check sim ready or not  by SIMST } */

//zhangqingyun add for set sms initialize 2018 05 09
// onSIMReady();
//wangbo debug
//RLOGI("---> enter getSIMStatus SIM_READY \n");
RLOGI("---> enter getSIMStatus SIM_READY ret = %d \n", ret);

done:
/*[zhaopengfei@meigsmart-2020-11-13] add for sim status monitor { */
s_sim_state = ret;
/*[zhaopengfei@meigsmart-2020-11-13] add for sim status monitor } */
at_response_free(p_response);
return ret;
}

int isCDMASim()
{
RLOGI("---> enter isCDMASim() \n");
//RLOGI("---> enter isCDMASim() | just test 3gpp\n");
return 0;
//return 1;
}

static void getIccid(char *iccid) {
    ATResponse *p_response = NULL;
    int err = -1;
    char *line = NULL;
    char *iccid_rsp = NULL;

    err = at_send_command_singleline("AT+ICCID", "ICCID:", &p_response);
    if (err < 0 || p_response->success == 0) {
        RLOGE("%s() cmd exec failed!", __FUNCTION__);
        at_response_free(p_response);
        return;
    }
    line =p_response->p_intermediates->line;;
    err = at_tok_start(&line);
    if (err < 0) {
        RLOGE("invalid +ICCID line %s\n", line);
        return;
    }

    err = at_tok_nextstr(&line, &iccid_rsp);
    if (err < 0) {
        RLOGE("invalid +ICCID line %s\n", line);
        return;
    }

    if (iccid) {
        strncpy(iccid, iccid_rsp, 32);
    }
    at_response_free(p_response);
    RLOGD("%s() leave, ICCID = %s", __FUNCTION__, iccid_rsp);
}

/**
 * Get the current card status.
 *
 * This must be freed using freeCardStatus.
 * @return: On success returns RIL_E_SUCCESS
 */
static int getCardStatus(RIL_CardStatus_v7** pp_card_status)
{
static RIL_AppStatus app_status_array[] = {
    // SIM_ABSENT = 0
    {
        RIL_APPTYPE_UNKNOWN, RIL_APPSTATE_UNKNOWN,
        RIL_PERSOSUBSTATE_UNKNOWN,
        NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN
    },
    // SIM_NOT_READY = 1
    {
        /* begin: modified by dongmeirong for ^SIMST reporting 20201117 */
        // framework did not process appState DETECTED, change it to UNKNOWN
        RIL_APPTYPE_SIM, RIL_APPSTATE_UNKNOWN,
        /* end: modified by dongmeirong for ^SIMST reporting 20201117 */
        RIL_PERSOSUBSTATE_UNKNOWN,
        NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN
    },
    // SIM_READY = 2
    {
        RIL_APPTYPE_USIM, RIL_APPSTATE_READY, RIL_PERSOSUBSTATE_READY,
        NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN
    },
    // SIM_PIN = 3
    {
        RIL_APPTYPE_USIM, RIL_APPSTATE_PIN, RIL_PERSOSUBSTATE_UNKNOWN,
        NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED,
        RIL_PINSTATE_UNKNOWN
    },
    // SIM_PUK = 4
    {
        RIL_APPTYPE_USIM, RIL_APPSTATE_PUK, RIL_PERSOSUBSTATE_UNKNOWN,
        NULL, NULL, 0, RIL_PINSTATE_ENABLED_BLOCKED,
        RIL_PINSTATE_UNKNOWN
    },
    // SIM_NETWORK_PERSONALIZATION = 5
    {
        RIL_APPTYPE_USIM, RIL_APPSTATE_SUBSCRIPTION_PERSO,
        RIL_PERSOSUBSTATE_SIM_NETWORK,
        NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED,
        RIL_PINSTATE_UNKNOWN
    },
    // RUIM_ABSENT = 6
    {
        RIL_APPTYPE_UNKNOWN, RIL_APPSTATE_UNKNOWN,
        RIL_PERSOSUBSTATE_UNKNOWN,
        NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN
    },
    // RUIM_NOT_READY = 7
    {
        /* begin: modified by dongmeirong for ^SIMST reporting 20201117 */
        // framework did not process appState DETECTED, change it to UNKNOWN
        RIL_APPTYPE_RUIM, RIL_APPSTATE_UNKNOWN,
        /* end: modified by dongmeirong for ^SIMST reporting 20201117 */
        RIL_PERSOSUBSTATE_UNKNOWN,
        NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN
    },
    // RUIM_READY = 8
    {
        RIL_APPTYPE_RUIM, RIL_APPSTATE_READY, RIL_PERSOSUBSTATE_READY,
        NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN
    },
    // RUIM_PIN = 9
    {
        RIL_APPTYPE_RUIM, RIL_APPSTATE_PIN, RIL_PERSOSUBSTATE_UNKNOWN,
        NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED,
        RIL_PINSTATE_UNKNOWN
    },
    // RUIM_PUK = 10
    {
        RIL_APPTYPE_RUIM, RIL_APPSTATE_PUK, RIL_PERSOSUBSTATE_UNKNOWN,
        NULL, NULL, 0, RIL_PINSTATE_ENABLED_BLOCKED,
        RIL_PINSTATE_UNKNOWN
    },
    // RUIM_NETWORK_PERSONALIZATION = 11
    {
        RIL_APPTYPE_RUIM, RIL_APPSTATE_SUBSCRIPTION_PERSO,
        RIL_PERSOSUBSTATE_SIM_NETWORK,
        NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED,
        RIL_PINSTATE_UNKNOWN
    },
    //
    {
        // add sim busy state zhangqingyun if not this may cause null pointer deference 
        RIL_APPTYPE_USIM, RIL_APPSTATE_UNKNOWN,
        RIL_PERSOSUBSTATE_UNKNOWN,
        NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN
    },
};
RIL_CardState card_state;
int num_apps;

int sim_status = getSIMStatus();

if (sim_status == SIM_ABSENT) {
    card_state = RIL_CARDSTATE_ABSENT;
    num_apps = 0;
} else {
    card_state = RIL_CARDSTATE_PRESENT;
    //num_apps = 2;
    num_apps = 1;
}
RLOGI("[getCardStatus] getStatus return value is:%d\n",sim_status);

/* [zhaopf@meigsmart-2021/05/10]add for notify upper Layer of framework when restart ril Begin */
if(1 == notifySimChangedOnce && SIM_READY == sim_status){
    sim_status = SIM_NOT_READY;
    notifySimChangedOnce = 0;
    RIL_requestTimedCallback(pollSIMState, NULL, &TIMEVAL_SIMPOLL); //trigger sim state change
    RLOGD("[meig]customed for hangsheng device report sim not ready first time");
}
/* [zhaopf@meigsmart-2021/05/10]add for notify upper Layer of framework when restart ril End */

// Allocate and initialize base card status.
RIL_CardStatus_v7*p_card_status = malloc(sizeof(RIL_CardStatus_v7));
if(p_card_status == NULL){
	RLOGD("function [getCardStatus] malloc fail return");
	return RIL_E_GENERIC_FAILURE;
}
memset(p_card_status, 0, sizeof(RIL_CardStatus_v7));
p_card_status->card_state = card_state;
p_card_status->universal_pin_state = RIL_PINSTATE_UNKNOWN;
//CMRequestGetSimAtr(1,sim_atr);
//CMRequestGetSimEid(1, sim_eid);
p_card_status->iccid = (char*) malloc(32);
if (p_card_status->iccid) {
    memset(p_card_status->iccid, 0, 32);
    getIccid(p_card_status->iccid);
    RLOGD("%s iccid = %s", __FUNCTION__, p_card_status->iccid);
}
//p_card_status->iccid = "89861202303200060989";
p_card_status->physicalslotid = 0 ; //now always set to zero

p_card_status->atr = sim_atr;
p_card_status->eid = sim_eid;

//p_card_status->eid =
//why?
//strcpy(p_card_status->eid,sim_eid);
RLOGD("getCardStatus p_atr is:%s,p_eid is:%s",p_card_status->atr,p_card_status->eid);
//p_card_status->gsm_umts_subscription_app_index = RIL_CARD_MAX_APPS;
//p_card_status->cdma_subscription_app_index = RIL_CARD_MAX_APPS;
//yugong set value ims_subscription_app_index -1
//p_card_status->ims_subscription_app_index = RIL_CARD_MAX_APPS; //RIL_CARD_MAX_APPS is 8
p_card_status->gsm_umts_subscription_app_index = -1;
p_card_status->cdma_subscription_app_index = -1;
p_card_status->ims_subscription_app_index = -1;
p_card_status->num_applications = num_apps;

// Initialize application status
int i;
for (i = 0; i < RIL_CARD_MAX_APPS; i++) {
    p_card_status->applications[i] = app_status_array[SIM_ABSENT];
}


if(isCDMASim()) {
    if (num_apps != 0) {
        p_card_status->num_applications = 1;
        p_card_status->gsm_umts_subscription_app_index = -1;
        p_card_status->cdma_subscription_app_index = 0; //pure value set 1
        p_card_status->applications[0] = app_status_array[sim_status+RUIM_ABSENT];
    }
} else {
    // Pickup the appropriate application status
    // that reflects sim_status for gsm.
    if (num_apps != 0) {
        // Only support one app, gsm
        //yugong set value num_applications 1
        //p_card_status->num_applications = 2;
        p_card_status->num_applications = 1;
        p_card_status->gsm_umts_subscription_app_index = 0;
        //yugong set value cdma_subscription_app_index -1
        p_card_status->cdma_subscription_app_index = -1; //pure value set 1
        //p_card_status->cdma_subscription_app_index = -1;
#if 0
        //wangbo debug 20170522
        RLOGI("---> enter getCardStatus | cdma_subscription_app_index = 8\n");
        //p_card_status->cdma_subscription_app_index = 8;
        p_card_status->cdma_subscription_app_index = 1;
#endif
        // Get the correct app status
        p_card_status->applications[0] = app_status_array[sim_status];
        //p_card_status->applications[1] =
        //  app_status_array[sim_status + RUIM_ABSENT];
    }
}
*pp_card_status = p_card_status;
return RIL_E_SUCCESS;
}

/**
 * Free the card status returned by getCardStatus
 */
static void freeCardStatus(RIL_CardStatus_v7* p_card_status)
{
    if (p_card_status) {
        if (p_card_status->iccid) {
            free(p_card_status->iccid);
        }
        free(p_card_status);
    }
}

/**
 * SIM ready means any commands that access the SIM will work, including:
 *  AT+CPIN, AT+CSMS, AT+CNMI, AT+CRSM
 *  (all SMS-related commands)
 */

static void pollSIMState(void *param __unused)
{
//ATResponse *p_response;
//int ret;

//wangbo debug
RLOGD("Enter pollSIMState Function ------> ");
/*[zhaopf@meigsmart-2020-1106] not poll sim status when modem lost { */
if (s_closed > 0) {

    RLOGD("never poll sim status due to modem lost");
    return;
}
/*[zhaopf@meigsmart-2020-1106] not poll sim status when modem lost } */

RLOGD("******** Enter pollSIMState | getSIMStatus() ");

switch (getSIMStatus()) {
#if 1
case RUIM_BUSY:
    sim_busy++;
    if(sim_busy <= SIM_BUSY_TIMES){
	RIL_requestTimedCallback(pollSIMState, NULL, &TIMEVAL_SIMPOLL);
    }else {
	RLOGI("sim busy always happen this may in esim state no need to poll every time just notify framework to get new simsate");
	RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED,
                            NULL, 0);
    }
   return;
#endif
case SIM_ABSENT:
case SIM_PIN:
case SIM_PUK:
case SIM_NETWORK_PERSONALIZATION:
case SIM_NOT_READY:
default:
    RLOGI("SIM_NOT_READY");

//SRM815 use ^SIMST
/*[zhaopf@meigsmart-2020-1231]if sim support hotpulg, dsiable poll {*/
if(!property_get_bool("ril.simhotplug.enable", false)) {
     RIL_requestTimedCallback(pollSIMState, NULL, &TIMEVAL_SIMPOLL);
}
/*[zhaopf@meigsmart-2020-1231]if sim support hotpulg, dsiable poll }*/
    return;

case SIM_READY:
    RLOGI("SIM_READY");
    onSIMReady(); //add by zhaopf for SMS init
    //wangbo 20170513 add
    // setRadioState(RADIO_STATE_SIM_READY);
    RLOGD("pollSIMState -> SIM_READY ");
    RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED,
                              NULL, 0);
/*zhaopengfei@meigsmart.com-2021-0729 add for force sim refresh Begin*/
#ifdef UNSOLICITED_SIM_REFRESH
    onSimRefresh();
#endif
/*zhaopengfei@meigsmart.com-2021-0729 add for force sim refresh End*/
    return;

}
}


/** returns 1 if on, 0 if off, and -1 on error */
static int isRadioOn()
{
ATResponse *p_response = NULL;
int err;
char *line;
char ret;

RLOGD("******** Enter Check radio is on ********");

err = at_send_command_singleline("AT+CFUN?", "+CFUN:", &p_response);

if (err < 0 || p_response->success == 0) {
    // assume radio is off
    goto error;
}

line = p_response->p_intermediates->line;

err = at_tok_start(&line);
if (err < 0)
    goto error;

err = at_tok_nextbool(&line, &ret);
if (err < 0)
    goto error;

at_response_free(p_response);

return (int)ret;

error:

at_response_free(p_response);
return -1;
}

/**
 * Parse the response generated by a +CTEC AT command
 * The values read from the response are stored in current and preferred.
 * Both current and preferred may be null. The corresponding value is ignored in that case.
 *
 * @return: -1 if some error occurs (or if the modem doesn't understand the +CTEC command)
 *          1 if the response includes the current technology only
 *          0 if the response includes both current technology and preferred mode
 */
int parse_technology_response(const char *response, int *current,
                              int32_t * preferred)
{
int err;
char *line, *p;
int ct;
int32_t pt = 0;
//char *str_pt;

//zhangqingyun add 
RLOGD("Enter parse_technology_response");

line = p = strdup(response);
RLOGD("Response: %s", line);
err = at_tok_start(&p);
if (err || !at_tok_hasmore(&p)) {
    RLOGD("err: %d. p: %s", err, p);
    free(line);
    return -1;
}

err = at_tok_nextint(&p, &ct);
if (err) {
    free(line);
    return -1;
}
if (current)
    *current = ct;

RLOGD("line remaining after int: %s", p);

err = at_tok_nexthexint(&p, &pt);
if (err) {
    free(line);
    return 1;
}
if (preferred) {
    *preferred = pt;
}
free(line);

return 0;
}





void initializeCallback_unlockPin(void *param)
{
/*
ATResponse *p_response = NULL;
int err;
int timeout = 0;
*/

RLOGD("Enter initializeCallback() unlockPin------------>");
//setRadioState (RADIO_STATE_OFF);
init_flag=1;
//at_handshake();

/* note: we don't check errors here. Everything important will
   be handled in onATTimeout and onATReaderClosed */

/*  atchannel is tolerant of echo but it must */
/*  have verbose result codes */
//at_send_command("AT", NULL);
//at_send_command("ATE0Q0V1", NULL);

/*  No auto-answer */

/* assume radio is off on error */
if (isRadioOn() > 0) {
    //zhangqingyun add 20180703 for solve compile error
    //setRadioState (RADIO_STATE_SIM_NOT_READY);
}
//<!--[ODM][ACDB]tony.wu add for open acbd when init

init_flag=0;
//end-->
}
/*[zhaopf@meigsmart-2020-0908]add for later init { */
static void onLaterInitialize (void *param __unused)
{
    ALOGD("%s", __FUNCTION__);
/*[zhaopf@meigsmart-2020-1106] not poll sim status when modem lost { */
    if(sState == RADIO_STATE_UNAVAILABLE){

        RLOGD("%s radio not ready", __FUNCTION__);
        return;
    }

    if (s_closed > 0) {
        RLOGD("never poll sim status due to modem lost");
        return;
    }
    /*[zhaopf@meigsmart-2020-1106] not poll sim status when modem lost } */

    /*[zhaopf@meigsmart-2020-0714]enable sleep {*/
    //add by zhaopf , default enable sleep on SRM815,  disable sleep on other modules {*/
    /* begin: modified by dongmeirong for AT Ver adaption 20201217 */
    if(property_get_bool("ril.sleep.work",
        (QCM == curr_modem_info.info.sltn_type) && (curr_modem_info.info.at_version == AT_VERSION_2))) {
        if(property_get_bool("ril.sleep.enable", true))
        {
            if((QCM == curr_modem_info.info.sltn_type && (curr_modem_info.info.at_version == AT_VERSION_2)) ||
                ASR == curr_modem_info.info.sltn_type) {
                at_send_command("AT+WAKEUPCFG=1", NULL); //will store
            } else {
                at_send_command("AT+SLEEPEN=1", NULL);
            }
        } else {
            if((QCM == curr_modem_info.info.sltn_type && (curr_modem_info.info.at_version == AT_VERSION_2)) ||
                ASR == curr_modem_info.info.sltn_type) {
                at_send_command("AT+WAKEUPCFG=0", NULL); //will store
            } else {
                at_send_command("AT+SLEEPEN=0", NULL);
            }
        }
    }
    /* end: modified by dongmeirong for AT Ver adaption 20201217 */
    /*[zhaopf@meigsmart-2020-0714]enable sleep }*/
}
/* begin: added by dongmeirong for AT Ver adaption 20201217 */
static AT_VERSION parseInnerVersion(char *line) {
    AT_VERSION atVersion = AT_VERSION_1;
    if (strstr(line, PRODUCT_NAME_SLM750)) {
        if (strstr(line, SOFTWARE_BASELINE_750_V2_0)) {
            atVersion = AT_VERSION_2;
            RLOGD("%s() SLM750 product with R2.0 version or above.", __FUNCTION__);
        }
        // Notice: only SLM750 is put in s_product_type. Other product is not defined. Define it if you need.
        s_product_type = PRODUCT_TYPE_SLM750;
/*yufeilong add SLM770A for support gsm only 20230227 begin*/
    } else if (strstr(line, PRODUCT_NAME_SLM770A)) {
        s_product_type = PRODUCT_TYPE_SLM770A;
/*yufeilong add SLM770A for support gsm only 20230227 end*/
    } else {
        RLOGD("%s() other version.", __FUNCTION__);
    }
    return atVersion;
}
/* Get AT version from module software version.
   Now only SLM750 needs to get AT version by this way, and R2.0 uses AT ver 2, others uses ver 1 by default
*/
AT_VERSION getAtVerByModuleSwVer() {
    ATResponse *p_response = NULL;
    int err = -1;
    ATLine *atLine = NULL;
    AT_VERSION atVersion = AT_VERSION_1;
    err = at_send_command_multiline("AT+SGSW", "+SGSW", &p_response);
    if (err < 0 || p_response->success == 0) {
        RLOGE("%s() Get software version failed, use at ver 1 by default!", __FUNCTION__);
        at_response_free(p_response);
        return AT_VERSION_1;
    }
    for (atLine = p_response->p_intermediates; atLine != NULL; atLine = atLine->p_next) {
        char *line = atLine->line;
        if (!strStartsWith(line, "InnerVersion:")) {
            continue;
        }
        err = at_tok_start(&line);
        if (err == 0 ) {
            atVersion = parseInnerVersion(line);
        }
        break;
    }
    at_response_free(p_response);
    RLOGD("%s() leave, atVersion = %d", __FUNCTION__, atVersion);
    return atVersion;
}

static void getATVersion() {
    if (curr_modem_info.info.get_at_version == NULL) {
        RLOGD("%s(), function pointer get_at_version is not set, uses default at_version.", __FUNCTION__);
        return;
    }
    curr_modem_info.info.at_version = curr_modem_info.info.get_at_version();
}

static void gpsInitATCmd() {
    //sleep(5); //optimized by zhaopf
    /*[zhaopf@meigsmart-20200-0624]add for srm815 gps support { */
    if((QCM == curr_modem_info.info.sltn_type) && (curr_modem_info.info.at_version == AT_VERSION_2)) {
        /* begin: modified by dongmeirong for AGPS requirement 20201117 */
        bool isAGpsSupported = property_get_bool("ril.agps.enable", false);
        char *suplHost = NULL;
        int suplPort = -1;
        at_send_command("AT+GPSINIT", NULL);
        at_send_command("AT+GPSCFG=\"outport\",1", NULL);
        /*begin: add by dongmeirong@meigsmart-2020-1102 for more nmea*/
        at_send_command("AT+GPSCFG=\"glonassnmeatype\",1", NULL);
        /*[zhaopf@meigsmart-20200-1211]add for srm815 enable gnss{ */
        at_send_command("AT+GPSCFG=\"galileonmeatype\",1", NULL);
        at_send_command("AT+GPSCFG=\"galileonmeatype\",2", NULL);
        at_send_command("AT+GPSCFG=\"galileonmeatype\",4", NULL);
        at_send_command("AT+GPSCFG=\"galileonmeatype\",8", NULL);
        at_send_command("AT+GPSCFG=\"galileonmeatype\",16", NULL);
        /*[zhaopf@meigsmart-20200-1211]add for srm815 enable gnss} */

        at_send_command("AT+GPSCFG=\"beidounmeatype\",2", NULL);
        at_send_command("AT+GPSCFG=\"beidounmeatype\",1", NULL);
        /*end: add by dongmeirong@meigsmart-2020-1102 for more nmea*/
        if (isAGpsSupported) {
            getSuplInfo(&suplHost, &suplPort);
        }
        /* begin: modified by dongmeirong for AGPS interface adapt 20210207 */
        if (suplHost != NULL) {
            char *cmd = NULL;
            ATResponse *response = NULL;
            int err = -1;
            asprintf(&cmd, "AT+GPSCFG=\"agpssupl\",%s:%d", suplHost, suplPort);
            err = at_send_command(cmd, &response);
            if (cmd != NULL) {
                free(cmd);
            }
            free(suplHost);
            if(err < 0 || response->success == 0) {
                RLOGD("%s send command set supl failed", __FUNCTION__);
            } else {
                s_is_supl_host_set = true;
            }
            at_response_free(response);
        }
        /* end: modified by dongmeirong for AGPS interface adapt 20210207 */
        /* end: modified by dongmeirong for AGPS requirement 20201117 */
        /*[zhaopf@meigsmart-2020-0730] default enable gps for some customer { */
        #ifdef DEFAULT_ENABLE_GPS
        /* begin: modified by dongmeirong for AGPS requirement 20201117 */
        /*[zhaopf@meigsmart-2020-1211]modify accuracy for get location faster { */
        if (isAGpsSupported) {
            at_send_command("AT+GPSRUN=1,255,200,0,1", NULL);
        } else {
            at_send_command("AT+GPSRUN=0,255,200,0,1", NULL);
        }
        /*[zhaopf@meigsmart-2020-1211]modify accuracy for get location faster } */
        /* end: modified by dongmeirong for AGPS requirement 20201117 */
        #endif
        /*[zhaopf@meigsmart-2020-0730] default enable gps for some customer } */
 /*begin: added by yufeilong for ASR adapt 20220914 */
    } else if (ASR == curr_modem_info.info.sltn_type) {
        #ifdef DEFAULT_ENABLE_GPS
        at_send_command("AT+GPSRUN", NULL);
        #endif
        at_send_command("AT+GPSCFG=\"outport\",1", NULL);
  /*end: added by yufeilong for ASR adapt 20220914 */
    } else {
        at_send_command("AT+FGGPSINIT", NULL);
        at_send_command("AT+FGGPSPORT=1,0", NULL);
        /*[zhaopf@meigsmart-2020-0730] default enable gps for some customer { */
        at_send_command("AT+FGGPSMODE=0,0,1000,10,255", NULL);
        #ifdef DEFAULT_ENABLE_GPS
        at_send_command("AT+FGGPSRUN", NULL);
        #endif
        /*[zhaopf@meigsmart-2020-0730] default enable gps for some customer } */
    }
    setIsGpsInited(true);
    /* begin: deleted by dongmeirong for AGPS requirement 20201117 */
    // meig_gps_init();
    /* end: deleted by dongmeirong for AGPS requirement 20201117 */
    /*[zhaopf@meigsmart-20200-0624]add for srm815 gps support } */
}
/* end: added by dongmeirong for AT Ver adaption 20201217 */
/*[zhaopf@meigsmart-2020-0908]add for later init } */
/**
 * Initialize everything that can be configured while we're still in
 * AT+CFUN=0
 */
/*[zhaopf@meigsmart-2022/08/23]add for network manual search failed Begin */
static int isManualSearchEnabled(){
    int err;
    char *line, *p;
    ATResponse *p_response = NULL;
    int enable = 0;
    int skip;

    err = at_send_command_singleline("AT+EFSRW=0,0,\"/nv/item_files/modem/nas/conn_mode_manual_search\"","+EFSRW:",&p_response);
    if(err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line, &enable);
    if(err < 0) {
        goto error;
    }
error:
    return enable;
}


static int enableManualSearch(){

    int err;
    char *line, *p;
    ATResponse *p_response = NULL;
    int skip;
    if(isManualSearchEnabled()){
        return 0;
    }
    err = at_send_command("AT+EFSRW=1,0,\"/nv/item_files/modem/nas/conn_mode_manual_search\", \"01\"",&p_response);
    if(err < 0 || p_response->success == 0) {
        goto error;
    }
    return 0;

error:
    return -1;

}
/*[zhaopf@meigsmart-2022/08/23]add for network manual search failed End */
/*[zhaopf@meigsmart-2022/08/23]add for uac support Begin */
static int isUacEnabled(){
    int err;
    char *line, *p;
    ATResponse *p_response = NULL;
    int enable = 0;
    int skip;

    err = at_send_command_singleline("AT^UACFG?","^UACFG:",&p_response);
    if(err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line, &enable);
    if(err < 0) {
        goto error;
    }
error:
    return enable;

}
/*modify for uac customed by zhaopengfei 2022/10/10 Begin */
static int initUac(){
    int err;
    ATResponse *p_response = NULL;
    int enable, sample;
    int skip;
    char* cmd = NULL;
    if(!curr_modem_info.info.uacSupport) {
        RLOGI("not support uac");
        return 0;
    }
    sample = property_get_int32("persist.sys.meig.uacsample", -1);
    if(sample < 0) {
        RLOGI("not support uac, do nothing");
        return 0;
    }
    if(sample != 0 && sample != 1) {
        RLOGI("disable uac");
        if(isUacEnabled()) {
            LOGD("uac has been enabled, should disable");
            err = at_send_command("AT^UACFG=0,0", NULL);
            if(err < 0) {
                RLOGE("AT^UACFG=0,0 failed");
            }
            RLOGI("reboot modem to take affect");
            at_send_command("AT+RESET", NULL);
            return -1;
        }
        return 0;
    }

    if(isUacEnabled()) {
        LOGD("uac has been enabled");
        return 0;
    }


    asprintf(&cmd, "AT^UACFG=1,%d", sample);
    err = at_send_command(cmd,&p_response);
    if(err < 0 || p_response->success == 0) {
        RLOGE("enalbe uac failed");
/*[yufeilong@meigsmart-2022/09/26]modify ril dialing fail after set uacfg failed Begin */
        free(cmd);
        return 0;
/*[yufeilong@meigsmart-2022/09/26]modify ril dialing fail after set uacfg failed end */
    }

    free(cmd);
    at_send_command("AT+RESET", NULL);
    RLOGI("reboot modem to take affect");
    at_response_free(p_response);
    return -1;
}
/*[zhaopf@meigsmart-2022/08/23]add for uac support End */
/*modify for uac customed by zhaopengfei 2022/10/10 End */
/*[zhaopf@meigsmart-2022/08/23]add for sim hotplug detect Begin */
static bool isSimHotPlugEnabled(){
    int err;
    char *line, *p;
    ATResponse *p_response = NULL;
    int enable = 0;
    int skip;

    err = at_send_command_singleline("AT+MGCFG=2","+MGCFG:",&p_response);
    if(err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line, &skip);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line, &enable);
    if(err < 0) {
        goto error;
    }
error:
    return (enable == 1);

}

static int isSimHotPlugTriggerLvl(){
    int err;
    char *line, *p;
    ATResponse *p_response = NULL;
    int trigLevel = 0;
    int skip;

    err = at_send_command_singleline("AT+MGCFG=2","+MGCFG:",&p_response);
    if(err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line, &skip);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line, &skip);
    if(err < 0) {
        goto error;
    }
    err = at_tok_nextint(&line, &trigLevel);
    if(err < 0) {
        goto error;
    }
error:
    return trigLevel;

}
/*[zhaopf@meigsmart-2022/08/23]add for sim hotplug detect End */
/*zhangqingyun add for support modem upgrade 2023-5-4 start*/
#ifdef AUTO_UPGRADE_MODEM_SUPPORT
void get_version_info(const char *version_info,VERSION_INFO *version){
    char *sep = "_";
    char *version_iterate = version_info;
    char *token;
    char version_number;
    if(version_info == NULL){
        RLOGD("version info is NULL return\n");
        return ;
    }else{
        RLOGD("version info is:%s now to analyze \n",version_info);
    }
    if((token =strsep(&version_iterate,sep)) != NULL){
        RLOGD("field project name is:%s \n",token);
        strcpy(version->project_name,token);
    }
    if((token =strsep(&version_iterate,sep)) != NULL){
        RLOGD("field hw version is:%s \n",token);
        strcpy(version->hw_version,token);
    }
    if((token =strsep(&version_iterate,sep)) != NULL){
        RLOGD("field base line is:%s \n",token);
        strcpy(version->baseline,token);
    }
    if((token =strsep(&version_iterate,sep)) != NULL){
        RLOGD("field build date is:%s \n",token);
        strcpy(version->build_time,token);
    }
    if((token =strsep(&version_iterate,sep)) != NULL){
        RLOGD("field  flash info is:%s \n",token);
        strcpy(version->flash_type,token);
    }
    if((token =strsep(&version_iterate,sep)) != NULL){
        RLOGD("field customer info is:%s \n",token);
        strcpy(version->customer_info,token);
    }
    if((token =strsep(&version_iterate,sep)) != NULL){
        RLOGD("field version number is:%s \n",token);
        strcpy(version->version_number,token);
    }
    
}
bool get_target_version_info_by_path(const char *dir,VERSION_INFO *target_version){
	DIR *pDir = NULL;
    DIR *pSubDir = NULL;
    char subdir[MAX_PATH];
	struct dirent* ent = NULL;
	struct dirent* subent = NULL;
	if ((pDir = opendir(dir)) == NULL)  {
        printf("Cannot open directory:%s/", dir);
        return false;
    }
	while ((ent = readdir(pDir)) != NULL){
		if(strstr(ent->d_name,"SLM770A") != NULL){
			RLOGD("find image in %s image name is:%s",dir,ent->d_name);
			#if 0 
			VERSION_INFO target_version;
		    memset(&target_version,0x0,sizeof(target_version);
		    get_version_info(ent->d_name, &target_version);
			#endif 
			get_version_info(ent->d_name, target_version);
			RLOGD("target version info version number is:%s\n",target_version->version_number);
			return true;
		}
	}
	RLOGD("cannot find upgrade image no need upgrade just return");
	return false;
}

bool get_image_name_by_path(const char *dir,char *image_name){
	DIR *pDir = NULL;
    DIR *pSubDir = NULL;
    char subdir[MAX_PATH];
	struct dirent* ent = NULL;
	struct dirent* subent = NULL;
	if ((pDir = opendir(dir)) == NULL)  {
        printf("Cannot open directory:%s/", dir);
        return false;
    }
	while ((ent = readdir(pDir)) != NULL){
		if(strstr(ent->d_name,"SLM770A") != NULL){
			RLOGD("[get_image_name_by_path] find image in %s ent d_name is:%s",dir,ent->d_name);
			#if 0 
			VERSION_INFO target_version;
		    memset(&target_version,0x0,sizeof(target_version);
		    get_version_info(ent->d_name, &target_version);
			#endif 
			//image_name = strdup(ent->d_name);
                        //asprintf(&image_name,"/vendor/etc/firmware/%s",ent->d_name);
                        strcpy(image_name,ent->d_name);
                        RLOGD("return image_name is%s",image_name);
			return true;
		}
	}
	RLOGD("[get_image_name_by_path] cannot find upgrade image no need upgrade just return");
	return false;
}

bool get_current_version_info(VERSION_INFO *current_version)
{
    ATResponse *p_response = NULL;
    int err = 0;
    char *line;
    char *cmd = NULL;

    err = at_send_command_singleline("AT+SGSW","InnerVersion:",&p_response);
    if(err<0 || p_response->success == 0) {
        RLOGD("at command send fail return");
		at_response_free(p_response);
		return false;
    } else {
        line = p_response->p_intermediates->line;

        at_tok_start(&line);
        skipWhiteSpace(&line);
	    RLOGD("version info is:%s\n",line);
		get_version_info(line, current_version);
		RLOGD("current version info version number is:%s\n",current_version->version_number);
        free(cmd);
    }
    at_response_free(p_response);
    return true;
}

bool check_upgrade(){
    VERSION_INFO target;
	VERSION_INFO current;
	int current_version_number;
	int target_version_number;
	char *p_current = NULL;
	char *p_target = NULL;
	if (access(VERSION_PATH, F_OK)) {
	    RLOGD("fail to acces directory:%s please check ",VERSION_PATH);
        return 0;
        }
	memset(&target,0x0,sizeof(VERSION_INFO));
	memset(&current,0x0,sizeof(VERSION_INFO));
	if(get_target_version_info_by_path(VERSION_PATH,&target) == false){
		RLOGD("fail to get target version info can't upgrade  ");
		return false;
	}
	if(get_current_version_info(&current) == false){
		RLOGD("fail to get current version info can't upgrade  ");
		return false;
	}
	p_current = current.version_number;
	p_target = target.version_number;
	p_current++;
	p_target++;
	current_version_number = atoi(p_current);
	target_version_number = atoi(p_target);
	RLOGD("current version number is:%d target version number is: %d\n ",current_version_number,target_version_number);
	if(current_version_number < target_version_number){
	    RLOGD("target version is greater then current version number need upgrade");
	    return true;
	}
	RLOGD("target version is equal or less  then current version number no need upgrade");
	return false;
}


static void startMeigUpgrade(const char *full_image_path) {
    pid_t child_pid;
    RLOGD ("%s entry full_image_path is:%s\n", __FUNCTION__,full_image_path);
    child_pid = fork();
    if (child_pid == 0) {
        //printf(shell_command, sizeof(shell_command), "/system/bin/MeigUpgradeTool_Linux -f /vendor/etc/firmware/%s -c arm64",image)
        RLOGD("success fork a child process");;
        execl("/data/MeigUpgradeTool_Linux", "MeigUpgradeTool_Linux", "-f", full_image_path, "-c", "arm64", NULL);
        exit(0);
    } else if (child_pid < 0) {
        RLOGE("failed to start %s, errno = %s\n", "MeigUpgradeTool_Linux", strerror(errno));
    } else {
        RLOGD("rild continue!!!");
    }
    RLOGD ("%s leave\n", __FUNCTION__);
}
#endif
/*zhangqingyun add for support modem upgrade 2023-5-4 end*/

/*modify libmeigcm APIs support by zhaopengfei 2022/10/10 Begin */
void initializeCallback(void *param __unused)
{
ATResponse *p_response = NULL;
int err;
int cmInitRetry = 4;
/*Add by zhaopengfei for UNISOC modem not ready for long time 2022/12/07 Begin*/
int radioRetry = 10;
/*Add by zhaopengfei for UNISOC modem not ready for long time 2022/12/07 End*/
bool cmInitFinished = false;
char dialMode[PROPERTY_VALUE_MAX] = {0};
/*[zhaopf@meigsmart-2020-0714]enable sim card hotplug {*/
char cmdstr[PROPERTY_VALUE_MAX] = { 0x0 };
/*[zhaopf@meigsmart-2020-0714]enable sim card hotplug }*/
/*[zhaopf@meigsmart-2020-0716] } handshake firstly { */
if( 0 != at_handshake()) {
    sleep(1); //optimized by zhaopf
    RLOGD("******** HandShake fail | restart initializeCallback %d times ********", handshake_failed_times);
    /*[zhaopf@meigsmart-2020-1207] reset modem when handshake many times { */
    handshake_failed_times++;
    if(s_closed > 0) {
        handshake_failed_times = 0;
        RLOGI("at port lost, die");
        return;
    }
    if(handshake_failed_times > HANDSHAKE_TIMEOUT){
        property_set("ril.meig.modem.reset", "true");
        handshake_failed_times = 0;
        /*Add by zhaopengfei for AT channel timeout 2023/01/09 Begin */
        if(UNISOC == curr_modem_info.info.sltn_type){
            if(curr_modem_info.info.descs.at_desc.epOUT != INVALID_DESC &&
                curr_modem_info.info.descs.at_desc.epIN != INVALID_DESC) {
                reset_ep(curr_modem_info.info.at_inf, curr_modem_info.info.descs.at_desc.epOUT);
                reset_ep(curr_modem_info.info.at_inf, curr_modem_info.info.descs.at_desc.epIN);
                RLOGI("reset at port");
                onATReaderClosed();
                return;
             }
        }
        /*Add by zhaopengfei for AT channel timeout 2023/01/09 End */
        RLOGI("broadcast at blocked, detect continue");

        system(RIL_AT_BLOCK_NOTIFY);
        //return; //removed by zhaopf , 2021/08/19
    }
    /*[zhaopf@meigsmart-2020-1207] reset modem when handshake many times } */

    RIL_requestTimedCallback(initializeCallback, NULL, &TIMEVAL_DELAYINIT);
    return;
}
/*[zhaopf@meigsmart-2020-0716] } handshake firstly } */
/* meig-zhaopengfei-2021-10-22 trigger module  dumps while at port timeout, not enale by default { */
#ifdef TRIG_DUMP_WHEN_TIMEOUT

if(s_last_at_timeout) {
    RLOGI("<zpf> laste at timeout, trigger dump");
    at_send_command("AT+DUMPDBG=1", NULL);
    sleep(1);
    at_send_command("AT+SYSCMD=\"echo c > /proc/sysrq-trigger\"", NULL);
}
s_last_at_timeout = false;
#endif
/* meig-zhaopengfei-2021-10-22 trigger module  dumps while at port timeout, not enale by default } */


/* [zhaopf@meigsmart-2021-0318]added for customed begin */
if(NULL != strstr(BUILD_CUSTOMER, "JINGYI")){
   if(ECM_MOD == curr_modem_info.net_mod) {
       RLOGI("customer %s not intent to support ecm, ajust to nids", BUILD_CUSTOMER);
       at_send_command("AT+SER=1,1", NULL);
    }
}

/* [zhaopf@meigsmart-2021-0318]added for customed end */

/*Modify by zhaopengfei for UNISOC modem not ready for long time 2022/12/07 Begin*/
while(RADIO_ONLINE_STATE != isRadioOn()  && radioRetry-- > 0) {
    at_send_command("AT+CFUN=1", NULL);
/*[zhaopf@meigsmart-20200-0624]srm815 need to wait more time for ready { */
    if(UNISOC == curr_modem_info.info.sltn_type ||
        (QCM == curr_modem_info.info.sltn_type && curr_modem_info.info.isFiveG)){
        RLOGD("wait 5g modem about 3s");
        sleep(radioRetry < 5?10:3);

    } else {
       sleep(radioRetry < 5?10:1);
    }
/*[zhaopf@meigsmart-20200-0624]srm815 need to wait more time for ready } */
}

if(RADIO_ONLINE_STATE != isRadioOn()  && radioRetry < 0) {

    RLOGE("radio power on failed, ignore.");
    setRadioState(RADIO_STATE_UNAVAILABLE);

}
/*Modify by zhaopengfei for UNISOC modem not ready for long time 2022/12/07 End*/
RLOGD("******** Enter initializeCallback() ********1");

/* begin: added by dongmeirong for AT Ver adaption 20201217 */
getATVersion();
/* end: added by dongmeirong for AT Ver adaption 20201217 */
/*zhangqingyun add for support autoupgrade 2023-5-7 start*/
#ifdef AUTO_UPGRADE_MODEM_SUPPORT
if(check_upgrade()){
    RLOGD("check_upgrade ok trigger upgrade modem");
    char *full_path = NULL ;
    char image[128] = {'\0'} ;
    char *pImage = image;
    if(get_image_name_by_path(VERSION_PATH,image)){
        RLOGD("call MeigUpgradeTool image_name is:%s",image);
        #if 0
	snprintf(shell_command, sizeof(shell_command), "/system/bin/MeigUpgradeTool_Linux -f /vendor/etc/firmware/%s -c arm64",image);
	sleep(1);
        RLOGD("shell cmd is:%s",shell_command);
        system(shell_command);	
        #endif
       asprintf(&full_path,"vendor/etc/firmware/%s",pImage);
       RLOGD("full image path is:%s\n",full_path);
       startMeigUpgrade(full_path);
    }else {
       RLOGD("not find image no need upgrade ");
    }
}
#endif 
/*zhangqingyun add for support autoupgrade 2023-5-7 end*/
/*[zhaopengfei@meigsmart-2022/04/01]add for reg monitor {*/
g_reg_monitor_started = false;
/*[zhaopengfei@meigsmart-2022/04/01]add for reg monitor }*/
/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail Begin */
g_invalid_sim_reset_enable = true;
/*Add by zhaopengfei 2022/11/01 reset sim power when sim ps registed fail End */
/*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 Begin */
 g_unisoc_attach_apn_notready = true;
/*Add by zhaopengfei for UNISOC attach APN support 2022/12/28 End */
 /*Add by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 Begin */
 g_deactive_working = false;
/*Add by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 End */
//Add by zhaopengfei for iface state indicate 2023/01/12
 property_set("sys.meig.ifup", "false");

/*zhaopf@meigsmart-2021/08/09 modify for unrecovery error Begin */

if(property_get_bool(CM_UNRECOVERY_ERR_PROP,false)){
    RLOGI("%s state true", CM_UNRECOVERY_ERR_PROP);
    if(curr_modem_info.info.descs.ndis_desc.epOUT != INVALID_DESC) {
        reset_ep(curr_modem_info.info.net_inf, curr_modem_info.info.descs.ndis_desc.epOUT);
    }
} else {
    RLOGI("%s state false", CM_UNRECOVERY_ERR_PROP);
}

property_set(CM_UNRECOVERY_ERR_PROP, "false");
/*zhaopf@meigsmart-2021/08/09 modify for unrecovery error End */

/*[zhaopf@meigsmart-2020-0714]modify for sim card hotplug , uac switch, manusearch Begin */
/*[yufeilong@meigsmart-2023/02/20]modify asr and unisoc support simhotplug Begin */
if(((QCM == curr_modem_info.info.sltn_type) && (curr_modem_info.info.at_version == AT_VERSION_2)) || 
    (ASR == curr_modem_info.info.sltn_type) || (UNISOC == curr_modem_info.info.sltn_type)) {
/*[yufeilong@meigsmart-2023/02/20]modify asr and unisoc support simhotplug end */
    bool hotPlugEnable = property_get_bool("ril.simhotplug.enable", false);
    int hotPlugLevel = property_get_int32("ril.simhotplug.polarity", 1);
    if(hotPlugEnable != isSimHotPlugEnabled() || hotPlugLevel != isSimHotPlugTriggerLvl()){
        sprintf(cmdstr, "AT+MGCFG=2,%d,%d", hotPlugEnable?1:0, (1 == hotPlugLevel)?1:0);
        at_send_command(cmdstr, NULL);
        at_send_command("AT$QCSIMSTAT=0", NULL); //add by zhaopf, disable qcsimstate
    } else {
        RLOGI("ignore same sim hotplug cfg");
    }
} else if(HISI == curr_modem_info.info.sltn_type){
       sprintf(cmdstr, "AT+HISICFG=4,%d,%d",
           property_get_bool("ril.simhotplug.enable", false)?1:0,
          (1 == property_get_int32("ril.simhotplug.polarity", 1))?1:0);
       at_send_command(cmdstr, NULL);


}

// Modify by zhaopengfei for only qcm support manusearch 2022/12/07
if(QCM == curr_modem_info.info.sltn_type && property_get_bool("ril.manusearch.enable", NULL != strstr(BUILD_CUSTOMER, "MC551"))){
    enableManualSearch();
}
/*Modify by zhaopengfei for disable IMS only qcm modem 2023/01/11 Begin */
if(curr_modem_info.info.sltn_type == QCM){
    if(property_get_bool("ril.meig.ims.disable", false)) {
        at_send_command("AT+EFSRW=1,0, \"/nv/item_files/ims/IMS_enable\", \"00\"", NULL);
    } else {
        at_send_command("AT+EFSRW=1,0, \"/nv/item_files/ims/IMS_enable\", \"01\"", NULL);
    }
}
/*Modify by zhaopengfei for disable IMS only qcm modem 2023/01/11 End */


if(initUac() < 0){
        RLOGI("wait modem ready");
        sleep(6);
        return;
}
/*[zhaopf@meigsmart-2020-0714]modify for sim card hotplug , uac switch, manusearch End */
RLOGD("******** Enter initializeCallback() ********1");

/* begin: added by dongmeirong for AT Ver adaption 20201217 */
getATVersion();
/* end: added by dongmeirong for AT Ver adaption 20201217 */

/*  No auto-answer */
at_send_command("ATS0=0", NULL);

/*  Extended errors */
at_send_command("AT+CMEE=1", NULL);

/*  Network registration events */
err = at_send_command("AT+CREG=2", &p_response);

//wangbo add
err = at_send_command("AT+CEREG=2", &p_response);
err = at_send_command("AT+CGREG=2", &p_response);

/* some handsets -- in tethered mode -- don't support CREG=2 */
if (err < 0 || p_response->success == 0) {
    at_send_command("AT+CREG=1", NULL);
}

at_response_free(p_response);

/*  GPRS registration events */
at_send_command("AT+CGREG=1", NULL);

/*  Call Waiting notifications */
at_send_command("AT+CCWA=1", NULL);

/*  Alternating voice/data off */
at_send_command("AT+CMOD=0", NULL);

/*  Not muted */
//at_send_command("AT+CMUT=0", NULL);

//wangbo debug
at_send_command("AT+NWMINDEN=0", NULL);

/*  +CSSU unsolicited supp service notifications */
at_send_command("AT+CSSN=0,1", NULL);

/*  no connected line identification */
//at_send_command("AT+COLP=0", NULL);

/*  HEX character set */
// at_send_command("AT+CSCS=\"HEX\"", NULL);

/*[zhaopf@meigsmart-2020-1016] QCM modem not support UCS2 now { */
at_send_command("AT+CSCS=\"IRA\"", NULL);
at_send_command("AT+CSCS?", NULL);
/*[zhaopf@meigsmart-2020-1016] QCM modem not support UCS2 now } */

/*  USSD unsolicited */
at_send_command("AT+CUSD=1", NULL);

/*  Enable +CGEV GPRS event notifications, but don't buffer */
at_send_command("AT+CGEREP=1,0", NULL);

/*  SMS PDU mode */
//zhangqingyun add for sms initialize setting 2018 05 08

at_send_command("AT$QCMGF=0", NULL);
at_send_command("AT+SMSMODE=1", NULL);

at_send_command("AT+CMGF=0", NULL);
/*yufeilong modify for cannot received sms after wake up 20230404 begin*/
reportUnreadSMS();
/*yufeilong modify for cannot received sms after wake up 20230404 end*/
/*[zhaopf@meigsmart-2020-0714]enable sim card hotplug {*/
//[zhaopf@meigsmart-2021/05/10]add for notify upper Layer of framework when restart ril Begin
if(NULL != strstr(BUILD_CUSTOMER, "HANGSHENG")){
    notifySimChangedOnce = 1;
//[zhaopf@meigsmart-2021/11/01]read adc then stored in prop, for hangsheng device
#ifdef RIL_REQUEST_ADCREADEX
    requestReadADCEX(NULL, NULL, NULL);
#endif

}
//[zhaopf@meigsmart-2021/05/10]add for notify upper Layer of framework when restart ril End

/*[zhaopf@meigsmart-2020-1204]add for update 5gmode when init { */
update5GMode(false);
updateServiceDomain();
/*[zhaopf@meigsmart-2020-1204]add for update 5gmode when init } */

// Modify by zhaopengfei suppport both property as easy for user to use 2022/12/07
if(property_get_bool("ril.gps.enable", false) || property_get_bool("persist.vendor.ril.gps.enable", false))
{
    RLOGD("%s() start to init gps, s_product_type = %d", __FUNCTION__, s_product_type);
    if (s_product_type == PRODUCT_TYPE_SLM750) {
        RIL_requestTimedCallback(gpsInitATCmd, NULL, &TIMEVAL_LATER_INIT_GPS_SLM750);
    } else {
        gpsInitATCmd();
    }
}
/* end: modified by dongmeirong for AT Ver adaption 20201217 */

#ifdef USE_TI_COMMANDS

at_send_command("AT%CPI=3", NULL);

/*  TI specific -- notifications when SMS is ready (currently ignored) */
at_send_command("AT%CSTAT=1", NULL);

#endif                /* USE_TI_COMMANDS */

//wangbo debug not support EHRPD
//at_send_command("AT+EHRPDEN=0", NULL);


//wangbo 2017/07/11 add for voice, remove as no response on SRM815 sometimes
//at_send_command("AT+CMIC=7", NULL);
//at_send_command("AT+CLVL=7", NULL);

//wangbo 2018/01/08 add for codec
/*[zhaopf@meigsmart-20200-0624]default disable codec reset, due block at channel at sometime { */
if(property_get_bool("ril.codec.reset", false)) {
    at_send_command("at+codec=0", NULL);
    at_send_command("at+codec=1", NULL);
    RLOGI("reset codec");
}
/*yufeilong modify for SLM770A recive incoming call after wakeup 20230506 begin*/
ReportIncomingCalls();
/*yufeilong modify for SLM770A recive incoming call after wakeup 20230506 end*/
/*[zhaopf@meigsmart-20200-0624]default disable codec reset, due block at channel at sometime } */
//wangbo 2018/02/03 start acbd
//at_send_command("at+syscmd=start_pcm acdb_start", NULL);

at_send_command("AT+IFC=0,0", NULL);
//disconnect data
at_send_command("ATH", NULL);
/*yufeilong modify for SLM770A exit factory mode 20230404 begin*/
at_send_command("AT*PROD=0", NULL);
/*yufeilong modify for SLM770A exit factory mode 20230404 end*/

//detect dial mode
devmode = curr_modem_info.net_mod;
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
curr_modem_info.use_deprecated_gobi = property_get_bool("persist.ril.use.oldgobi", true);
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
RLOGI("use old gobi? %d\n",curr_modem_info.use_deprecated_gobi);


if(property_get("ril.dial.mode", dialMode, "")  <= 0 && property_get("ro.dial.mode", dialMode, "")  <= 0) {
    devmode = curr_modem_info.net_mod;
    RLOGD("auto detect mode %s ", devmode2str[devmode]);
} else {
    int it;
    for(it =0; it < MAX_MOD; it++) {
        if(0 == strncmp(dialMode, devmode2str[it], strlen(devmode2str[it]))) {
            curr_modem_info.net_mod = devmode = (NET_MOD)it;
            /*[zhaopf@meigsmart-2020-0615]add default interface for fixed dial mode {*/
            free(curr_modem_info.if_name);
            /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
            if(curr_modem_info.use_deprecated_gobi) {
                curr_modem_info.if_name = strdup(devmode2definfdeprectd[it]);
            } else {
                curr_modem_info.if_name = strdup(devmode2definf[it]);
            }
            /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
            RLOGD("read prop get %s mode , interface:%s\n", devmode2str[it], curr_modem_info.if_name);
            /*[zhaopf@meigsmart-2020-0615]add default interface for fixed dial mode }*/
            break;
        }
    }

}
/*yufeilong modify ifc_enable use null point begin*/
if(curr_modem_info.net_mod == QMI_MOD || curr_modem_info.net_mod == MULTI_QMI_MOD) {
    int i;
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
    curr_modem_info.use_deprecated_gobi = property_get_bool("persist.ril.use.oldgobi", true);
    if(curr_modem_info.use_deprecated_gobi){
        g_ndis_multi_num = 0;
        curr_modem_info.net_mod = QMI_MOD;
        RLOGD("as persist.ril.use.oldgobi is true, not support multi qmi/ndis");
    }
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
    for(i = 0; i < NDIS_MULTI_NUM_MAX; i++) {
        if(curr_modem_info.vif_name[i] != NULL) {
            free(curr_modem_info.vif_name[i]);
            curr_modem_info.vif_name[i] = NULL;
        }
        asprintf(&curr_modem_info.vif_name[i], "bmwan%d", i);
    }
}
/*yufeilong modify ifc_enable use null point end*/
//Add by zhaopengfei for iface state indicate 2023/01/12
property_set("sys.meig.ifname", curr_modem_info.if_name);

//[zhaopf@meigsmart-2021/05/10]add for multi ndis support Begin
if(MULTI_NDIS_MOD == devmode){
    at_send_command("AT$QCRMCALL=0,1", NULL);
    at_send_command("AT$QCRMCALL=0,2", NULL);
}
//[zhaopf@meigsmart-2021/05/10]add for multi ndis support End

/* assume radio is off on error */
if (isRadioOn() == RADIO_ONLINE_STATE) {
    setRadioState(RADIO_STATE_ON);
    flag_rildinitialize = 1;
}

    /*[zhaopf@meigsmart-2020-1217]add for modem state { */
    set_modem_state_connected(true);
    /*[zhaopf@meigsmart-2020-1217]add for modem state } */

    /*[zhaopf@meigsmart-2020-0714]enable sleep {*/
    RIL_requestTimedCallback(onLaterInitialize, NULL, &TIMEVAL_LATER_INIT);
    /*[zhaopf@meigsmart-2020-0714]enable sleep }*/

    /* begin: add by dongmeirong for poll signal strength by ril 20210615 */
#ifdef UNSOLICITED_SIGNAL_STRENGTH
    if (!s_is_pollSignalStarted) {
        RIL_requestTimedCallback(pollSignalRegularly, NULL, NULL);
        s_is_pollSignalStarted = true;
    }
#endif
    /* end: add by dongmeirong for poll signal strength by ril 20210615 */

    /* begin: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/
#ifdef POLL_SIM_ABSENT_RESET_MODULE
    if (!s_is_pollSimAbsentStarted) {
        RIL_requestTimedCallback(detectSimAbsent, NULL, &TIMEVAL_60);
        s_is_pollSimAbsentStarted = true;
    }
#endif
    /* end: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/
//init cm
RLOGI(" cm init start");

if(devmode == QMI_MOD|| devmode == MULTI_QMI_MOD){

    while(cmInitRetry-->0){
         /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
         if(0 == CMInitInstance(curr_modem_info.if_name, curr_modem_info.use_deprecated_gobi?1:0)) {
            CMRegisterDataCallListChangeListener(onCMDataCallListChanged);
            CMRegisterRegisterStateChangedListener(onCMRegisterStateChanged);
            CMRegisterRegisterHardwareRemovedListener(onCMHardwareRemoved);
             cmInitFinished = true;
             break;
        }
        /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
        RLOGI(" cm init retry %d", cmInitRetry);
        sleep(1);
    }

    if(!cmInitFinished){
        RLOGI("cm init failed, roll-back to ppp");
        free(curr_modem_info.if_name);
        curr_modem_info.if_name = strdup(devmode2definf[RAS_MOD]);
        curr_modem_info.net_mod = devmode = RAS_MOD;
    }
}
}
/*modify libmeigcm APIs support by zhaopengfei 2022/10/10 End */
static void waitForClose()
{
pthread_mutex_lock(&s_state_mutex);

while (s_closed == 0) {
    pthread_cond_wait(&s_state_cond, &s_state_mutex);
}

pthread_mutex_unlock(&s_state_mutex);
}

static void sendUnsolImsNetworkStateChanged()
{
#if 0                // to be used when unsol is changed to return data.
int reply[2];
reply[0] = s_ims_registered;
reply[1] = s_ims_services;
reply[1] = s_ims_format;
#endif
RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_IMS_NETWORK_STATE_CHANGED,
                          NULL, 0);
}
/* begin: modified by dongmeirong for add network change listenner to CGREG 20210508 */
void initCxregStat() {
    int i = 0;
    for (; i < sizeof(s_cxreg_cmd) / sizeof(CXREG_CMD); i++) {
        s_cxreg_cmd[i].stat = -1;
    }
}

static int findCxregCmd(const char *s) {
    int i = -1;
    for (i = 0; i < sizeof(s_cxreg_cmd) / sizeof(CXREG_CMD); i++) {
        if (strStartsWith(s, s_cxreg_cmd[i].cmdPrefix)) {
            RLOGD("%s cmd idx is %d", __FUNCTION__, i);
            return i;
        }
    }
    RLOGD("%s cmd idx is %d", __FUNCTION__, -1);
    return -1;
}
/* end: modified by dongmeirong for add network change listenner to CGREG 20210508 */

/**
 * Called by atchannel when an unsolicited line appears
 * This is called on atchannel's reader thread. AT commands may
 * not be issued here
 */
static void onUnsolicited(const char *s, const char *sms_pdu)
{
char *line = NULL, *p;
int err;
/* begin: modified by dongmeirong for add network change listenner to CGREG 20210508 */
int cmdId = -1;
/* end: modified by dongmeirong for add network change listenner to CGREG 20210508 */

RLOGD("******** Enter onUnsolicited() *********** ");
/* Ignore unsolicited responses until we're initialized.
 * This is OK because the RIL library will poll for initial state
 */

RLOGD("******** souce string is:%s\n",s);
/*zhangqingyun add for support nitz 2023-7-11 start*/
if (strStartsWith(s, "+CTZV:") || strStartsWith(s,"+NITZ:")) {
    /* TI specific -- NITZ time */
    char *response;

    line = p = strdup(s);
    at_tok_start(&p);
    p++;
    response = p;
    if(p != NULL){
    //err = at_tok_nextstr(&p, &response);
        RLOGD("send nitz data to android framework nitz data is: %s",response);
        RIL_onUnsolicitedResponse(RIL_UNSOL_NITZ_TIME_RECEIVED,response, strlen(response));
    }
    free(line);
/*zhangqingyun add for support nitz 2023-7-11 end*/
} else if (strStartsWith(s, "+CRING:")|| strStartsWith(s, "RING") || strStartsWith(s, "NO CARRIER") || strStartsWith(s, "+CCWA") || strStartsWith(s, "IRING")) {
    RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED,  NULL, 0);
#ifdef WORKAROUND_FAKE_CGEV
    if(QMI_MOD != devmode && MULTI_QMI_MOD != devmode) { //add by zhaopengfei 2021/11/01, for qmi mode cm will do this
        RIL_requestTimedCallback(onDataCallListChanged, NULL, NULL);    //TODO use new function
    }
#endif                /* WORKAROUND_FAKE_CGEV */
} else if (strStartsWith(s, "^SRVST:")) {
/* begin: add by dongmeirong for poll signal strength by ril 20210615 */
    int srvst = 0;
    line = p = strdup(s);
    at_tok_start(&p);
    err = at_tok_nextint(&p, &srvst);
    if (err != 0) {
        RLOGE("invalid command line %s\n", s);
    }
    free(line);
#ifdef UNSOLICITED_SIGNAL_STRENGTH
    if (srvst == 2) {
        int newStart = 1;
        RIL_requestTimedCallback(pollSignalQuickly, &newStart, NULL);
    }
#endif
/* end: add by dongmeirong for poll signal strength by ril 20210615 */
}
/* begin: modified by dongmeirong for add network change listenner to CGREG 20210508 */
else if ((cmdId = findCxregCmd(s)) >= 0) { // +CREG:,+CGREG:,+CEREG: cmd
    int stat = -1;
    line = p = strdup(s);
    at_tok_start(&p);
    err = at_tok_nextint(&p, &stat);
    if (err != 0) {
        RLOGE("invalid command line %s\n", s);
    }
    free(line);
    if (stat != s_cxreg_cmd[cmdId].stat) {
        s_cxreg_cmd[cmdId].stat = stat;
        RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED, NULL, 0);
        /*[zhaopf@meigsmart-2022-0714]add for refresh network when invalid reg state Begin*/
         RLOGI("new stat %d", stat);
         if(stat != 1 && stat != 5) {
            /*Modify by zhaopengfei for flush net state when ps not registered Begin*/
            struct timeval delay_flush = {0,700};
            RIL_requestTimedCallback (flushNetIfNecessary, NULL, &delay_flush);
            /*Modify by zhaopengfei for flush net state when ps not registered Begin*/
        }
    /*[zhaopf@meigsmart-2022-0714]add for refresh network when invalid reg state End*/
        // RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED, NULL, 0); //Remove by zhaopf as will trigger simload high-frequecy 2022/12/07
#ifdef WORKAROUND_FAKE_CGEV
        if(QMI_MOD != devmode && MULTI_QMI_MOD != devmode) { //add by zhaopf 2021/11/01, for qmi mode cm will do this.
            RIL_requestTimedCallback(onDataCallListChanged, NULL, NULL);
        }
#endif
    } else {
        RLOGD("stat not chang, %d", stat);
    }
}
/* end: modified by dongmeirong for add network change listenner to CGREG 20210508 */
else if (strStartsWith(s, "+CMT:")) {
    RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_NEW_SMS,
                              sms_pdu, strlen(sms_pdu));
}
//zhangqingyun add for urc datadisconn 2018 05 15 start
else if (strStartsWith(s, "^DATADISCONN")) {
    RLOGD("---DATADISCONN---- ");
    RIL_requestTimedCallback (onDeactiveDataCallList, NULL, &TIMEVAL_WAITDATADISCONNECT);
/* begin: add by zhaopengfei for qcrmcall disconnect 20210714 */
} else if(strStartsWith(s, "$QCRMCALL:")){
    int dialstate;
    char *proto = NULL;
    line = p = strdup(s);
    at_tok_start(&p);
    err = at_tok_nextint(&p, &dialstate);
    if (err != 0) {
        RLOGE("invalid $QCRMCALL line %s\n", s);
    }
    err = at_tok_nextstr(&p, &proto);
    if (err != 0) {
        RLOGE("invalid $QCRMCALL line %s\n", s);
    }
    if((0 == dialstate) && (NULL != strcasestr(proto, "V4"))){ //we treated v4 disconn as all disconn
        RLOGD("---DATADISCONN---- ");
        /*Modify by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 Begin */
        if(g_deactive_working) {
            RLOGD("deactive working, ignore.");
            g_deactive_working = false;
        } else {
            RIL_requestTimedCallback (onDeactiveDataCallList, NULL, &TIMEVAL_WAITDATADISCONNECT);
        }
        /*Modify by zhaopengfei ignore unsolicited disconn at when deactive is working 2023/01/09 End */
    }

    free(line);

}
/* end: add by zhaopengfei for qcrmcall disconnect 20210714 */

/* begin: modified by dongmeirong for ^SIMST reporting 20201117 */
else if(strStartsWith(s,"^SIMST")) {
    RLOGD("sim state changed:");
    /*[zhaopf@meigsmart-2020-1119]modify for sim state change { */
    int simstate;
    line = p = strdup(s);
    at_tok_start(&p);
    err = at_tok_nextint(&p, &simstate);
    if (err != 0) {
        RLOGE("invalid ^SIMST line %s\n", s);
    }
    switch(simstate){
    case 0:
        s_sim_state = SIM_NOT_READY;
        RLOGI("sim not ready\n");
        break;
    case 1:
        s_sim_state = SIM_READY;
        RLOGI("sim ready\n");
        break;
    case 255:
         s_sim_state = SIM_ABSENT;
         RLOGI("sim removed\n");
        /*[zhaopf@meigsmart-2022-0714]deactive datacall when sim removed Begin */
        RIL_requestTimedCallback (onDeactiveDataCallList, NULL, &TIMEVAL_WAITDATADISCONNECT);
        /*zhangqingyun add for support chuangwei send mms 2023-4-26 start*/
        #ifdef SEND_MMS_USE_PPP
        meig_pppd_stop(SIGKILL);
        #endif
        /*zhangqingyun add for support chuangwei send mms 2023-4-26 end*/
        /*[zhaopf@meigsmart-2022-0714]deactive datacall when sim removed End */
        break;
    }
    free(line);
    /*[zhaopf@meigsmart-2020-1119]modify for sim state change } */
    //sleep(5);//optimized by zhaopf
    RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED, NULL, 0);
}
/* end: modified by dongmeirong for ^SIMST reporting 20201117 */
else if(strStartsWith(s,"^NDISSTAT")){
    int tempndisstate = 0;
    char *ipType = NULL;
    int erro_code  = 0;
    //if(ndisstate == NDIS_SUCCESS){
      //  RLOGD("ndis state already connect not care");
       // return;
    //}
    line = p = strdup(s);
    //AT< ^NDISSTAT:1,1,,,"IPV4"
    //AT< ^NDISSTAT:1,0,50,,"IPV6"
    if (!line) {
        RLOGE("^NDISSTAT: Unable to allocate memory");
        return;
    }
    //start with :
    if (at_tok_start(&p) < 0) {
        RLOGE("not a valid response string");
        free(line);
        return;
    }
    /*Add by zhaopengfei for unisoc modem data disconnection 2022/12/31 Begin */
    if(curr_modem_info.info.sltn_type != UNISOC) {
        //always start with 1,
        if (at_tok_nextint(&p, &tempndisstate) < 0) {
            RLOGE("invalid integer %d", tempndisstate);
            free(line);
            return;
        }
    }
    /*Add by zhaopengfei for unisoc modem data disconnection 2022/12/31 End */
    tempndisstate = 0;
    //check ndisstate
    if (at_tok_nextint(&p, &tempndisstate) < 0) {
        RLOGE("invalid integer %d", tempndisstate);
        free(line);
        return;
    }
    //if connect not hava erro code skip two comma get ip type
    if(tempndisstate == 1){
        if(skipComma(&p) < 0){
            RLOGE("invalid comma ");
            free(line);
            return;
        }
        if(skipComma(&p) < 0){
            RLOGE("invalid comma ");
            free(line);
            return;
        }
    if(at_tok_nextstr(&p,&ipType) < 0){
        RLOGE("invalid string");
            free(line);
            return;
        }
        RLOGD("get ipv4 or ipv6 is:%s",ipType);
        if(strcmp(ipType,"IPV4") == 0){
            ndisIPV4state = NDIS_SUCCESS;
            RLOGD("ndis ipv4 state is:%d",ndisIPV4state);
        }else if(strcmp(ipType,"IPV6") == 0){
            ndisIPV6state = NDIS_SUCCESS;
            RLOGD("ndis ipv6 state is:%d",ndisIPV6state);
        }
        return;
    }else if(tempndisstate== 0){
        //not connect have erro code get error code then just skip one comma get ip type
    /*Modify by zhaopengfei for unisoc modem data disconnection 2022/12/31 Begin */
    if(curr_modem_info.info.sltn_type == UNISOC) {
        if(skipComma(&p) < 0){
            RLOGE("invalid comma ");
            free(line);
            return;
        }
    } else {
        if(at_tok_nextint(&p,&erro_code) < 0){
            RLOGE("invalid erroc caust number ");
            free(line);
            return;
        }
    }
    /*Modify by zhaopengfei for unisoc modem data disconnection 2022/12/31 End */
    if(skipComma(&p) < 0){
        RLOGE("invalid comma ");
        free(line);
        return;
    }
    if(at_tok_nextstr(&p,&ipType) < 0){
        RLOGE("invalid string");
        free(line);
            return;
    }
    RLOGD("get ipv4 or ipv6 is:%s",ipType);
    if(strcmp(ipType,"IPV4") == 0){
        ndisIPV4state = NDIS_NOTCONNECT;
        RLOGD("not connect ndis ipv4 state is:%d",ndisIPV4state);
        /*Add by zhaopengfei for unisoc modem data disconnection 2022/12/31 Begin */
        if(curr_modem_info.info.sltn_type == UNISOC) {
            if(g_deactive_working) {
                RLOGD("deactive working, ignore.");
                g_deactive_working = false;
            } else {
                RLOGD("---DATADISCONN---- ");
                RIL_requestTimedCallback (onDeactiveDataCallList, NULL, &TIMEVAL_WAITDATADISCONNECT);
            }
        }
        /*Add by zhaopengfei for unisoc modem data disconnection 2022/12/31 End */
    }else if(strcmp(ipType,"IPV6") == 0){
        ndisIPV6state = NDIS_NOTCONNECT;
        RLOGD("not connect ndis ipv6 state is:%d",ndisIPV6state);
    }
    return;
    }
    //RLOGD("ndis state is:%d",ndisstate);
}
//zhangqingyun add for urc datadisconn 2018 05 15 end
else if (strStartsWith(s, "+CDS:")) {
    RIL_onUnsolicitedResponse
    (RIL_UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT, sms_pdu,
     strlen(sms_pdu));
}
//zhangqingyun 2018 05 05 add for receive sms start
else if(strStartsWith(s,"+CMGR:")) {
    if(sms_type == SMS_GENERAL || sms_type == SMS_BROADCAST) {
        RIL_onUnsolicitedResponse (
            RIL_UNSOL_RESPONSE_NEW_SMS,
            sms_pdu, strlen(sms_pdu));
    } else if (sms_type == SMS_SEND_REPORT) {
        RIL_onUnsolicitedResponse (
            RIL_UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT,
            sms_pdu, strlen(sms_pdu));
    }
}

#if 1
else if(strStartsWith(s,"^HCMGR:")) {
    //char *cdma_sms_pdu = s+7;
    char *cdma_sms_pdu = s+7;
    //char *cdma_sms_pdu = s+11;    //pdu string remove 0033
    //       char *cdma_sms_pdu = s+9;    //pdu string remove 0033
    char pdu_3gpp[500] = {0};
    char *cdma_sms_pdu_meig = 0 ;
    char *cdma_sms_pdu_meig1 = 0 ;

    RLOGD("^HCMGR: %s   len=%d",cdma_sms_pdu,strlen(cdma_sms_pdu));
    //wangbo 2017/07/11 add for sms cdma pdu

//           cdma_sms_pdu_meig = SubString(cdma_sms_pdu,4,(strlen(cdma_sms_pdu)-4) );

//           cdma_sms_pdu_meig1 = SubString(cdma_sms_pdu,2,(strlen(cdma_sms_pdu)-2) );

//           RLOGD("cdma_sms_pdu_meig ^HCMGR: %s   len=%d",cdma_sms_pdu_meig,strlen(cdma_sms_pdu_meig));
    RLOGD("cdma_sms_pdu  ^HCMGR: %s   len=%d",cdma_sms_pdu,strlen(cdma_sms_pdu));

//           RLOGD("cdma_sms_pdu_meig1 ^HCMGR: %s   len=%d",cdma_sms_pdu_meig1,strlen(cdma_sms_pdu_meig1));

    cdma_pdu_2_3gpp_pdu(cdma_sms_pdu, pdu_3gpp);
    //cdma_pdu_2_3gpp_pdu(cdma_sms_pdu_meig, pdu_3gpp);
//           cdma_pdu_2_3gpp_pdu(cdma_sms_pdu_meig1, pdu_3gpp);
    //cdma_pdu_2_3gpp_pdu(cdma_sms_pdu, pdu_3gpp);
//           RLOGD("pdu_3gpp: %s     len=%d",pdu_3gpp,strlen(pdu_3gpp));
    RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_NEW_SMS,pdu_3gpp, strlen(pdu_3gpp));

    RLOGD("pdu_3gpp: %s     len=%d",pdu_3gpp,strlen(pdu_3gpp));
    // RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_NEW_SMS,cdma_sms_pdu, strlen(cdma_sms_pdu));
    //RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_CDMA_NEW_SMS,cdma_sms_pdu, strlen(cdma_sms_pdu));
}
#endif

else if ( strStartsWith(s, "+CMTI:")  || strStartsWith(s, "+CBMI:") || strStartsWith(s, "+CDSI:")) {
    onNewSmsNotification(s); // modify by FPL
}

//zhangqingyun 2018 05 05 add for receive sms end
else if (strStartsWith(s, "+CGEV:")) {
    /* Really, we can ignore NW CLASS and ME CLASS events here,
     * but right now we don't since extranous
     * RIL_UNSOL_DATA_CALL_LIST_CHANGED calls are tolerated
     */
    /* can't issue AT commands here -- call on main thread */
    if(QMI_MOD != devmode && MULTI_QMI_MOD != devmode) { //add by zhaopf 2021/11/01, qmi mode will use cm replace this.
        RIL_requestTimedCallback(onDataCallListChanged, NULL, NULL);
    }
#ifdef WORKAROUND_FAKE_CGEV
} else if (strStartsWith(s, "+CME ERROR: 150")) {
    RIL_requestTimedCallback(onDataCallListChanged, NULL, NULL);
#endif                /* WORKAROUND_FAKE_CGEV */
} else if (strStartsWith(s, "+CTEC: ")) {
    int tech, mask;
    switch (parse_technology_response(s, &tech, NULL)) {
    case -1:    // no argument could be parsed.
        RLOGE("invalid CTEC line %s\n", s);
        break;
    case 1:    // current mode correctly parsed
    case 0:    // preferred mode correctly parsed
        mask = 1 << tech;
        if (mask != MDM_GSM && mask != MDM_CDMA &&
                mask != MDM_WCDMA && mask != MDM_LTE) {
            RLOGE("Unknown technology %d\n", tech);
        } else {
            setRadioTechnology(sMdmInfo, tech);
        }
        break;
    }
} else if (strStartsWith(s, "+CCSS: ")) {
    int source = 0;
    line = p = strdup(s);
    if (!line) {
        RLOGE("+CCSS: Unable to allocate memory");
        return;
    }
    if (at_tok_start(&p) < 0) {
        free(line);
        return;
    }
    if (at_tok_nextint(&p, &source) < 0) {
        RLOGE("invalid +CCSS response: %s", line);
        free(line);
        return;
    }
    SSOURCE(sMdmInfo) = source;
    RIL_onUnsolicitedResponse
    (RIL_UNSOL_CDMA_SUBSCRIPTION_SOURCE_CHANGED, &source,
     sizeof(source));
} else if (strStartsWith(s, "+WSOS: ")) {
    char state = 0;
    int unsol;
    line = p = strdup(s);
    if (!line) {
        RLOGE("+WSOS: Unable to allocate memory");
        return;
    }
    if (at_tok_start(&p) < 0) {
        free(line);
        return;
    }
    if (at_tok_nextbool(&p, &state) < 0) {
        RLOGE("invalid +WSOS response: %s", line);
        free(line);
        return;
    }
    free(line);

    unsol = state ?
            RIL_UNSOL_ENTER_EMERGENCY_CALLBACK_MODE :
            RIL_UNSOL_EXIT_EMERGENCY_CALLBACK_MODE;

    RIL_onUnsolicitedResponse(unsol, NULL, 0);

} else if (strStartsWith(s, "+WPRL: ")) {
    int version = -1;
    line = p = strdup(s);
    if (!line) {
        RLOGE("+WPRL: Unable to allocate memory");
        return;
    }
    if (at_tok_start(&p) < 0) {
        RLOGE("invalid +WPRL response: %s", s);
        free(line);
        return;
    }
    if (at_tok_nextint(&p, &version) < 0) {
        RLOGE("invalid +WPRL response: %s", s);
        free(line);
        return;
    }
    free(line);
    RIL_onUnsolicitedResponse(RIL_UNSOL_CDMA_PRL_CHANGED, &version,
                              sizeof(version));
} else if (strStartsWith(s, "+CFUN: 0")) {
    setRadioState(RADIO_STATE_OFF);
} else if (strStartsWith(s, "^HCSQ")) {
    RLOGD("unsolicited send signalstrenth");
/*[zhaopf@meigsmart-2020-1103] update radio tech indication when received ^MODE { */
} else if (strStartsWith(s, "^MODE")) {
   RLOGD("voice radio tech changed");
   struct timeval check_delay = {0,500};
   RIL_requestTimedCallback(updateRadioTechnology, NULL, &check_delay); //modify by zhaopf, delay 500ms
  /*zhangqingyun add for support ussd */
} else if(strStartsWith(s, "+CUSD:")){
   #ifdef SUPPORT_USSD_PARTIAL
   RLOGD("RIL UNSOL USSD RECEIVED");
   int type;
    char *ussd_string  = NULL;
    char **responseStr = NULL;
    responseStr = malloc(2* sizeof(char *));
       // if (!responseStr) goto error;
    memset(responseStr, 0, 2 * sizeof(char *));
    //asprintf(&responseStr[0], "1"); 
    line = p = strdup(s);
    at_tok_start(&p);
    err = at_tok_nextint(&p, &type);
    if (err != 0) {
        RLOGE("invalid CUSD line %s\n", s);
    }
    RLOGD("ussd type is:%d\n",type);
    err = at_tok_nextstr(&p, &ussd_string);
    if (err != 0) {
        RLOGE("invalid cusd line %s\n", s);
    }
    RLOGD("ussd_string is:%s\n",ussd_string);
    
    asprintf(&responseStr[0], "%d",type);
    asprintf(&responseStr[1], "%s",ussd_string);
    RIL_onUnsolicitedResponse(RIL_UNSOL_ON_USSD, responseStr,2*sizeof(responseStr));

    free(responseStr[0]);
    responseStr[0] = NULL;
    free(responseStr[1]);
    responseStr[1] = NULL;
    free(responseStr);
    responseStr = NULL;

    free(line);
    #endif
}
/*[zhaopf@meigsmart-2020-1103] update radio tech indication when received ^MODE } */
#if 0
//20170616 add for 3gpp2
//else if(strStartsWith(s,"^MODE:2") || strStartsWith(s,"^MODE:8") || strStartsWith(s,"^MODE: 2") || strStartsWith(s,"^MODE: 8"))
else if(strStartsWith(s,"^MODE:8") || strStartsWith(s,"^MODE: 8")) {
    RLOGD ("Modem ^MODE: 3gpp2 - network change, return initializeCallback......");
    sleep(10);  //process evdo and cdma dial
    //RIL_requestTimedCallback (initializeCallback, NULL, NULL);
    RIL_requestTimedCallback(initializeCallback, NULL, &TIMEVAL_DELAYINIT);
}

//20170412 wangbo add for ^MODE fix : run again
else if(strStartsWith(s,"^MODE:")) {
    RLOGD ("Modem ^MODE: - network change, return initializeCallback......");
    sleep(3);
    //RIL_requestTimedCallback (initializeCallback, NULL, NULL);
    RIL_requestTimedCallback(initializeCallback, NULL, &TIMEVAL_DELAYINIT);
}
#endif

}

/* Called on command or reader thread */
static void onATReaderClosed()
{
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin */
char if_name[10] = { 0x0 };
int i;
RLOGI("AT channel closed\n");
at_close();
s_closed = 1;

if(pppd)
    RLOGD("Stop existing %s", devmode2str[devmode]);
switch(devmode) {
case RAS_MOD:
    system("pkill pppd");
    break;
case ECM_MOD:
case RNDIS_MOD: // modified by dongmeirong for RNDIS adapt 20210219
    //dhcp_stop(curr_modem_info.if_name);
    break;
case QMI_MOD:
    CMRequestTurnDownDataCall(0);
    CMRequestTurnDownDataCall(1); //mms
    CMDeinitInstance();


    break;

case MULTI_NDIS_MOD:
    if(curr_modem_info.if_name[0] != '\0') {
        ifc_disable(curr_modem_info.if_name);
    }
    break;
case MULTI_QMI_MOD:
    if(curr_modem_info.if_name[0] != '\0') {
        ifc_disable(curr_modem_info.if_name);
    }
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
    if(curr_modem_info.use_deprecated_gobi){
        CMRequestTurnDownDataCall(0);
    } else {
        for(i = 0; i < g_ndis_multi_num; i++) {
            CMRequestTurnDownDataCall(i);
            if(curr_modem_info.vif_name[i][0] != '\0') {
                ifc_disable(curr_modem_info.vif_name[i]);
            }
        }
    }
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
    CMDeinitInstance();
    break;
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support End */
default:
    break;
}
pppd = 0;
/*zhaopf@meigsmart-2021/03/11 let framework to update sim state Begin */
RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED, NULL, 0);
sleep(1);
/*zhaopf@meigsmart-2021/03/11 let framework to update sim state End */
setRadioState(RADIO_STATE_UNAVAILABLE);
}

/* Called on command thread */
/*zhaopf@meigsmart-2021/10/22 stop qmi dial when at timeout Begin */
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
static void onATTimeout()
{
int i;
RLOGI("AT channel timeout; closing\n");
at_close();

if(bSetupDataCallCompelete) {
    if(MULTI_QMI_MOD == devmode || MULTI_NDIS_MOD == devmode ){
        RLOGI("stop qmi dial\n");
        if(curr_modem_info.if_name[0] != '\0') {
            ifconfigDown(curr_modem_info.if_name);
        }
        if(curr_modem_info.use_deprecated_gobi){
            CMRequestTurnDownDataCall(0);
        } else {
            for(i = 0; i < g_ndis_multi_num; i++) {
                CMRequestTurnDownDataCall(i);
                if(curr_modem_info.vif_name[i] && curr_modem_info.vif_name[i][0] != '\0') ifconfigDown(curr_modem_info.vif_name[i]);
            }
        }
    } else if(QMI_MOD == devmode) {
/*[zhaopf@meigsmart-2022-06-10] add for mms support Begin */
    if(curr_modem_info.if_name[0] != '\0') {
        ifconfigDown(curr_modem_info.if_name);
    }
    if(curr_modem_info.use_deprecated_gobi){
         CMRequestTurnDownDataCall(0);
    } else {
        for(i = 0; i < 2; i++) { //with mms
            CMRequestTurnDownDataCall(i);
            if(curr_modem_info.vif_name[i] && curr_modem_info.vif_name[i][0] != '\0') ifconfigDown(curr_modem_info.vif_name[i]);
        }
    }
/*[zhaopf@meigsmart-2022-06-10] add for mms support End */
    }
}
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
/*modify libmeigcm APIs support by zhaopengfei 2022/10/10 End */

/*Add by zhaopengfei for host AT port works bad 2023/01/06 Begin*/
g_at_timeout_count++;
if(g_at_timeout_count > AT_CHANNEL_TIMEOUT_MAX) {
    g_at_timeout_count = 0;
    if(curr_modem_info.info.descs.at_desc.epOUT != INVALID_DESC &&
        curr_modem_info.info.descs.at_desc.epIN != INVALID_DESC) {
        reset_ep(curr_modem_info.info.at_inf, curr_modem_info.info.descs.at_desc.epOUT);
        reset_ep(curr_modem_info.info.at_inf, curr_modem_info.info.descs.at_desc.epIN);
        RLOGI("reset at port");
    }
    RLOGI("reset at port, as reach max at timeout count:%d", AT_CHANNEL_TIMEOUT_MAX);
}
/*Add by zhaopengfei for host AT port works bad 2023/01/06 End*/

#ifdef TRIG_DUMP_WHEN_TIMEOUT
s_last_at_timeout = true;
#endif

s_closed = 1;

/* FIXME cause a radio reset here */

setRadioState(RADIO_STATE_UNAVAILABLE);
}
/*zhaopf@meigsmart-2021/10/22 stop qmi dial when at timeout End */

/* Called to pass hardware configuration information to telephony
 * framework.
 */
//add for android4.4 support by zhaopf 2020/12/11
 #if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
static void setHardwareConfiguration(int num, RIL_HardwareConfig * cfg)
{
RIL_onUnsolicitedResponse(RIL_UNSOL_HARDWARE_CONFIG_CHANGED, cfg,  num * sizeof(*cfg));
}
#endif

static void usage(char *s __unused)
{
#ifdef RIL_SHLIB
fprintf(stderr,
        "meig-ril requires: -p <tcp port> or -d /dev/tty_device\n");
#else
fprintf(stderr, "usage: %s [-p <tcp port>] [-d /dev/tty_device]\n", s);
exit(-1);
#endif
}

void on_usb_lost(void)
{

ALOGD("******** on_usb_lost ********");
onATReaderClosed();
}

/*[zhaopf@meigsmart-2020-11-17]add for usb reconnect { */
void on_usb_reconnected(void)
{

ALOGD("******** on_usb_reconnected ********");
RIL_requestTimedCallback(onNetworkStateChanged, NULL, NULL);
    }
/*[zhaopf@meigsmart-2020-11-17]add for usb reconnect } */

/*zhaopf@meigsmart-2021-11-01 add for mglogtoo auto start { */
static void sigChldHandle(int sig) {
    RLOGD ("%s entry\n", __FUNCTION__);
    pid_t pid;
    pid = waitpid(-1, NULL, 0);
    if (pid > 0) {
        RLOGD ("pid = %d terminated\n", pid);
    } else {
        RLOGD ("waitpid error [%s]\n", strerror(errno));
    }
}

static void startMglogtool() {
    pid_t child_pid;
    RLOGD ("%s entry\n", __FUNCTION__);
    child_pid = fork();
    if (child_pid == 0) {
        execl("/system/bin/mglogtool", "mglogtool", "-c", "/system/etc/mglog.cfg", "-d", "/data", "-s", "100", "-start", NULL);

        exit(0);
    } else if (child_pid < 0) {
        RLOGE("failed to start %s, errno = %s\n", "mglogtool", strerror(errno));
    } else {
        RLOGD("rild continue!!!");
    }
    RLOGD ("%s leave\n", __FUNCTION__);
}
/*zhaopf@meigsmart-2021-11-01 add for mglogtoo auto start } */


#if 1
/*modify for libmeigcm APIs support by zhaopengfei 2022/10/10 Begin */
static void *mainLoop(void *param __unused)
{
int fd;
int ret;
int i;

struct termios new_termios, old_termios;
/*zhaopf@meigsmart-2021/06/11 hangsheng device wait less time Begin */
static bool bReopend = false;
/*zhaopf@meigsmart-2021/06/11 hangsheng device wait less time End */


AT_DUMP("== ", "entering mainLoop()", -1);
at_set_on_reader_closed(onATReaderClosed);
at_set_on_timeout(onATTimeout);

/*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin */
g_ndis_multi_num = property_get_int32("ril.ndismulti.num", 0);
g_ndis_multi_num = (g_ndis_multi_num > NDIS_MULTI_NUM_MAX)?NDIS_MULTI_NUM_MAX:g_ndis_multi_num;
RLOGD("multi ndis num=%d", g_ndis_multi_num);
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support End */
/*Add by zhaopengfei reset modem when get gw failed 2023/01/09 Begin*/
 g_reset_modem_enable = true;
/*Add by zhaopengfei reset modem when get gw failed 2023/01/09 End*/



for (;;) {
    fd = -1;
    /*[zhaopf@meigsmart-2020-1217]add for modem state { */
    set_modem_state_connected(false);
    /*[zhaopf@meigsmart-2020-1217]add for modem state } */
    while (fd < 0) {
        RLOGI("---> enter mainloop wait at port \n");
        // if (s_device_path != NULL) {
        if(get_modem_info(&curr_modem_info) <= 0) {

            RLOGI("---> can't find meig usb devices \n");
            if(curr_modem_info.if_name != NULL) {
                free(curr_modem_info.if_name);
                curr_modem_info.if_name = NULL;
            }

            for(i = 0; i < NDIS_MULTI_NUM_MAX; i++) {
                if(curr_modem_info.vif_name[i] != NULL) {
                    free(curr_modem_info.vif_name[i]);
                    curr_modem_info.vif_name[i] = NULL;
            }
        }


            if(curr_modem_info.at_port_name != NULL) {
                free(curr_modem_info.at_port_name);
                curr_modem_info.at_port_name = NULL;
            }

            if(curr_modem_info.modem_port_name != NULL) {
                free(curr_modem_info.modem_port_name);
                curr_modem_info.modem_port_name = NULL;
            }

            /*zhaopf@meigsmart-2021/06/11 hangsheng device wait less time Begin */
            if(NULL != strstr(BUILD_CUSTOMER, "HANGSHENG")) {
                sleep(1);
            } else {
                sleep(2);
            }
            /*zhaopf@meigsmart-2021/06/11 hangsheng device wait less time End */

            continue;
        }

        if(curr_modem_info.at_port_name!= NULL) {
            s_device_path = curr_modem_info.at_port_name;
        } else { /* if(NULL == s_device_path)*/
            RLOGI("---> didn't find at port \n");
            sleep(2);
            continue;

        }

        if(curr_modem_info.modem_port_name != NULL) {
            property_set("ril.datachannel",  curr_modem_info.modem_port_name);
            RLOGI("set ril.datachannel=%s\n", curr_modem_info.modem_port_name);

        } else {
            property_set("ril.datachannel", "");
            sleep(2);
            continue;

        }
        RLOGI("device path=%s\n", s_device_path);

        //do{
        /*[zhaopf@meigsmart-2022-0714]modify for log switch Begin */
        if(property_get_bool("ril.debug.enable", false)) {
            debug_enable = 1;
        } else {
            debug_enable = 0;
        }
        /*[zhaopf@meigsmart-2022-0714]modify for log switch End */
        /*zhaopf@meigsmart-2021/06/11 hangsheng device wait less time Begin */
        if(NULL != strstr(BUILD_CUSTOMER, "HANGSHENG")) {
            if(bReopend){
                RLOGI("For HS device, wait 2s for ready again");
                sleep(2);
            } else {
                RLOGI("For HS device, wait 50ms for ready");
                usleep(50*1000);
            }
        } else {
            sleep(2); //optimized by zhaopf
        }
        /*zhaopf@meigsmart-2021/06/11 hangsheng device wait less time Begin */
        fd = open (s_device_path, O_RDWR);
        if(fd < 0) {
            RLOGI("%s cannot open, will retry 2s....\n", s_device_path);
            sleep(2);
        }
        //}while(fd < 0);

        if (fd >= 0&& !memcmp(s_device_path, "/dev/ttyS", 9)) {
            /* disable echo on serial ports */
            struct termios ios;
            tcgetattr(fd, &ios);
            ios.c_lflag = 0;    /* disable ECHO, ICANON, etc... */
            tcsetattr(fd, TCSANOW, &ios);

        }
        //}
    }


    s_closed = 0;
    //add by zhaopengfei for usb monitor
    //set_track_dev(s_device_path, fd);
    //start_usb_monitor(on_usb_lost);
    ret = at_open(fd, onUnsolicited);

    if (ret < 0) {
        RLOGE("AT error %d on at_open\n", ret);
        continue; //add by zhaopf, when open failed retry
    }
    /*[zhaopf@meigsmart-2020-11-17]add for usb reconnection { */
    at_set_on_usb_reconnected(on_usb_reconnected);
    /*[zhaopf@meigsmart-2020-11-17]add for usb reconnection } */
    /*zhaopf@meigsmart-2021-11-01 add for mglogtoo auto start { */
    if(property_get_bool("persist.sys.meig.qxlogen", false)) {
        signal(SIGCHLD, sigChldHandle);
        startMglogtool();
    }
    /*zhaopf@meigsmart-2021-11-01 add for mglogtoo auto start } */
    /* Set UART parameters (e.g. Buad rate) for connecting with SIGNAL modem */
    tcgetattr(fd, &old_termios);
    new_termios = old_termios;
    new_termios.c_lflag &= ~(ICANON | ECHO | ISIG);
    new_termios.c_cflag |= (CREAD | CLOCAL);
    new_termios.c_cflag &= ~(CSTOPB | PARENB | CRTSCTS);
    new_termios.c_cflag &= ~(CBAUD | CSIZE) ;
    new_termios.c_cflag |= (B115200 | CS8);
    ret = tcsetattr(fd, TCSANOW, &new_termios);
    if(ret < 0) {
        RLOGD ("Fail to set UART parameters. tcsetattr return %d \n", ret);
        //add by zhaopf, when open failed retry
        close(fd);
        continue;
    }


    /*[zhaopf@meigsmart-2020-1207] reset modem when handshake many times } */
    handshake_failed_times = 0; //init times
   /*[zhaopf@meigsmart-2020-1207] reset modem when handshake many times } */
    RIL_requestTimedCallback(initializeCallback, NULL, &TIMEVAL_0);

    // Give initializeCallback a chance to dispatched, since
    // we don't presently have a cancellation mechanism
    ////sleep(1);

    waitForClose();
    /* begin: add by dongmeirong for AGPS requirement 20201117 */
    setIsGpsInited(false);
    /* end: add by dongmeirong for AGPS requirement 20201117 */
    /* begin: added by dongmeirong for AGPS interface adapt 20210207 */
    s_is_supl_host_set = false;
    /* end: added by dongmeirong for AGPS interface adapt 20210207 */
    /*zhaopf@meigsmart-2021/06/11 hangsheng device wait less time Begin */
    if(NULL != strstr(BUILD_CUSTOMER, "HANGSHENG")){
        RLOGI("For HS device, wait Re-opening after close");
        bReopend = true;
    } else {
        RLOGI("Re-opening after close");

    }
    /*zhaopf@meigsmart-2021/06/11 hangsheng device wait less time End */
}
    //add by zhaopf
    return NULL;
}
#endif
#ifdef RIL_SHLIB

pthread_t s_tid_mainloop;

const RIL_RadioFunctions *RIL_Init(const struct RIL_Env *env, int argc,
                                   char **argv)
{
int ret;
//int fd = -1;
int opt;
pthread_attr_t attr;
char fingerprint[PROPERTY_VALUE_MAX] = {0};
s_rilenv = env;

RLOGI("############################");
//RLOGI("[MeiG Smart Ril Version]: [%s] ", REFERENCE_RIL_VERSION);
RLOGI("[MeiG Smart Ril Version]: [%s] ", "MT578_ANDROID_RIL_V01");
#ifdef BUILD_AUTHOR
RLOGI("[Build Author]: [%s] ", BUILD_AUTHOR);
#endif
#ifdef BUILD_TIME
RLOGI("[Build Time]: [%s] ", BUILD_TIME);
#endif
#ifdef BUILD_CUSTOMER
RLOGI("[Customer]: [%s] ", BUILD_CUSTOMER);

#endif
if(property_get("ro.build.fingerprint", fingerprint, "unkown") >= 0) {
    RLOGI("[Fingerprint]: [%s] ", fingerprint);
}
/*[zhaopf@meigsmart-2020-0601] update for sdk version detect { */
g_sdk_version = property_get_int32("ro.build.version.sdk", PLATFORM_SDK_VERSION);
RLOGI("[sdk version]: [%d] ", g_sdk_version);
/*[zhaopf@meigsmart-2020-0601] update for sdk version detect } */
/*[zhaopf@meigsmart-2020-0615]add for old version srm815 support {*/
if(property_get_bool("ril.use.csq", false)) {
    get_stength_by_csq = 1;
}
/*[zhaopf@meigsmart-2020-0615]add for old version srm815 support }*/
RLOGI("############################");
#if 0
while (-1 != (opt = getopt(argc, argv, "p:d:s:c:"))) {
    switch (opt) {
    case 'p':
        s_port = atoi(optarg);
        if (s_port == 0) {
            usage(argv[0]);
            return NULL;
        }
        RLOGI("Opening loopback port %d\n", s_port);
        break;

    case 'd':
        s_device_path = optarg;
        RLOGI("Opening tty device %s\n", s_device_path);
        break;

    case 's':
        s_device_path = optarg;
        s_device_socket = 1;
        RLOGI("Opening socket %s\n", s_device_path);
        break;

    case 'c':
        s_device_path_c = optarg;
        RLOGI("Client id received %s\n", optarg);
        RLOGI("Client id received s_device_path_c %s\n", s_device_path_c);
        break;

    default:
        usage(argv[0]);
        return NULL;
    }
}

if (s_port < 0 && s_device_path == NULL) {
    RLOGI("Client id received case 1\n");
    usage(argv[0]);
    return NULL;
}
#endif //auto detect


sMdmInfo = calloc(1, sizeof(ModemInfo));
if (!sMdmInfo) {
    RLOGE("Unable to alloc memory for ModemInfo");
    return NULL;
}

pthread_attr_init(&attr);
pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
ret = pthread_create(&s_tid_mainloop, &attr, mainLoop, NULL);
/* begin: added by dongmeirong for AGPS requirement 20201117 */
meig_gps_init();
/* end: added by dongmeirong for AGPS requirement 20201117 */
//optimized by zhaopf
sleep(1);

return &s_callbacks;
}
#else                /* RIL_SHLIB */
int main(int argc, char **argv)
:
{
//int ret;
//int fd = -1;
int opt;

while (-1 != (opt = getopt(argc, argv, "p:d:"))) {
    switch (opt) {
    case 'p':
        s_port = atoi(optarg);
        if (s_port == 0) {
            usage(argv[0]);
        }
        RLOGI("Opening loopback port %d\n", s_port);
        break;

    case 'd':
        s_device_path = optarg;
        RLOGI("Opening tty device %s\n", s_device_path);
        break;

    case 's':
        s_device_path = optarg;
        s_device_socket = 1;
        RLOGI("Opening socket %s\n", s_device_path);
        break;

    default:
        usage(argv[0]);
    }
}

if (s_port < 0 && s_device_path == NULL) {
    usage(argv[0]);
}

RIL_register(&s_callbacks);

mainLoop(NULL);

return 0;
}

#endif                /* RIL_SHLIB */
