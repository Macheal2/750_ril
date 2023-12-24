#ifndef __COMMON_H__
#define __COMMON_H__
#define CONFIG_GOBINET
//#define CONFIG_QMIWWAN
#define CONFIG_SIM
#define CONFIG_APN
#define CONFIG_VERSION
#define CONFIG_DEFAULT_PDP 1
//#define CONFIG_IMSI_ICCID
#define LOG_TAG "RIL-CM"
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stddef.h>
#include "meig_cm.h"
#include "mpqmi.h"
#include "mpqctl.h"
#include "mpqmux.h"
#include "util.h"
#include "meig-log.h"
#define DEVICE_CLASS_UNKNOWN           0
#define DEVICE_CLASS_CDMA              1
#define DEVICE_CLASS_GSM               2
#define DEVICE_CLASS_NR5G              3



#define WWAN_DATA_CLASS_NONE            0x00000000
#define WWAN_DATA_CLASS_GPRS            0x00000001
#define WWAN_DATA_CLASS_EDGE            0x00000002 /* EGPRS */
#define WWAN_DATA_CLASS_UMTS            0x00000004
#define WWAN_DATA_CLASS_HSDPA           0x00000008
#define WWAN_DATA_CLASS_HSUPA           0x00000010
#define WWAN_DATA_CLASS_LTE             0x00000020
#define WWAN_DATA_CLASS_1XRTT           0x00010000
#define WWAN_DATA_CLASS_1XEVDO          0x00020000
#define WWAN_DATA_CLASS_1XEVDO_REVA     0x00040000
#define WWAN_DATA_CLASS_1XEVDV          0x00080000
#define WWAN_DATA_CLASS_3XRTT           0x00100000
#define WWAN_DATA_CLASS_1XEVDO_REVB     0x00200000 /* for future use */
#define WWAN_DATA_CLASS_UMB             0x00400000
#define WWAN_DATA_CLASS_NR5G            0x00800000
#define WWAN_DATA_CLASS_CUSTOM          0x80000000


#define ARRAY_SIZE(x) (sizeof(x)/x[0])
#define MAX_INTERFACE_NAME    (56)

struct wwan_data_class_str {
    ULONG class;
    CHAR *str;
};

#pragma pack(push, 1)

typedef struct _QCQMIMSG {
    QCQMI_HDR QMIHdr;
    union {
        QMICTL_MSG CTLMsg;
        QMUX_MSG MUXMsg;
    };
} __attribute__ ((packed)) QCQMIMSG, *PQCQMIMSG;

typedef struct __PROFILE {
    /* Begin: modify by zhaopengfei for the scene that apn released by users 2022/07/06 */
    char *apn;
    char *user;
    char *password;
    char *pincode;
    /* End: modify by zhaopengfei for the scene that apn released by users 2022/07/06 */
    int auth;
    int pdp;
    int IsDualIPSupported;
    int curIpFamily;
    int muxid;
    IPV4_ADDR ipv4;
    IPV6_ADDR ipv6;
    int enable_ipv6;
    int ipv4_flag;
    int ipv6_flag;
    int apntype;
    int pdpIndex;
    char *qmapnet_adapter;
} PROFILE_T;




typedef struct __WDS_QMI_CLIENT_ID {
    int v4clientId;
    int v6clientId;

} WDS_QMI_CLIENT_ID;

typedef struct __CM_DEV_CONTEXT {
    PROFILE_T profileList[PDP_SUPPORT_MAX];
    uint32_t wdsConnV4HandleList[PDP_SUPPORT_MAX];
    uint32_t wdsConnV6HandleList[PDP_SUPPORT_MAX];
    int qmiclientId[QMUX_TYPE_WDS_ADMIN + 1];
    WDS_QMI_CLIENT_ID wdsClient[PDP_SUPPORT_MAX];
    char *qmichannel;
    char *usbnet_adapter;
    char *driver_name;
    int qmap_mode;
    int qmap_version;
    int rawIP;
    int read_quit;
    void (*dataCallListChanged)(int pdpIndex, CM_IP_PROT ip_protocol, unsigned char state);
    void (*registerStateChanged)(CM_NAS_REG_STATE reg_state, CM_CS_ATTACH_STATE cs_state, CM_PS_ATTACH_STATE ps_state);
    void (*hardwareRemoved)();
    const struct qmi_device_ops *qmi_ops;

} CM_DEV_CONTEXT;

#pragma pack(pop)


//struct __PROFILE;
struct qmi_device_ops {
    int (*init)(CM_DEV_CONTEXT *devContext);
    int (*deinit)(void);
    int (*send)(PROFILE_T *profile, PQCQMIMSG pRequest);
    void* (*read)(void *pData);
};
int (*qmidev_send)(PROFILE_T *profile, PQCQMIMSG pRequest);


/*zhangqingyun add for support transmit apdu_buffer to larger 512 2023-11-3 */
#define WDM_DEFAULT_BUFSIZE    512
#define RIL_REQUEST_QUIT    0x1000
#define RIL_INDICATE_DEVICE_CONNECTED    0x1002
#define RIL_INDICATE_DEVICE_DISCONNECTED    0x1003
#define RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED    0x1004
#define RIL_UNSOL_DATA_CALL_LIST_CHANGED    0x1005

int pthread_cond_timeout_np(pthread_cond_t *cond, pthread_mutex_t * mutex, unsigned msecs);
int QmiThreadSendQMI(PROFILE_T *profile, PQCQMIMSG pRequest, PQCQMIMSG *ppResponse);
int QmiThreadSendQMITimeout(PROFILE_T *profile, PQCQMIMSG pRequest, PQCQMIMSG *ppResponse, unsigned msecs);
void QmiThreadRecvQMI(PQCQMIMSG pResponse);
void udhcpc_start(CM_DEV_CONTEXT *devContext, int pdpIndex);
void udhcpc_stop(CM_DEV_CONTEXT *devContext, int pdpIndex);
void dump_qmi(void *dataBuffer, int dataLen);
void qmidevice_send_event_to_main(int triger_event);
int requestGetIPAddress(int pdpIndex, int curIpFamily) ;
int requestSetEthMode(CM_DEV_CONTEXT *cmDevContext, int pdpIndex);
int requestSetProfile(PROFILE_T *profile);
int requestGetICCID(void);
int requestGetIMSI(void);
int requestDeactivatePDP(int pdpIndex, int curIpFamily);
int requestRegistrationState2(UCHAR *pPSAttachedState);
int requestRegistrationState(UCHAR *pPSAttachedState);
int requestSetupDataCall(PROFILE_T *profile, int curIpFamily);
//int requestDeactivateDefaultPDP(PROFILE_T *profile, int curIpFamily);
int requestCreateProfile(PROFILE_T *profile);
int requestGetProfile(PROFILE_T *profile);
int requestBaseBandVersion(const char **pp_reversion);
int requestSetOperatingMode(unsigned char OperatingMode);
int requestQueryDataCall(int pdpIndex, unsigned char  *pConnectionStatus, int curIpFamily);
int requestSimOpenChannel(int p2, unsigned char* buffer, unsigned short length,int* session_id,int* select_response_length);
int requestSimCloseChannel(int channel_id);
int requestTransmitApduLogicChannel(int channeld_id,unsigned char* apdu, unsigned short apdu_length,unsigned char* apdu_response,int* apdu_response_len);
int requestGetSimAtr(int slotid,unsigned char* sim_atr,int *atr_len);
int requestGetSimEid(int slotid, unsigned char*sim_eid);
int requestQueryBodySar(QMISAR_VALUE * sarValue);
int requestSetBodySar(QMISAR_VALUE sarValue);
//zhangqingyun add for support get ModemActivityInfo
int requestGetModemActivityInfo();

void cond_setclock_attr(pthread_cond_t *cond, clockid_t clock);
int GobiNetDeInit(void);
int GobiNetGetClientID(const char *qcqmi, UCHAR QMIType);
int varify_driver(CM_DEV_CONTEXT *devContext);
BOOL qmidevice_detect(char *qmichannel, char *usbnet_adapter, unsigned bufsize);
//int meig_bridge_mode_detect(PROFILE_T *profile);
int meig_enable_qmi_wwan_rawip_mode(CM_DEV_CONTEXT *cmDevContext);
int meig_driver_type_detect(CM_DEV_CONTEXT *cmDevContext);
void OnQMIDeviceDisconnected();
#ifdef MEIG_NEW_FEATURE
int requestSimAuthentication(uim_authentication_data_type *auth_info, SIM_IO_rsp *rsp);
#endif
#ifdef START_KEEP_ALIVE
int requestStartKeepAlive(wds_modem_assisted_ka_start_req_msg_type *ka_info, KeepaliveStatus *rsp);
#endif
const struct qmi_device_ops gobi_qmidev_ops;
const struct qmi_device_ops qmiwwan_qmidev_ops;

#define qmidev_is_gobinet(_qmichannel) (strncmp(_qmichannel, "/dev/qcqmi", strlen("/dev/qcqmi")) == 0)
#define qmidev_is_qmiwwan(_qmichannel) (strncmp(_qmichannel, "/dev/cdc-wdm", strlen("/dev/cdc-wdm")) == 0)
#define qmidev_is_pciemhi(_qmichannel) (strncmp(_qmichannel, "/dev/mhi_", strlen("/dev/mhi_")) == 0)

#define driver_is_qmi(_drv_name) (strncasecmp(_drv_name, "qmi_wwan", strlen("qmi_wwan")) == 0)
#define driver_is_mbim(_drv_name) (strncasecmp(_drv_name, "cdc_mbim", strlen("cdc_mbim")) == 0)

int debug_qmi;
int qmidevice_control_fd[2];
extern CM_DEV_CONTEXT gCMDevContext;

USHORT le16_to_cpu(USHORT v16);
UINT  le32_to_cpu (UINT v32);
UINT  meig_swap32(UINT v32);
USHORT cpu_to_le16(USHORT v16);
UINT cpu_to_le32(UINT v32);
void update_resolv_conf(int iptype, const char *ifname, const char *dns1, const char *dns2);

#define CM_MAX_BUFF 256
#define strset(k, v) {if (k) free(k); k = strdup(v);}
#define mfree(v) {if (v) {free(v); v = NULL;}

#ifdef FRWK_TRACE
#define dbg_time(fmt, args...) do { \
    FRWK_TRACE(TRACE_INF, "[%s][meig_cm] " fmt "\n", get_time(), ##args); \
} while(0);

#else
#ifdef CM_DEBUG
#define dbg_time(fmt, args...) do { \
    fprintf(stdout, "[%s-%04d: %s][meig_cm] " fmt "\n", __FILE__, __LINE__, get_time(), ##args); \
} while(0);
#else
#ifdef ANDROID

#define dbg_time(fmt, args...) do { \
    LOGD("[%s][meig_cm] " fmt "\n", get_time(), ##args); \
} while(0);

#else
#define dbg_time(fmt, args...) do { \
    printf("[%s][meig_cm] " fmt "\n", get_time(), ##args); \
} while(0);
#endif

#endif
#endif


#endif



