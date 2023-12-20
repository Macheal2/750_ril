


#ifndef __GETDEVINFO_H__
#define __GETDEVINFO_H__
/*[zhaopf@meigsmart-2020-1211]add for android4.4 support { */
#include <sys/cdefs.h>
#include <sys/types.h>

#include "ril_common.h"
/*[zhaopf@meigsmart-2020-1211]add for android4.4 support } */
#define KVERSION(j,n,p)    ((j)*1000000 + (n)*1000 + (p))

/* begin: added by dongmeirong for AT Ver adaption 20201217 */
/* At version used by modem*/
typedef enum {
    AT_VERSION_1 = 1,
    AT_VERSION_2,
    AT_VERSION_MAX
} AT_VERSION;

/* Define product type. Because maybe different products send their AT commands on different timing sequence.
   For example, SLM750's gps init AT command needs to be sent a few seconds after modem startup.
   This is not used frequently, add other products here if you need it.*/
typedef enum {
    PRODUCT_TYPE_NOT_DEFINED = 0,
    PRODUCT_TYPE_SLM750,
    PRODUCT_TYPE_SLM770A,
    PRODUCT_TYPE_MAX
} PRODUCT_TYPE;
/* end: added by dongmeirong for AT Ver adaption 20201217 */

/*add by zhaopengfei for uac support 2022/10/10 Begin */
typedef enum {
    UAC_NOT_SUPPORT = 0,
    UAC_SUPPORT,
} UAC_STATE;
/*add by zhaopengfei for uac support 2022/10/10 End */

typedef enum {
    QCM = 0,
    HISI = 1,
    ASR = 2,   //zhangqingyun add for support asr platform 20220428
    UNISOC = 3    //yufeilong add for support UNISOC platform 20220527
} SOLUTOIN_TYPE;

typedef enum {
    RAS_MOD = 0,
    NCM_MOD,
    ECM_MOD,
    QMI_MOD,
    NDIS_MOD,
    RNDIS_MOD, // modified by dongmeirong for RNDIS adapt 20210219
    MULTI_NDIS_MOD, //add by zhaopf 2021/03/11
    MULTI_QMI_MOD, //add by zhaopf 2021/08/09
    MAX_MOD
} NET_MOD;

/*[zhaopf@meigsmart-2021-0108]add for module type {*/
typedef enum{
   SLM630 = 0,
   SLM730,
   SLM750,
   SLM790,
   SLM868,
   SRM815,
   SRM825,
   SLM770,//zhangqingyun add for support asr platfrom 20220428
   SRM811,//yufeilong add for support SRM811 20220527
   MAX_MODULE_TYPE = SRM811
}MODULE_TYPE;
/* zhangqingyun add for support modem upgrade 2023-4-28 start*/
#define MEIG_VERSION_FIELD_MAX_LENGTH 30

typedef struct {
    char project_name[MEIG_VERSION_FIELD_MAX_LENGTH];
    char hw_version[MEIG_VERSION_FIELD_MAX_LENGTH];
    char baseline[MEIG_VERSION_FIELD_MAX_LENGTH];
    char build_time[MEIG_VERSION_FIELD_MAX_LENGTH];
    char flash_type[MEIG_VERSION_FIELD_MAX_LENGTH];
    char customer_info[MEIG_VERSION_FIELD_MAX_LENGTH];
    char version_number[MEIG_VERSION_FIELD_MAX_LENGTH];
}VERSION_INFO;

/*zhangqingyun add for support modem upgrade 2023-4-28 end*/
#if (PLATFORM_SDK_VERSION > ANDROID_4_4_W_SDK_VERSION)
#define SLM630_MODULE    (1 << SLM630)
#define SLM730_MODULE    (1 << SLM730)
#define SLM750_MODULE    (1 << SLM750)
#define SLM790_MODULE    (1 << SLM790)
#define SLM868_MODULE    (1 << SLM868)
#define SRM815_MODULE    (1 << SRM815)
#define SRM825_MODULE    (1 << SRM825)
#define SLM770_MODULE    (1 << SLM770) //zhangqingyun add for support asr platfrom 20220428
#define SRM811_MODULE    (1 << SRM811) //yufeilong add for support SRM811 20220527
#else
#define SLM630_MODULE    (0x1)
#define SLM730_MODULE    (0x2)
#define SLM750_MODULE    (0x4)
#define SLM790_MODULE    (0x8)
#define SLM868_MODULE    (0x10)
#define SRM815_MODULE    (0x20)
#define SRM825_MODULE    (0x40)
#define SLM770_MODULE    (0x80) //zhangqingyun add for support asr platfrom 20220428 //fixed err by zhaopf
#define SRM811_MODULE    (0x100) //yufeilong add for support SRM811 20220527
#endif
/*[zhaopf@meigsmart-2021-0108]add for module type }*/



/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection {*/
#define USB_DESC_MAX_LEN     (4)
/*add by zhaopengfei for usb ep desc support 2022/10/10 Begin */
#define INVALID_DESC         (0xff)

struct meig_port_desc{
    char cls[USB_DESC_MAX_LEN];
    char subcls[USB_DESC_MAX_LEN];
    char prot[USB_DESC_MAX_LEN];
    unsigned char epINT;
    unsigned char epIN;
    unsigned char epOUT;
};
/*add by zhaopengfei for usb ep desc support 2022/10/10 End */
struct meig_port_desc_list{
        struct meig_port_desc at_desc;
        struct meig_port_desc modem_desc;
        struct meig_port_desc ecm_desc;
        struct meig_port_desc ndis_desc;
};
/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection }*/
/*add by zhaopengfei for uac support 2022/10/10 Begin */
struct meig_product_info {
    /*[zhaopf@meigsmart-2021-0108]add for module type {*/
    int module_type;
    /*[zhaopf@meigsmart-2021-0108]add for module type }*/
    char vid[5];
    char pid[5];
    unsigned short at_inf;
    unsigned short ppp_inf;
    unsigned short net_inf;
    SOLUTOIN_TYPE sltn_type;
/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection {*/
    struct meig_port_desc_list descs;
/*[zhaopf@meigsmart-2020-0622]modify for 5G device detect {*/
    int isFiveG;
/*[zhaopf@meigsmart-2020-0622]modify for 5G device detect }*/
/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection }*/
/* begin: added by dongmeirong for AT Ver adaption 20201217 */
    AT_VERSION (* get_at_version)(); // get at version used by modem
    AT_VERSION at_version;
    UAC_STATE uacSupport;
/* end: added by dongmeirong for AT Ver adaption 20201217 */
};
/*add by zhaopengfei for uac support 2022/10/10 End */
/*add by zhaopengfei for virtual interface support 2022/10/10 Begin */
typedef struct {
    struct meig_product_info info;
    char* if_name;
    char* vif_name[NDIS_MULTI_NUM_MAX];
    char* at_port_name;
    char* modem_port_name;
    int busnum;
    int devnum;
    NET_MOD net_mod;
    bool use_deprecated_gobi; // Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14

} MODEM_INFO;
/*add by zhaopengfei for virtual interface support 2022/10/10 End */

extern const char* devmode2str[];
/*[zhaopf@meigsmart-2020-0615]add for default interface name {*/
extern const char* devmode2definf[];
extern const char* devmode2definfdeprectd[]; // Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14
/*[zhaopf@meigsmart-2020-0615]add for default interface name }*/

int get_modem_info(MODEM_INFO * netinfo);
/*[zhaopf@meigsmart-2020-1211]add for android4.4 support { */
#if (PLATFORM_SDK_VERSION <= ANDROID_4_4_W_SDK_VERSION)
#include <stdbool.h>
int32_t property_get_int32(const char *key, int32_t default_value);
bool property_get_bool(const char *key, bool  defb) ;
#endif
/*[zhaopf@meigsmart-2020-1211]add for android4.4 support } */
#endif


