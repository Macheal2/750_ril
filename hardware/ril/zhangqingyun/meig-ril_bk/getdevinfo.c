#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
/*[zhaopf@meigsmart-2020-0622]modify for 5G device detect {*/
#include <cutils/properties.h>
#include <stdbool.h>
/*[zhaopf@meigsmart-2020-0622]modify for 5G device detect }*/

#define LOG_TAG "RIL-DEV"
#include "getdevinfo.h"
#include <utils/Log.h>
//add for android 4.4 support by zhaopf
#if (PLATFORM_SDK_VERSION <= ANDROID_4_4_W_SDK_VERSION)
#include <inttypes.h>
#endif
#include "meig-log.h" // add by zhaopengfei for logs 2022/10/10
/* begin: modified by dongmeirong for RNDIS adapt 20210219 */
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin*/
const char* devmode2str[] = {"ppp", "ncm", "ecm", "qmi", "ndis", "rndis", "multindis", "multiqmi"};

/*[zhaopf@meigsmart-2020-0615]add for default interface name {*/
/*[zhaopf@meigsmart-2020-0615]change for default interface name for gobi Begin */
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
const char* devmode2definf[] = {"ppp0", "usb0", "usb0", "wwan0", "usb0", "usb0", "bmwan0", "bmwan0"};
const char* devmode2definfdeprectd[] = {"ppp0", "usb0", "usb0", "usb0", "usb0", "usb0", "usb0", "usb0"};
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
/*[zhaopf@meigsmart-2020-0615]change for default interface name for gobi End */
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support End */
/*[zhaopf@meigsmart-2020-0615]add for default interface name }*/
/* end: modified by dongmeirong for RNDIS adapt 20210219 */
/*zhaopengfei@meigsmart.com-2022/08/23 add solutin name string Begin */
const char* solution2str[] = {"QCM", "HISI", "ASR", "UNISOC"};
/*zhaopengfei@meigsmart.com-2022/08/23 add solutin name string End */
#define ECM_LABLE "CDC Ethernet Control Model"
#define ECM_LABLE_1 "Mobile ECM Network Adapter" // modified by yufeilong for asr platform ecm adapt 20220929
#define NCM_LABLE "CDC Network Data"
#define NCM_LABLE_UNISOC "CDC Network Control Model" // modified by yufeilong for NCM adapt 20220527
#define RNDIS_LABLE "RNDIS Communications Control" // modified by dongmeirong for RNDIS adapt 20210219
#define RNDIS_LABLE_1 "Mobile RNDIS Network Adapter" //zhangqingyun add for asr platform rnis 20220428

#define MAX_PATH                    (1024)
#define MAX_VALUE_LEN           (128)
#define SRM815_VERSION         "2.1"
/*[zhaopf@meigsmart-2020-0716]skip adb port as use same prot with modem port { */
#define ADB_SUBCLS_STR                  "42"
/*[zhaopf@meigsmart-2020-0716]skip adb port as use same prot with modem port } */

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

extern int debug_enable;
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support Begin */
extern int g_ndis_multi_num;
/*zhaopf@meigsmart-2021/03/11 add for multi ndis support End */



/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection {*/
/*[zhaopf@meigsmart-2020-0622]modify for 5G device detect {*/
/*[zhaopf@meigsmart-2020-0622]add by zhaopf, for ruixun, if modem port in front of at port, it can't work.so we switch them { */
/* begin: modified by dongmeirong for AT Ver adaption 20201217 */
/* begin: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
extern AT_VERSION getAtVerByModuleSwVer();
extern bool findPPPDExecFile();
/*[zhaopf@meler module type {*/
/* modified by zhaopengfei for supporting of ep desc and uac ability Begin */
struct meig_product_info meig_product_list[] = {
    //vid |pid |at |modem |net | slution
/*[zhaopf@meigsmart-2020-0716]remove one device as can't work on some devices { */
#if 0
    //SLM720
    {"2dee", "4d07",  2, 3, 5, QCM,
        {
           //cls|subcls|prot
            {"ff", "ff", "ff"}, //at
            {"ff", "ff", "ff"}, //modem
            {"ff", "ff", "ff"}, //ecm
            {"ff", "ff", "ff"}, //ndis
        },
        0,
    },
#endif
/*[zhaopf@meigsmart-2020-0716]remove one device as can't work on some devices } */
/*[zhaopf@meigsmart-2022-06-10] add for xiongdi slm750 Begin */
{SLM750_MODULE,
    "05c6", "f615", 2, 1, 4, QCM,
    {
       //cls|subcls|prot|epINT|epIN|epOUT
        {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
        {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
        {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ecm
        {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ndis
    },
    0,
    // Use AT ver 1 by default, SLM750 R2.0 uses AT ver 2 which is updated during initialize.
    getAtVerByModuleSwVer,
    AT_VERSION_1,
    UAC_SUPPORT, //uac support,need prop to enable
 },

/*[zhaopf@meigsmart-2022-06-10] add for xiongdi slm750 End */
    //SLM630,SLM730,SLM750, SLM868
    {SLM630_MODULE|SLM730_MODULE|SLM750_MODULE|SLM868_MODULE,
        "05c6", "f601", 2, 1, 5, QCM,
        {
           //cls|subcls|prot
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ecm
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, 0x8a}, //ndis
        },
        0,
        // Use AT ver 1 by default, SLM750 R2.0 uses AT ver 2 which is updated during initialize.
        getAtVerByModuleSwVer,
        AT_VERSION_1,
        UAC_SUPPORT, //uac support,need prop to enable
     },
     //SLM790
    {SLM790_MODULE,
        "2dee", "4d20", 1, 4, 0, HISI,
        {
          //cls|subcls|prot
            {"ff",   "02", "12", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff",   "02", "01", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"02",   "06", "00", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ecm
            {"ff",   "03", "16", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ndis
        },
        0,
        // SLM790 use AT ver 1
        NULL,
        AT_VERSION_1,
        UAC_NOT_SUPPORT, //uac support,need prop to enable
     },
     //SRM815
    {SRM815_MODULE|SRM825_MODULE,
        "2dee", "4d22", 2, 1, 5,  QCM,
        {
           //cls|subcls|prot
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ecm
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ndis
        },
       1, //5G
       // SRM815 use AT ver 1
       NULL,
       AT_VERSION_2,
       UAC_SUPPORT, //uac support,need prop to enable
    },
    //SRM815 ECM
    {SRM815_MODULE|SRM825_MODULE,
        "2dee", "4d23", 2, 1, 5,  QCM,
        {
           //cls|subcls|prot
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ecm
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ndis
        },
     1, //5G
     // SRM815 use AT ver 2
     NULL,
     AT_VERSION_2,
     UAC_SUPPORT, //uac support,need prop to enable
     },
     /* begin: modified by dongmeirong for RNDIS adapt 20210219 */
     { SRM815_MODULE,
         "2dee", "4d38", 4, 3, 0, QCM,
         {
             //cls|subcls|prot
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ecm
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ndis
         },
       1, // 5G
       // SRM815 use AT ver 2
       NULL,
       AT_VERSION_2,
       UAC_SUPPORT, //uac support,need prop to enable
     },
     // SLM 750 RNDIS
     { SLM750_MODULE,
         "05c6", "f622", 3, 4, 0, QCM,
         {
             //cls|subcls|prot
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ecm
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ndis
         },
       0, // 5G
       getAtVerByModuleSwVer,
       AT_VERSION_1,
       UAC_SUPPORT, //uac support,need prop to enable
     },
     /*zhangqingyun add for supprt asr platform 20220428 start*/
     { SLM770_MODULE,
         "2dee", "4d57", 4,3, 0, ASR,
         {
             //cls|subcls|prot
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //reserverd
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //resercerd
         },
       0, // 4g
       getAtVerByModuleSwVer,
       AT_VERSION_1,
       UAC_SUPPORT,
     },
    /*zhangqingyun add fro support asy platform 20220428 end*/
     /* end: modified by dongmeirong for RNDIS adapt 20210219 */
    /*yufeilong add for support asr ecm dialing 20221024 start*/
     { SLM770_MODULE,
         "2dee", "4d58", 4,3, 0, ASR,
         {
             //cls|subcls|prot
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ecm
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //resercerd
         },
       0, // 4g
       getAtVerByModuleSwVer,
       AT_VERSION_1,
       UAC_SUPPORT,
     },
    /*yufeilong add for support asr ecm dialing 20221024 end*/
    /*yufeilong add for support SRM811 20220527 start*/
     { SRM811_MODULE,
         "2dee", "4d52", 4,3, 0, UNISOC,
         {
             //cls|subcls|prot|epINT|epIN|epOUT //Modify by zhaopengfei 2023/01/09
            {"ff", "ff", "ff", INVALID_DESC, 0x85, 0x04}, //at
            {"ff", "ff", "ff", INVALID_DESC, 0x84, 0x03}, //modem
            {"ff", "ff", "ff", 0x82, 0x81, 0x01}, //ncm
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //resercer
         },
       1, // 5g
       NULL,
       AT_VERSION_2,
       UAC_SUPPORT,
     },
    /*yufeilong add for support SRM811 20220527 end*/
    /*yufeilong add for support SRM8x1 20221024 start*/
     { SRM811_MODULE,
         "2dee", "4d50", 4,3, 0, UNISOC,
         {
             //cls|subcls|prot
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //ecm
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //resercer
         },
       1, // 5g
       NULL,
       AT_VERSION_2,
       UAC_SUPPORT,
     },
     { SRM811_MODULE,
         "2dee", "4d51", 4,3, 0, UNISOC,
         {
             //cls|subcls|prot
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //at
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //modem
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //rndis
            {"ff", "ff", "ff", INVALID_DESC, INVALID_DESC, INVALID_DESC}, //resercer
         },
       1, // 5g
       NULL,
       AT_VERSION_2,
       UAC_SUPPORT,
     },
    /*yufeilong add for support SRM8x1 20221024 end*/
};
/* modified by zhaopengfei for supporting of ep desc and uac ability End */
/* end: modified by dongmeirong for ruixun exchange modem port and at port 20210507 */
/*[zhaopf@meigsmart-2021-0108]add for module type }*/
/* end: modified by dongmeirong for AT Ver adaption 20201217 */
/*[zhaopf@meigsmart-2020-0622]add by zhaopf, for ruixun, if modem port in front of at port, it can't work.so we switch them }*/
/*[zhaopf@meigsmart-2020-0622]modify for 5G device detect }*/
/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection }*/

/*[zhaopf@meigsmart-2020-1211]add for android4.4 support {*/
#if (PLATFORM_SDK_VERSION <= ANDROID_4_4_W_SDK_VERSION)
static bool check_flag(const char *prop, const char *flag) {
    const char *cp = strcasestr(prop, flag);
    if (!cp) {
        return false;
    }
    // We only will document comma (,)
    static const char sep[] = ",:;|+ \t\f";
    if ((cp != prop) && !strchr(sep, cp[-1])) {
        return false;
    }
    cp += strlen(flag);
    return !*cp || !!strchr(sep, *cp);
}


#define BOOL_DEFAULT_FLAG_PERSIST    0x2
bool property_get_bool(const char *key, bool  defb) {
    char def[PROPERTY_VALUE_MAX];
    char property[PROPERTY_VALUE_MAX];
    def[0] = '\0';

    property_get(key, property, def);

    if (check_flag(property, "true")) {
        return true;
    }
    if (check_flag(property, "false")) {
        return false;
    }
    return defb;
}


static intmax_t property_get_imax(const char *key, intmax_t lower_bound, intmax_t upper_bound,
        intmax_t default_value) {
    if (!key) {
        return default_value;
    }

    intmax_t result = default_value;
    char buf[PROPERTY_VALUE_MAX] = {'\0',};
    char *end = NULL;

    int len = property_get(key, buf, "");
    if (len > 0) {
        int tmp = errno;
        errno = 0;

        // Infer base automatically
        result = strtoimax(buf, &end, /*base*/0);
        if ((result == INTMAX_MIN || result == INTMAX_MAX) && errno == ERANGE) {
            // Over or underflow
            result = default_value;
            RLOGV("%s(%s,%" PRIdMAX ") - overflow", __FUNCTION__, key, default_value);
        } else if (result < lower_bound || result > upper_bound) {
            // Out of range of requested bounds
            result = default_value;
            RLOGV("%s(%s,%" PRIdMAX ") - out of range", __FUNCTION__, key, default_value);
        } else if (end == buf) {
            // Numeric conversion failed
            result = default_value;
            RLOGV("%s(%s,%" PRIdMAX ") - numeric conversion failed",
                    __FUNCTION__, key, default_value);
        }

        errno = tmp;
    }

    return result;
}

int32_t property_get_int32(const char *key, int32_t default_value) {
    return (int32_t)property_get_imax(key, INT32_MIN, INT32_MAX, default_value);
}

#endif
/*[zhaopf@meigsmart-2020-1211]add for android4.4 support } */
int  find_vendor_index(const char* vid)
{
    size_t index;
    for (index = 0; index < ARRAY_SIZE(meig_product_list); index++) {
        if (0 == strncasecmp(vid,  meig_product_list[index].vid, 4)) {

            return index;
        }
    }
    return -1;
}


int find_product_index(const char* pid)
{
    size_t index;
    for (index = 0; index < ARRAY_SIZE(meig_product_list); index++) {
        if (0 == strncasecmp(pid,  meig_product_list[index].pid, 4)) {
            return index;
        }
    }
    return -1;
}

int find_product_of_vendor_index(const char* vid, const char* pid)
{
    size_t index;
    for (index = 0; index < ARRAY_SIZE(meig_product_list); index++) {
        if ((0 ==  strncasecmp(vid,  meig_product_list[index].vid, 4))  && (0 ==  strncasecmp(pid,  meig_product_list[index].pid, 4)) ) {
            return index;
        }
    }
    return -1;
}


static void dump_net_info(MODEM_INFO* netinfo)
{
    if(NULL == netinfo ) {
        return;
    }
    RLOGD("module:%d", netinfo->info.module_type);
    RLOGD("vid:%s", netinfo->info.vid);
    RLOGD("pid:%s", netinfo->info.pid);
    RLOGD("at port:%d", netinfo->info.at_inf);
    RLOGD("ppp port:%d", netinfo->info.ppp_inf);
    RLOGD("net port:%d", netinfo->info.net_inf);
    /*zhaopengfei@meigsmart.com-2022/08/23 add solutin name string Begin */
    RLOGD("solution:%s", solution2str[netinfo->info.sltn_type]);
    /*zhaopengfei@meigsmart.com-2022/08/23 add solutin name string End */
    RLOGD("net mode:%s", devmode2str[netinfo->net_mod]);
    /*[zhaopf@meigsmart-2020-0622]modify for 5G device detect {*/
    RLOGD("5G: %s", netinfo->info.isFiveG?"YES":"NO");
    /*[zhaopf@meigsmart-2020-0622]modify for 5G device detect }*/
    /* begin: modified by dongmeirong for AT Ver adaption 20201217 */
    if (netinfo->info.get_at_version == NULL) {
        RLOGD("at_version:AT_VERSION_%d", netinfo->info.at_version);
    } else {
        RLOGD("at_version:AT_VERSION_%d, this is default value, may be updated later during initialize",
            netinfo->info.at_version);
    }
    /* end: modified by dongmeirong for AT Ver adaption 20201217 */
    if(NULL != netinfo->if_name) {
        RLOGD("interface:%s", netinfo->if_name);
    }
    if(NULL != netinfo->at_port_name) {
        RLOGD("at port:%s", netinfo->at_port_name);
    }
    if(NULL != netinfo->modem_port_name) {
        RLOGD("modem port:%s", netinfo->modem_port_name);
    }
    if(-1 != netinfo->busnum && -1 != netinfo->devnum) {
        RLOGD("bus:%03d/%03d", netinfo->busnum, netinfo->devnum);
    }

}

//businfo
int read_node_val_int(const char* fileNode){
    int fd;
    char nodeVal[5] = "";
    fd = open(fileNode, O_RDONLY);
    if (fd > 0) {
        read(fd, nodeVal, 4);
        close(fd);
        RLOGD("%s read %s\n", fileNode, nodeVal);
        return atoi(nodeVal);

    }
    return -1;
}

//businfo
char* find_ttyUSBX_by_id(const char* subdir)
{
    DIR *tDir = NULL;
    struct dirent* tent = NULL;
    int found_device = 0;
    /*zhaopengfei@meigsmart.com-2022/08/23 moodify for devName released on some platform Begin */
    char* devName = NULL;

    if ((tDir = opendir(subdir)) == NULL)  {
        RLOGE("Cannot open directory:%s/", subdir);
        return NULL;
    }

    while ((tent= readdir(tDir)) != NULL) {
        if (strncmp(tent->d_name, "ttyUSB", strlen("ttyUSB")) == 0) {
            devName = strdup(tent->d_name);
            RLOGD("Find port = %s", devName);
            found_device = 1;
            break;
        }
    }
    closedir(tDir );
    return (1 == found_device)?devName:NULL;
    /*zhaopengfei@meigsmart.com-2022/08/23 moodify for devName released on some platform End */
}


int  get_netif_name_by_path(const char* dir, char** out_ifname)
{
    DIR *pDir = NULL;
    DIR *pSubDir = NULL;
    char subdir[MAX_PATH];
    struct dirent* ent = NULL;
    struct dirent* subent = NULL;
    int found_netinf = 0;

    if ((pDir = opendir(dir)) == NULL)  {
        RLOGE("Cannot open directory:%s/", dir);
        return -ENODEV;
    }

    while ((ent = readdir(pDir)) != NULL) {
        if (strncmp(ent->d_name, "net", strlen("net")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/net");
            if ((pSubDir = opendir(subdir)) == NULL)  {
                RLOGE("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if ((strncmp(subent->d_name, "wwan", strlen("wwan")) == 0)
                        || (strncmp(subent->d_name, "eth", strlen("eth")) == 0)
                        || (strncmp(subent->d_name, "usb", strlen("usb")) == 0)) {
                    found_netinf = 1;
                    RLOGD("found net interface, return it");
                    /*zhaopf@meigsmart-2022/10/10 change default interface name of gobi Begin */
                     (*out_ifname) = strdup(subent->d_name);
                    /*zhaopf@meigsmart-2022/10/10 change default interface name of gobi End */
                    break;
                }
            }
            closedir(pSubDir);
        }

    }
    closedir(pDir);
    if(!found_netinf) {
        (*out_ifname) = strdup("ppp0");
        RLOGE("didn't found net interface");
    }

    return found_netinf;

}


NET_MOD get_netif_mode_by_path(const char* dir, const char* usb_class_name)
{
    DIR *pDir = NULL;
    DIR *pSubDir = NULL;
    char subdir[MAX_PATH];
    char value_read[MAX_VALUE_LEN] = {0};
    struct dirent* ent = NULL;
    struct dirent* subent = NULL;
    int fd;

    //int found_device = 0;
    int find_qmichannel = 0;
    NET_MOD net_mode  = RAS_MOD;


//    strncpy(target_dir, dir, strlen(dir));
    if ((pDir = opendir(dir)) == NULL)  {
        RLOGE("Cannot open directory:%s/", dir);
        return -ENODEV;
    }
    RLOGD("get_netif_mode_by_path=%s\n", dir);
    while ((ent = readdir(pDir)) != NULL) {
        RLOGD("%s", ent->d_name);

        if ((strlen(ent->d_name) == strlen(usb_class_name) && !strncmp(ent->d_name, usb_class_name, strlen(usb_class_name)))) {
            strcpy(subdir, dir);
            strncat(subdir, "/", strlen("/"));
            strncat(subdir, ent->d_name, strlen(ent->d_name));
            if ((pSubDir = opendir(subdir)) == NULL)  {
                RLOGE("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {

                if (strncmp(subent->d_name, "cdc-wdm", strlen("cdc-wdm")) == 0) {
                    RLOGD("Find qmichannel = %s", subent->d_name);
                    find_qmichannel = 1;
#if 0
                    snprintf(uevent_path, MAX_PATH, "%s/%s/%s", subdir, subent->d_name, "uevent");
                    fd_uevent = open(uevent_path, O_RDONLY);
                    if (fd_uevent < 0) {
                        RLOGE("Cannot open file:%s, errno = %d(%s)", uevent_path, errno, strerror(errno));
                    } else {
                        snprintf(cdc_nod, MAX_PATH, "/dev/%s", subent->d_name);
                        read(fd_uevent, uevent_buf, CDCWDM_UEVENT_LEN);
                        close(fd_uevent);
                        pmajor = strstr(uevent_buf, "MAJOR");
                        pminor = strstr(uevent_buf, "MINOR");
                        if (pmajor && pminor) {
                            pmajor += sizeof("MAJOR");
                            pminor += sizeof("MINOR");
                            pcr = pmajor;
                            while (0 != strncmp(pcr++, "\n", 1));
                            *(pcr - 1) = 0;
                            pcr = pminor;
                            while (0 != strncmp(pcr++, "\n", 1));
                            *(pcr - 1) = 0;
                            cdc_major = atoi((const char *)pmajor);
                            cdc_minor = atoi((const char *)pminor);
                            if (0 == stat(cdc_nod, &st)) {
                                if (st.st_rdev != (unsigned)MKDEV(cdc_major, cdc_minor)) {
                                    need_newnod = 1;
                                    if (0 != remove(cdc_nod)) {
                                        LOGE("remove %s failed. errno = %d(%s)", cdc_nod, errno, strerror(errno));
                                    }
                                } else {
                                    need_newnod = 0;
                                }
                            } else {
                                need_newnod = 1;
                            }
                            if ((1 == need_newnod) && (0 != mknod(cdc_nod, S_IRUSR | S_IWUSR | S_IFCHR, MKDEV(cdc_major, cdc_minor)))) {
                                RLOGE("mknod for %s failed, MAJOR = %d, MINOR =%d, errno = %d(%s)", cdc_nod, cdc_major,
                                      cdc_minor, errno, strerror(errno));
                            }
                        } else {
                            RLOGE("major or minor get failed, uevent_buf = %s", uevent_buf);
                        }
                    }
#endif
                    break;
                }
            }
            closedir(pSubDir);
        }

        else if (strncmp(ent->d_name, "GobiQMI", strlen("GobiQMI")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/GobiQMI");
            if ((pSubDir = opendir(subdir)) == NULL)  {
                RLOGE("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if (strncmp(subent->d_name, "qcqmi", strlen("qcqmi")) == 0) {
                    RLOGD("Find qmichannel = %s", subent->d_name);
                    find_qmichannel = 1;
                    /*zhaopf@meigsmart-2022/10/10 change default gobi mode to qmi Begin */
                    if(g_ndis_multi_num > 0){
                        net_mode = MULTI_QMI_MOD;
                        RLOGD("adjust net mode to multi qmi");
                    } else {
                        net_mode = QMI_MOD;
                    }
                    /*zhaopf@meigsmart-2022/10/10 change default gobi mode to qmi End */
                    break;
                }
            }
            closedir(pSubDir);
            if(find_qmichannel) {
                break;
            }
        } else if (strncmp(ent->d_name, "interface", strlen("interface")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/interface");
            RLOGD("read %s\n", subdir);
            fd = open(subdir, O_RDONLY);
            if (fd > 0) {
                read(fd, value_read, MAX_VALUE_LEN);
                close(fd);
                RLOGD("interface is *%s*", value_read);
                /*yufeilong add for support asr ecm 20220929 begin*/

                //* Modify by zhaopengfei for put NCM priority higher than ECM/RNDIS 2022/12/07 Begin */
                /*yufeilong add for support SRM811 20220527 start*/
                if((NULL != strstr(value_read, NCM_LABLE)) || (NULL != strstr(value_read, NCM_LABLE_UNISOC))) {
                /*yufeilong add for support SRM811 20220527 end*/
                    RLOGD("is ncm mode");
                    net_mode = NCM_MOD;
                    break;
                }
                 else if((NULL != strstr(value_read, ECM_LABLE)) || (NULL != strstr(value_read, ECM_LABLE_1))) {
                /*yufeilong add for support asr ecm 20220929 end*/
                    RLOGD("is ecm mode");
                    net_mode = ECM_MOD;
                    break;
                }
                /* Modify by zhaopengfei for put NCM priority higher than ECM/RNDIS 2022/12/07 End */
                /* begin: modified by dongmeirong for RNDIS adapt 20210219 */
                /*zhangqingyun add for support asr platfrom 20220428 start*/
                else if ((NULL != strstr(value_read, RNDIS_LABLE)) || (NULL != strstr(value_read,RNDIS_LABLE_1))) {
                    RLOGD("is rndis mode");
                    net_mode = RNDIS_MOD;
                }
                /*zhangqingun add for support asr platform 20220428 end*/
                /* end: modified by dongmeirong for RNDIS adapt 20210219 */
            }

        }
    }
    closedir(pDir);
    return net_mode;

}

//zhangqingyun add reset interface number through port id in hisi solution
/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection {*/
int  node_read_str(const char* nodePath, char* outString, int maxSize){
           int len = -1;
           int fd = open(nodePath, O_RDONLY);
           if(fd < 0){
               RLOGE("read %s failed", nodePath);
               return -1;
           }
            len = read(fd, outString, maxSize);
            close(fd);
            if(len > 0) {
                if(len < maxSize){
                    outString[len - 1] = '\0';
                } else {
                    outString[maxSize - 1] = '\0';
                }
            }
            return len;
}
void  resetInterfacenumberByDesc(const char* root_dir, int totalPortNumber, int productIndex){
        char prot_node[MAX_PATH] = {0};
        char subcls_node[MAX_PATH] = {0};
        char cls_node[MAX_PATH] = {0};
        struct meig_port_desc port_desc;
        int fd = -1;
        int interface_index ;
        if(0 != access(root_dir, R_OK)){
                RLOGE("Cannot open root_dir:%s/", root_dir);
                return;
        }

        for(interface_index = 0; interface_index < totalPortNumber; interface_index ++){
            memset(prot_node, 0x0, sizeof(prot_node));
            memset(subcls_node, 0x0, sizeof(subcls_node));
            memset(cls_node, 0x0, sizeof(cls_node));
            memset(&port_desc, 0x0, sizeof(port_desc));
            sprintf(prot_node,"%s:1.%d/bInterfaceProtocol", root_dir, interface_index);
            sprintf(subcls_node,"%s:1.%d/bInterfaceSubClass", root_dir, interface_index);
            sprintf(cls_node,"%s:1.%d/bInterfaceClass", root_dir, interface_index);
            LOGD("current traversal prot node is:%s", prot_node);
            LOGD("current traversal cls node is:%s", cls_node);
            LOGD("current traversal subcls node is:%s", subcls_node);


            if(0 != access(prot_node, R_OK) || 0 != access(subcls_node, R_OK)  || 0 != access(cls_node, R_OK)){
                RLOGE("cann't determine usb desc"); //fix err by zhaopf
                continue;
             }
              //protocol
             if(node_read_str(prot_node, port_desc.prot, USB_DESC_MAX_LEN) < 0){
                RLOGE("read %s failed", prot_node);
                continue;
             }
             if(node_read_str(subcls_node, port_desc.subcls, USB_DESC_MAX_LEN) < 0){
                RLOGE("read %s failed", subcls_node);
                continue;
             }
             if(node_read_str(cls_node, port_desc.cls, USB_DESC_MAX_LEN) < 0){
                RLOGE("read %s failed", cls_node);
                continue;
             }

              RLOGD("#if=%d desc: cls=%s, subcls=%s, prot=%s",interface_index, port_desc.cls, port_desc.subcls, port_desc.prot);

              //at
              if(0 == strncasecmp(port_desc.prot, meig_product_list[productIndex].descs.at_desc.prot, 2)){
                      meig_product_list[productIndex].at_inf = interface_index;
                      RLOGD("adjust at port to %d",interface_index);
               //modem
              /*[zhaopf@meigsmart-2020-0716]skip adb port as use same prot with modem port { */
              }else if(0 == strncasecmp(port_desc.prot, meig_product_list[productIndex].descs.modem_desc.prot, 2) &&
              (0 != strncasecmp(port_desc.subcls, ADB_SUBCLS_STR, 2))){ //skip adb
              /*[zhaopf@meigsmart-2020-0716]skip adb port as use same prot with modem port } */
                  meig_product_list[productIndex].ppp_inf = interface_index;
                  RLOGD("adjust modem port to %d",interface_index);

               //ecm
              }else if(0 == strncasecmp(port_desc.cls, meig_product_list[productIndex].descs.ecm_desc.cls, 2)  &&
                  0 == strncasecmp(port_desc.subcls, meig_product_list[productIndex].descs.ecm_desc.subcls, 2) &&
                  0 == strncasecmp(port_desc.prot, meig_product_list[productIndex].descs.ecm_desc.prot, 2)){
                  //cdc have two port use class 02 as port number,not use 0a
                  meig_product_list[productIndex].net_inf = interface_index;
                  RLOGD("adjust ecm port to %d",interface_index);

              //ndis
              }else if(0 == strncasecmp(port_desc.prot, meig_product_list[productIndex].descs.ndis_desc.prot, 2)){
                  meig_product_list[productIndex].net_inf = interface_index;
                  RLOGD("adjust ndis port to %d", interface_index);
              }
   }
}
/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection }*/

int getTotalPortNumbers(const char * dir){
    DIR *cDir = NULL;
    struct dirent* dent = NULL;
    char subdir[MAX_PATH]={0};
        int fd = -1;
/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection {*/
        char totalInterfaces[USB_DESC_MAX_LEN] = {0};
/*[zhaopf@meigsmart-2020-0615]modify for usb desc detection }*/
        int totalPort = 0;
        RLOGD("get port num by path:%s",dir);
        fd = open(dir,O_RDONLY);
        if(fd > 0){
                int read_count = 0;
               /*[zhaopf@meigsmart-2020-0615]modify for usb desc detection {*/
                read_count = read(fd,totalInterfaces, USB_DESC_MAX_LEN);
                if(read_count <= 0){
                    RLOGE("can't read total interface num");
                } else {
                    if(read_count < USB_DESC_MAX_LEN){
                        totalInterfaces[read_count - 1] = '\0';
                    } else {
                        totalInterfaces[USB_DESC_MAX_LEN - 1] = '\0';
                    }
                    RLOGD("read value is:%s read count is:%d",totalInterfaces, read_count);
                    totalPort = atoi(totalInterfaces);
                }

                RLOGD("total Port this moudle have %d",totalPort);
               close(fd);
               /*[zhaopf@meigsmart-2020-0615]modify for usb desc detection }*/
        }
        return totalPort;
}


//zhangqingyun add reset interface number through port id in hisi solution end


int get_modem_info(MODEM_INFO * netinfo)
{
    struct dirent* ent = NULL;
    DIR *pDir;
    char dir[MAX_PATH], subdir[MAX_PATH];
    char target_dir[MAX_PATH], parent_d_name[10], buffer[20];
    char *port_name = NULL;
    int bus_num = -1, dev_num = -1;
    struct utsname  sname;
    int kernel_version;
    int fd;
    /*zhaopf@meigsmart-2022/10/10 add viutual interface name for mms and multi pdn support Begin */
    int i;
    /*zhaopf@meigsmart-2022/10/10 add viutual interface name for mms and multi pdn support End */
    int productIndex = -1;
    int found_modem = 0;
    int total_port = 0;
    int get_netif_num = 10;

#define CDCWDM_UEVENT_LEN 256
#ifndef MKDEV
#define MKDEV(ma,mi) ((ma)<<8 | (mi))
#endif

    int osmaj, osmin, ospatch;
    char *usb_class_name = NULL;
    RLOGD("Get modem info\n");

    /*zhaopf@meigsmart-2022/10/10 add viutual interface name for mms and multi pdn support Begin */
    memset(netinfo, 0x0, sizeof(MODEM_INFO));
    for(i = 0; i < NDIS_MULTI_NUM_MAX; i++){
        netinfo->vif_name[i] = NULL;
    }
    /*zhaopf@meigsmart-2022/10/10 add viutual interface name for mms and multi pdn support End */
    netinfo->if_name = NULL;
    netinfo->busnum = -1;
    netinfo->devnum = -1;
    netinfo->at_port_name= NULL;
    netinfo->modem_port_name= NULL;
    memset(&netinfo->info, 0x0, sizeof(netinfo->info));
    /*zhangqingyun add for suport send mms through ppp 2023-5-7 start */
    #ifdef SEND_MMS_USE_PPP
    netinfo->net_mod = QMI_MOD;
    #else 
    netinfo->net_mod = QMI_MOD;
    #endif
    /*zhangqingyun add for support send mms throuth ppp 2023-5-7 end*/
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
    netinfo->use_deprecated_gobi = false;
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */

    /* get the kernel version now, since we are called before sys_init */
    uname(&sname);
    osmaj = osmin = ospatch = 0;
    sscanf(sname.release, "%d.%d.%d", &osmaj, &osmin, &ospatch);
    kernel_version = KVERSION(osmaj, osmin, ospatch);
    if (kernel_version < KVERSION(3, 6, 0)) {
        usb_class_name = "usb";
    } else {
        usb_class_name = "usbmisc";
    }

    strcpy(dir, "/sys/bus/usb/devices");
    if ((pDir = opendir(dir)) == NULL)  {
        RLOGE("Cannot open directory: %s", dir);
        return found_modem;
    }

    while ((ent = readdir(pDir)) != NULL) {
        char idVendor[5] = "";
        char idProduct[5] = "";
        char version[5] = "";

        sprintf(subdir, "%s/%s/idVendor", dir, ent->d_name);
        if(debug_enable) RLOGD("subdir=%s\n", subdir);
        fd = open(subdir, O_RDONLY);
        if (fd > 0) {
            read(fd, idVendor, 4);
            close(fd);
            RLOGD("idVendor = %s\n", idVendor);
            if (find_vendor_index(idVendor) < 0) {
                continue;
            }

        } else {
            continue;
        }

        sprintf(subdir, "%s/%s/idProduct", dir, ent->d_name);
        fd = open(subdir, O_RDONLY);
        if (fd > 0) {
            read(fd, idProduct, 4);
            close(fd);
            RLOGD("idProduct = %s\n", idProduct);
            if((productIndex = find_product_of_vendor_index(idVendor, idProduct)) < 0) {
                continue;
            }
        } else {
            continue;
        }


        //read version
    /*[zhaopengfei@meigsmart-2020-05-22] modify for radio tech funcion {*/
    if(property_get_bool("ril.fixed.isFiveG", false)) {
        RLOGD("treated as 5G device \n");
        meig_product_list[productIndex].isFiveG = 1;
    }
    /*[zhaopengfei@meigsmart-2020-05-22] modify for radio tech funcion }*/
        memcpy(&netinfo->info, &meig_product_list[productIndex], sizeof(meig_product_list[productIndex]));

        RLOGD("Find idVendor=%s, idProduct=%s", idVendor, idProduct);
        found_modem = 1;
        break;
    }

    if (!found_modem) {
        RLOGE("Cannot find Meig devices");
        closedir(pDir);
        return found_modem;
    }
    strcpy(parent_d_name, ent->d_name);
        //RLOGD("parent_d_name is :%s",parent_d_name);
        //zhangqingyun add support find at,modem,netport through vid pid,class,portid .quacom not implementate in module can not support
        if(meig_product_list[productIndex].sltn_type == HISI){
        memset(target_dir, 0x0, sizeof(target_dir));
        sprintf(target_dir, "%s/%s/bNumInterfaces", dir, parent_d_name);
        total_port = getTotalPortNumbers(target_dir);
        memset(target_dir, 0x0, sizeof(target_dir));
        sprintf(target_dir,"%s/%s", dir, parent_d_name);
        /*[zhaopf@meigsmart-2020-0615]modify for usb desc detection {*/
        resetInterfacenumberByDesc(target_dir, total_port, productIndex);
        /*[zhaopf@meigsmart-2020-0615]modify for usb desc detection }*/

        }
//zpf find businfo
    memset(target_dir, 0x0, sizeof(target_dir));
    sprintf(target_dir, "%s/%s/busnum", dir, parent_d_name);
    RLOGD("Read busnum from %s\n", target_dir);
    if((bus_num = read_node_val_int(target_dir)) >= 0) {
        netinfo->busnum = bus_num;
    } else {
        RLOGE("Cannot find busnum\n");
        found_modem = 0;
        closedir(pDir);
        return found_modem;
    }


    memset(target_dir, 0x0, sizeof(target_dir));
    sprintf(target_dir, "%s/%s/devnum", dir, parent_d_name);
    RLOGD("Read devnum from %s\n", target_dir);
    if((dev_num = read_node_val_int(target_dir)) >= 0) {
        netinfo->devnum = dev_num;
    } else {
        RLOGE("Cannot find devnum\n");
        found_modem = 0;
        closedir(pDir);
        return found_modem;
    }
//zpf

    memset(target_dir, 0x0, sizeof(target_dir));
    sprintf(target_dir, "%s/%s:1.%d", dir, parent_d_name, meig_product_list[productIndex].at_inf);
    /* zhaopengfei@meigsmart.com-2022/08/23 moodify for devName released on some platform Begin */
    RLOGD("Find at path=%s\n", target_dir);
    if((port_name = find_ttyUSBX_by_id(target_dir)) != NULL) {
        memset(buffer, 0x0, sizeof(buffer));
        RLOGE("got at port %s\n", port_name);
        sprintf(buffer, "/dev/%s", port_name);
        free(port_name);
        netinfo->at_port_name = strdup(buffer);
    } else {
        RLOGE("Cannot find at port\n");
        found_modem = 0;
        closedir(pDir);
        return found_modem;
    }
    port_name = NULL;
    memset(target_dir, 0x0, sizeof(target_dir));
    sprintf(target_dir, "%s/%s:1.%d", dir, parent_d_name, meig_product_list[productIndex].ppp_inf);
    RLOGD("Find modem path=%s\n", target_dir);
    if((port_name = find_ttyUSBX_by_id(target_dir)) != NULL) {
        memset(buffer, 0x0, sizeof(buffer));
        sprintf(buffer, "/dev/%s", port_name);
        RLOGE("got modem port %s\n", port_name);
        free(port_name);
        netinfo->modem_port_name = strdup(buffer);
    } else {
        RLOGE("Cannot find modem port\n");
        closedir(pDir);
        found_modem = 0;
        return found_modem;
    }
    /* zhaopengfei@meigsmart.com-2022/08/23 moodify for devName released on some platform End */

    //find net mode
    memset(target_dir, 0x0, sizeof(target_dir));
    sprintf(target_dir, "%s/%s:1.%d", dir, parent_d_name, meig_product_list[productIndex].net_inf);
    RLOGD("Find net mode in path=%s\n", target_dir);
    //zhangqingyun add for use ppp send mms 2023-5-6 
   //#ifndef SEND_MMS_USE_PPP 
/*[yufeilong@meigsmart-2023/02/23]optimize the slow loading probile of ecm driver Begin */
   // while ((netinfo->net_mod == RAS_MOD) && !findPPPDExecFile() && get_netif_num--) {
     //   sleep(2);
        netinfo->net_mod =  get_netif_mode_by_path(target_dir, usb_class_name);
   // }
/*[yufeilong@meigsmart-2023/02/23]optimize the slow loading probile of ecm driver end */
 
    //netinfo->net_mod =  get_netif_mode_by_path(target_dir, usb_class_name);
    //#endif 
    //find net interface
    RLOGD("Find net interface in path=%s\n", target_dir);
    (void)get_netif_name_by_path(target_dir, &netinfo->if_name);

    closedir(pDir);


//find net
    if(found_modem) {
        dump_net_info(netinfo);
    }
    return found_modem;
}





