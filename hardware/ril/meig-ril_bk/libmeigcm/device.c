#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>

#include "common.h"

#define CM_MAX_PATHLEN 256

#define CM_INVALID_VAL (~((int)0))
/* get first line from file 'fname'
 * And convert the content into a hex number, then return this number */
static int file_get_value(const char *fname)
{
    FILE *fp = NULL;
    int hexnum;
    char buff[32 + 1] = {'\0'};
    char *endptr = NULL;

    fp = fopen(fname, "r");
    if (!fp) goto error;
    if (fgets(buff, sizeof(buff), fp) == NULL)
        goto error;
    fclose(fp);

    hexnum = strtol(buff, &endptr, 16);
    if (errno == ERANGE && (hexnum == LONG_MAX || hexnum == LONG_MIN))
        goto error;
    /* if there is no digit in buff */
    if (endptr == buff)
        goto error;
    return (int)hexnum;

error:
    if (fp) fclose(fp);
    return CM_INVALID_VAL;
}

/*
 * This function will search the directory 'dirname' and return the first child.
 * '.' and '..' is ignored by default
 */
int dir_get_child(const char *dirname, char *buff, unsigned bufsize)
{
    struct dirent *entptr = NULL;
    DIR *dirptr = opendir(dirname);
    if (!dirptr)
        goto error;
    while ((entptr = readdir(dirptr))) {
        if (entptr->d_name[0] == '.')
            continue;
        snprintf(buff, bufsize, "%s", entptr->d_name);
        break;
    }

    closedir(dirptr);
    return 0;
error:
    buff[0] = '\0';
    if (dirptr) closedir(dirptr);
    return -1;
}

int conf_get_val(const char *fname, const char *key)
{
    char buff[CM_MAX_BUFF] = {'\0'};
    FILE *fp = fopen(fname, "r");
    if (!fp)
        goto error;

    while (fgets(buff, CM_MAX_BUFF, fp)) {
        char prefix[CM_MAX_BUFF] = {'\0'};
        char tail[CM_MAX_BUFF] = {'\0'};
        /* To eliminate cppcheck warnning: Assume string length is no more than 15 */
        sscanf(buff, "%15[^=]=%15s", prefix, tail);
        if (!strncasecmp(prefix, key, strlen(key))) {
            fclose(fp);
            return atoi(tail);
        }
    }

error:
    fclose(fp);
    return CM_INVALID_VAL;
}


//modify for multi modem support by zhaopengfei 2021/02/07 Beiain
BOOL qmidevice_detect(char *qmichannel, char *usbnet_adapter, unsigned bufsize)
{
//static int qmidevice_detect(char **pp_qmichannel, char **pp_usbnet_adapter) {
    struct dirent* ent = NULL;
    DIR *pDir;
    char* devNameList[1]= { "qcqmi"};
    int use_fixed_adapter = -1; //-1:undef, 0:continue, 1:got

    if ((pDir = opendir("/dev")) == NULL)  {
        dbg_time("Cannot open directory: %s, errno:%d (%s)", "/dev", errno, strerror(errno));
        return FALSE;
    }

    while ((ent = readdir(pDir)) != NULL) {
        if (strncmp(ent->d_name, devNameList[0], strlen(devNameList[0])) == 0) {
            char net_path[64];
            int devIndex = 0;
            snprintf(qmichannel,bufsize,  "/dev/%s", ent->d_name);
            dbg_time("Find qmichannel = %s", qmichannel);
            devIndex = 0;
            //got interface name form param
            {
                if (strncmp(ent->d_name, devNameList[devIndex], strlen(devNameList[devIndex])) == 0) {
                    if(usbnet_adapter[0] != '\0' ) {
                        char* pDevIndex = NULL;
                        if (!!(pDevIndex = strstr( usbnet_adapter, "wwan" ))) {
                            pDevIndex += strlen( "wwan" );
                        } else if (!!(pDevIndex = strstr( usbnet_adapter, "usb" ))) {
                            pDevIndex += strlen( "usb" );
                        } else if (!!(pDevIndex = strstr( usbnet_adapter, "eth" ))) {
                            pDevIndex += strlen( "eth" );
                        }

                        if(0 != strcmp(pDevIndex, &ent->d_name[strlen(devNameList[devIndex])])) {
                            dbg_time("match next\n");
                            use_fixed_adapter = 0;
                            break;
                        }

                        snprintf(net_path, 64, "/sys/class/net/%s", usbnet_adapter);
                        dbg_time("net_path=%s\n", net_path);
                        if(access(net_path, R_OK) == 0) {
                            dbg_time("use fixed adapter");
                            use_fixed_adapter = 1;
                            break;
                        }
                    } else {
                        if(0 == devIndex) {
                            snprintf(net_path, 64, "/sys/class/net/wwan%s", &ent->d_name[strlen(devNameList[devIndex])]);
                        } else {
                            snprintf(net_path, 64, "/sys/class/net/usb%s", &ent->d_name[strlen(devNameList[devIndex])]);
                            if (access(net_path, R_OK) && errno == ENOENT)
                                snprintf(net_path, 64,  "/sys/class/net/eth%s", &ent->d_name[strlen(devNameList[devIndex])]);
                        }
                    }
                }
            }

            if(usbnet_adapter[0] != '\0') {
                if(1 == use_fixed_adapter) {
                    dbg_time("use fixed adapter");
                    break;
                } else if(0 == use_fixed_adapter) {
                    continue;
                }
            }

            if (access(net_path, R_OK) == 0) {
                if (usbnet_adapter[0] != '\0' && strcmp(usbnet_adapter, (net_path + strlen("/sys/class/net/")))) {
                    memset(qmichannel, 0x0, bufsize);
                    qmichannel[0]='\0';
                    continue;
                }

                snprintf(usbnet_adapter, bufsize, "%s", net_path + strlen("/sys/class/net/"));
                dbg_time("Find usbnet_adapter = %s", usbnet_adapter);
                break;
            } else {
                dbg_time("Failed to access %s, errno:%d (%s)", net_path, errno, strerror(errno));
                memset(qmichannel, 0x0, bufsize);
                qmichannel[0]='\0';
            }
        }
    }
    closedir(pDir);

    return (qmichannel[0] != '\0' && usbnet_adapter[0] != '\0');
}
//modify for multi modem support by zhaopengfei 2021/02/07 End

#define USB_CLASS_COMM            2
#define USB_CLASS_VENDOR_SPEC        0xff
#define USB_CDC_SUBCLASS_MBIM            0x0e

/*
 * To check whether the system load the wrong driver:
 *      error1: usbnet 2(MBIM) match the QMI driver(qmi_wwan|GobiNet)
 *      error2: usbnet 0(QMI) match the MBIM driver(cdc_mbim)
 * return:
 *  0 for ok, or ignorance
 *  others for failure or error
 */
int varify_driver(CM_DEV_CONTEXT *devContext)
{
    char path[CM_MAX_PATHLEN+1] = {'\0'};
    int bInterfaceClass = -1;

    snprintf(path, sizeof(path), "/sys/class/net/%s/device/bInterfaceClass", devContext->usbnet_adapter);
    bInterfaceClass = file_get_value(path);

    /* QMI_WWAN */
    if (driver_is_qmi(devContext->driver_name) && bInterfaceClass != USB_CLASS_VENDOR_SPEC) {
        dbg_time("module register driver %s, but at+qcfg=\"usbnet\" is not QMI mode!", devContext->driver_name);
        return 1;
    }

    /* CDC_MBIM */
    if (driver_is_mbim(devContext->driver_name) && bInterfaceClass != USB_CLASS_COMM) {
        dbg_time("module register driver %s, but at+qcfg=\"usbnet\" is not MBIM mode!", devContext->driver_name);
        return 1;
    }

    return 0;
}
