 #include "resetep.h"
 #include <stdio.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <errno.h>
 #include <sys/ioctl.h>
 #include <linux/usbdevice_fs.h>
#include "meig-log.h"
#include "getdevinfo.h"
#include "ril_common.h"

extern MODEM_INFO  curr_modem_info;



struct usbfs_ioctl
{
    int ifno;       /* interface 0..N ; negative numbers reserved */
    int ioctl_code; /* MUST encode size + direction of sdata so the
                         * macros in <asm/ioctl.h> give correct values */
    void *data;     /* param buffer (in, or out) */
};



static void usbfs_detach_kernel_driver(int fd, int ifnum)
{
    struct usbfs_ioctl operate;
    operate.data = NULL;
    operate.ifno = ifnum;
    operate.ioctl_code = USBDEVFS_DISCONNECT;
    if (ioctl(fd, USBDEVFS_IOCTL, &operate) < 0) {
        RLOGD("%s detach kernel driver failed", __func__);
    } else {
        RLOGD("%s detach kernel driver success", __func__);
    }
}

static void usbfs_attach_kernel_driver(int fd, int ifnum)
{
    struct usbfs_ioctl operate;
    operate.data = NULL;
    operate.ifno = ifnum;
    operate.ioctl_code = USBDEVFS_CONNECT;
    if (ioctl(fd, USBDEVFS_IOCTL, &operate) < 0) {
        RLOGD("%s detach kernel driver failed", __func__);
    } else {
        RLOGD("%s detach kernel driver success", __func__);
    }
}

static int reattach_driver(int fd, int ifnum)
{
    usbfs_detach_kernel_driver(fd, ifnum);
    usbfs_attach_kernel_driver(fd, ifnum);
    return 0;
}

static int clear_usb_halt(int fd, int ifnum, int ep)
{
       int rc;
       rc = ioctl(fd, USBDEVFS_CLAIMINTERFACE, &ifnum);
        if (rc < 0) {
            RLOGE("Error in ioctl");
            return rc;
        }

        rc = ioctl(fd, USBDEVFS_CLEAR_HALT, &ep);
        if (rc < 0) {
            RLOGE("Error in ioctl");
            return rc;
        }

       rc = ioctl(fd, USBDEVFS_RELEASEINTERFACE, &ifnum);
        if (rc < 0) {
            RLOGE("Error in ioctl");
            return rc;
        }

       return rc;
}



int reset_ep(int infNum, int ep)
{

        char nodename[25] = { 0x0};
        int fd;
        int rc;
        /*add by zhaopengfei for ep check 2022/10/10 Begin */
        if(ep == INVALID_DESC) {
            RLOGE("invalid ep");
            return -1;
        }
        /*add by zhaopengfei for ep check 2022/10/10 End */
        if(curr_modem_info.busnum < 0 || curr_modem_info.devnum < 0) {
            RLOGE("empty bus info");
            return -1;
        }
        sprintf(nodename, "/dev/bus/usb/%03d/%03d", curr_modem_info.busnum, curr_modem_info.devnum);
        RLOGI("reset inf:%d ep:0x%x by %s", infNum, ep, nodename);
        fd = open(nodename, O_WRONLY);
        if (fd < 0) {
            RLOGE("Error opening output file");
            return 1;
        }

        usbfs_detach_kernel_driver(fd, infNum);
        clear_usb_halt(fd, infNum, ep);
        usbfs_attach_kernel_driver(fd, infNum);
        close(fd);
        return 0;
}

#if 0
int main(int argc, char **argv)
{
    reset_ep(5, 0x8a);
    return 0;
}
#endif
