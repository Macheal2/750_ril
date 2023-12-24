#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <errno.h>
#include "usb_monitor.h"
#define LOG_TAG "RIL-USB"
#include <utils/Log.h>

static USB_STATE g_usb_state = USB_UNPLUGGED;

static  TRACKED_DEV  tracked_dev;

static usb_lost_callback on_usb_lost;
#define HAS_CONST_PREFIX(str,end,prefix)  has_prefix((str),(end),prefix,strlen(prefix))
#define UEVENT_BUFFER_SIZE      (2048)


char *get_dev_name(char *p)
{
    char ch = '\\';
    char *q = strrchr(p,ch) + 1;

    return q;
}

static const char*
has_prefix(const char* str, const char* end, const char* prefix, size_t prefixlen)
{
    if ((size_t)(end - str) >= prefixlen &&
            (prefixlen == 0 || !memcmp(str, prefix, prefixlen))) {
        return str + prefixlen;
    } else {
        return NULL;
    }
}


static int parseAsciiNetlinkMessage(char *buffer, int size)
{
    const char *s = buffer;
    const char *end;
    int first = 1;
    if (size == 0)
        return -1;

    /* Ensure the buffer is zero-terminated, the code below depends on this */
    buffer[size-1] = '\0';

    end = s + size;
    while (s < end) {
        if (first) {
            const char *p;
            /* buffer is 0-terminated, no need to check p < end */
            for (p = s; *p != '@'; p++) {
                if (!*p) { /* no '@', should not happen */
                    return 0;
                }
            }
            first = 0;
        } else {
            const char* a;
            if ((a = HAS_CONST_PREFIX(s, end, "ACTION=")) != NULL) {
                if (!strcmp(a, "add")) {
                    if(tracked_dev.tracked && NULL != strstr(buffer, tracked_dev.name)) {
                        RLOGD("===Add %s\n", tracked_dev.name);
                        tracked_dev.state = USB_PLUGGED;
                    }
                } else if (!strcmp(a, "remove")) {
                    if(tracked_dev.tracked && NULL != strstr(buffer, tracked_dev.name)) {
                        tracked_dev.state =  USB_UNPLUGGED;
                        RLOGD("===Remove %s\n", tracked_dev.name);
                    }
                }
#if 0
                else if (!strcmp(a, "change")) {
                    RLOGD("===Change\n");
                } else {
                    RLOGD("unkonw...\n");
                }
#endif
            }

        }
        s += strlen(s) + 1;
    }
    return 1;
}


static int init_uevent_sock(void)
{
    struct sockaddr_nl nladdr;
    const int sz = (64*1024);
    int on = 1;
    memset(&nladdr, 0x0, sizeof(struct sockaddr_nl));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = getpid();
    nladdr.nl_groups = 0xffffffff;

    int mSock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if(mSock < 0) {
        RLOGD("error open socket:%s\n", strerror(errno));
        return -1;
    }


    // When running in a net/user namespace, SO_RCVBUFFORCE is not available.
    // Try using SO_RCVBUF first.
    if ((setsockopt(mSock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) < 0) &&
            (setsockopt(mSock, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz)) < 0)) {
        RLOGD("Unable to set uevent socket SO_RCVBUF/SO_RCVBUFFORCE option: %s", strerror(errno));
    }

    if (setsockopt(mSock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0) {
        RLOGD("Unable to set uevent socket SO_PASSCRED option: %s", strerror(errno));
    }

    if (bind(mSock, (struct sockaddr *) &nladdr, sizeof(nladdr)) < 0) {
        RLOGD("Unable to bind uevent socket: %s", strerror(errno));
        close(mSock);
        mSock = -1;
    }

    return mSock;

}



static void *usb_monitor_thread(void *arg __unused)
{
    int mSock = -1;
    char mBuffer[UEVENT_BUFFER_SIZE*2] = {0};
    int count;
    RLOGD("usb_monitor_thread start usb monitor\n");
    mSock = init_uevent_sock();
    if(mSock < 0) {
        RLOGD("sock error\n");
        return NULL;
    }
    while(1 == tracked_dev.tracked &&  USB_PLUGGED == tracked_dev.state) {
        count = recv(mSock, mBuffer, sizeof(mBuffer), 0);
        if (count < 0) {
            continue;
        }


        (void)parseAsciiNetlinkMessage(mBuffer, count);
#ifdef DEBUG
        RLOGD("->%s\n", mBuffer);
#endif
    }
    if(on_usb_lost) {
        (*on_usb_lost)();
    }
    RLOGD("usb device %s lost\n", tracked_dev.name);
    if(NULL != tracked_dev.name) {
        free(tracked_dev.name);
        tracked_dev.name = NULL;

    }
    RLOGD("close usb socket\n");
    close(mSock);
    mSock = -1;
    return NULL;

}

void set_track_dev(const char* devname, int fd)
{
    char* pName = NULL;
    char name[MAX_TRACKED_DEV_NAME_LEN+4];
    pName= strstr(devname, "ttyUSB");
    if(NULL == pName) {
        RLOGE("invalid dev name %s \n", devname);
        return;
    }

    if(strlen(pName) > MAX_TRACKED_DEV_NAME_LEN || fd < 0) {
        RLOGE("track dev name %s is too loog \n", devname);
        return;
    }

    tracked_dev.state = USB_PLUGGED;
    tracked_dev.fd = fd;
    sprintf(name, "tty/%s", pName);
    tracked_dev.name = strdup(name);
    // strncpy(tracked_dev.name, name,  strlen(name));
    RLOGD("set_track_dev_name %s\n", tracked_dev.name);
}

USB_STATE flush_usb_state()
{
    if(tracked_dev.tracked && USB_UNPLUGGED == tracked_dev.state && tracked_dev.fd >= 0) {
        RLOGD ("close fd %d\n", tracked_dev.fd);
        close(tracked_dev.fd);
        tracked_dev.fd = -1;
    }
    return tracked_dev.state;
}

void start_usb_monitor(usb_lost_callback  on_usb_lost_fun)
{
    pthread_t thread_tid;
    int ret;
    tracked_dev.tracked = 1;
    tracked_dev.state = USB_PLUGGED;
    on_usb_lost = on_usb_lost_fun;
    ret = pthread_create(&thread_tid, NULL, usb_monitor_thread, NULL);
    if (ret < 0) {
        RLOGE ("qcrmcall_thread  failed");
        return;
    }

}
