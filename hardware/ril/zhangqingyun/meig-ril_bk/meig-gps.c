#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <alloca.h>
#include <getopt.h>
#include <linux/sockios.h>
#include <termios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/un.h>
#include <linux/poll.h>
#include <poll.h>
/*[zhaopf@meigsmart-2020-1211]add for android4.4 support { */
#include <telephony/ril.h>
/*[zhaopf@meigsmart-2020-1211]add for android4.4 support } */

#define LOG_NDEBUG 0
#define LOG_TAG "RIL-GPS"
#include "atchannel.h"
#include "at_tok.h"
#include "misc.h"
#include "getdevinfo.h"
#include "meig-log.h"

#define GNSS_ENABLE 1
#define GNSS_DISABLE 0
#define GNSS_INJECT_TIME 23
#define GNSS_INJECT_LOCATION 34
/* begin: added by dongmeirong for AGPS requirement 20201117 */
#define GNSS_SET_SUPL_CFG 35
/* end: added by dongmeirong for AGPS requirement 20201117 */


extern MODEM_INFO  curr_modem_info;
/* begin: added by dongmeirong for AGPS interface adapt 20210207 */
extern bool s_is_supl_host_set;
/* end: added by dongmeirong for AGPS interface adapt 20210207 */

static const struct timeval TIMEVAL_1 = {1,0};

typedef struct _GPS_TLV {
   int type;
   int length;
   unsigned char data[0];
} GPS_TLV;

/* begin: modified by dongmeirong for AGPS requirement 20201117 */
#define MAX_URL_LEN 256
extern bool getIsGpsInited();
static pthread_mutex_t s_gps_cfg_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct _SUPL_INFO {
    int suplHostLen;
    char suplHost[MAX_URL_LEN];
    int suplPort;
} SUPL_INFO;
SUPL_INFO sSuplInfo = {0};
/* end: modified by dongmeirong for AGPS requirement 20201117 */

static int s_gps_state = 0;
static pthread_t s_gps_thread;
static int s_agps_check_times = 0;
static void pollXTRAStateChange (void *param __unused) {
#if 0
    if (s_gps_state && s_agps_check_times--) {
        int xtradatadurtime = 0;
        ATResponse *p_response = NULL;
        int err = at_send_command_singleline("AT+QGPSXTRADATA?", "+QGPSXTRADATA: ", &p_response);
        if (err == 0 && p_response != NULL && p_response->success == 1) {
            char *line = p_response->p_intermediates->line;
            if (at_tok_start(&line) == 0) {
                at_tok_nextint(&line, &xtradatadurtime);
            }
        }
        at_response_free(p_response);
        if (xtradatadurtime == 0)
            RIL_requestTimedCallback (pollXTRAStateChange, NULL, &TIMEVAL_1);
    }
#endif
}

static time_t s_last_inject_time = 0;
static int s_last_inject_uncertainty = 10;
static void *s_last_inject_xtra_data = NULL;
static int s_last_inject_xtra_length = 0;
/* begin: modified by dongmeirong for AGPS requirement 20201117 */
static int parse_gps_conf_info(unsigned char *tlv_data) {
    if (tlv_data == NULL) {
        RLOGE("%s(): input param is null!", __FUNCTION__);
        return -1;
    }
    RLOGD("%s() entry.", __FUNCTION__);
    pthread_mutex_lock(&s_gps_cfg_mutex);
    memcpy(&sSuplInfo.suplHostLen, tlv_data, sizeof(sSuplInfo.suplHostLen));
    /* begin: modified by dongmeirong for AGPS interface adapt 20210207 */
    memset(sSuplInfo.suplHost, 0, sizeof(sSuplInfo.suplHost));
    /* end: modified by dongmeirong for AGPS interface adapt 20210207 */
    memcpy(sSuplInfo.suplHost, tlv_data + sizeof(sSuplInfo.suplHostLen), sSuplInfo.suplHostLen * sizeof(char));
    memcpy(&sSuplInfo.suplPort,
        tlv_data + sizeof(sSuplInfo.suplHostLen) + sSuplInfo.suplHostLen * sizeof(char), sizeof(sSuplInfo.suplPort));
    RLOGD("SUPL_HOST_LEN: %d, SUPL_HOST: %s, SUPL_PORT: %d",
        sSuplInfo.suplHostLen, sSuplInfo.suplHost, sSuplInfo.suplPort);
    pthread_mutex_unlock(&s_gps_cfg_mutex);
    RLOGD("%s() leave.", __FUNCTION__);
    return 0;
}
/* end: modified by dongmeirong for AGPS requirement 20201117 */
static void onGPSStateChange (void *param)
{
    char *cmd;
    ATResponse *p_response = NULL;
    int oldState = 0xff;
    GPS_TLV *extra_gps_tlv = (GPS_TLV *)param;
/* begin: added by dongmeirong for AGPS requirement 20201117 */
    bool isGpsInited = getIsGpsInited();
/* end: added by dongmeirong for AGPS requirement 20201117 */
#if 0
    int err = at_send_command_singleline("AT+QGPS?", "+QGPS: ", &p_response);

    if (err == 0 && p_response != NULL && p_response->success == 1) {
        char *line = p_response->p_intermediates->line;
        if (at_tok_start(&line) == 0) {
            at_tok_nextint(&line, &oldState);
        }
    }
    at_response_free(p_response);
#endif

    RLOGD("onGPSStateChange = {type=%d, length=%d}", extra_gps_tlv->type, extra_gps_tlv->length);
/* begin: added by dongmeirong for AGPS requirement 20201117 */
    if (!isGpsInited && extra_gps_tlv->type != GNSS_SET_SUPL_CFG) {
        RLOGD("GPS is not initialized, don't process cmds except supl cfg.");
        free(extra_gps_tlv);
        return;
    }
/* end: added by dongmeirong for AGPS requirement 20201117 */
    if (extra_gps_tlv->type == GNSS_DISABLE) //disable
    {
#if 0
        if (oldState == 0)
            return;
#endif
        s_gps_state = 0;
        /* begin: modified by dongmeirong for AT Ver adaption 20201217 */
        /* Modified by zhaopengfei for ASR GPS support 2022/11/01 Begin */
        if(((QCM == curr_modem_info.info.sltn_type) && (curr_modem_info.info.at_version == AT_VERSION_2)) || ASR == curr_modem_info.info.sltn_type) {
            at_send_command("AT+GPSSTOP", NULL);
        } else {
            at_send_command("AT+FGGPSSTOP", NULL);
        }
        /* Modified by zhaopengfei for ASR GPS support 2022/11/01 End */
        /* end: modified by dongmeirong for AT Ver adaption 20201217 */
    }
    else if (extra_gps_tlv->type == GNSS_ENABLE) //enable
    {
#if 0
        if (oldState != 0)
            return;
#endif
        if (s_last_inject_xtra_data != NULL)
        {
            struct tm tm;
            time_t now = time(NULL);

            if (s_last_inject_time > now)
                now = s_last_inject_time;
            gmtime_r(&now, &tm);

            at_send_command("AT+GPSXTRA=1", NULL);
#if 0
            asprintf(&cmd, "AT+QFUPL=\"RAM:xtra2.bin\",%d,%d", s_last_inject_xtra_length, 60);
            at_send_command_raw(cmd, s_last_inject_xtra_data, s_last_inject_xtra_length, "+QFUPL:", NULL);
            free(cmd);
#endif
            asprintf(&cmd, "AT+GPSXTRATIME=0, \"%d/%d/%d,%d:%d:%d\",1,1,%d",
                tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, s_last_inject_uncertainty);
            at_send_command(cmd, NULL);
            free(cmd);
#if 0
            at_send_command("AT+QGPSXTRADATA=\"RAM:xtra2.bin\"", NULL);
            at_send_command("AT+QFDEL=\"RAM:xtra2.bin\"", NULL);
#endif
            free(s_last_inject_xtra_data);
            s_last_inject_xtra_data = NULL;

            s_gps_state = 1;
            s_agps_check_times = 15;
            //RIL_requestTimedCallback (pollXTRAStateChange, NULL, &TIMEVAL_1);
        }
        /* begin: modified by dongmeirong for AT Ver adaption 20201217 */
        if((QCM == curr_modem_info.info.sltn_type) && (curr_modem_info.info.at_version == AT_VERSION_2)) {
            /* begin: modified by dongmeirong for AGPS requirement 20201117 */
            /*[zhaopf@meigsmart-2020-1211]modify accuracy for get location faster { */
            if (property_get_bool("ril.agps.enable", true)) {
                at_send_command("AT+GPSRUN=1,255,200,0,1", NULL);
            } else {
                at_send_command("AT+GPSRUN=0,255,200,0,1", NULL);
            }
            /*[zhaopf@meigsmart-2020-1211]modify accuracy for get location faster { */
            /* end: modified by dongmeirong for AGPS requirement 20201117 */
        /* Modified by zhaopengfei for ASR GPS support 2022/11/01 Begin */
        } else if (ASR == curr_modem_info.info.sltn_type) {
            at_send_command("AT+GPSRUN", NULL);
        } else {
            at_send_command("AT+FGGPSRUN", NULL);
        }
        /* Modified by zhaopengfei for ASR GPS support 2022/11/01 End */
        /* END: modified by dongmeirong for AT Ver adaption 20201217 */
    }
    else if (extra_gps_tlv->type == GNSS_INJECT_TIME) //inject time
    { //inject time
        /** Milliseconds since January 1, 1970 */
        typedef int64_t GpsUtcTime;
        GpsUtcTime gpsutctime; int64_t timeReference; int uncertainty;
        struct tm tm;

        memcpy(&gpsutctime, extra_gps_tlv->data, sizeof(gpsutctime));
        memcpy(&timeReference, extra_gps_tlv->data + sizeof(gpsutctime), sizeof(timeReference));
        memcpy(&uncertainty, extra_gps_tlv->data + sizeof(gpsutctime) + sizeof(uncertainty), sizeof(uncertainty));

        RLOGD("%s(time=%lld, timeReference=%lld, uncertainty=%d)",__FUNCTION__,
            *((int64_t *)&gpsutctime), timeReference, uncertainty);

        s_last_inject_time = (gpsutctime+999)/1000;
        s_last_inject_uncertainty = uncertainty;

        gmtime_r(&s_last_inject_time, &tm);

        RLOGD("%s GpsUtcTime: \"%d/%d/%d,%d:%d:%d\", uncertainty=%d", __func__,
                tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, s_last_inject_uncertainty);
    }
    else if (extra_gps_tlv->type == GNSS_INJECT_LOCATION)
    { //inject xtra
        if (s_last_inject_xtra_data)
            free(s_last_inject_xtra_data);

        s_last_inject_xtra_data = malloc(extra_gps_tlv->length);
        s_last_inject_xtra_length = extra_gps_tlv->length;
        if (s_last_inject_xtra_data != NULL)
            memcpy(s_last_inject_xtra_data, extra_gps_tlv->data, extra_gps_tlv->length);
    }
    /* begin: added by dongmeirong for AGPS requirement 20201117 */
    /* begin: modified by dongmeirong for AGPS interface adapt 20210207 */
    else if (extra_gps_tlv->type == GNSS_SET_SUPL_CFG && property_get_bool("ril.agps.enable", false)) {
        int ret = -1;
        char * suplHost = NULL;
        int suplPort = -1;
        asprintf(&suplHost, "%s", sSuplInfo.suplHost);
        suplPort = sSuplInfo.suplPort;
        if (extra_gps_tlv->length > 0) {
            ret = parse_gps_conf_info(extra_gps_tlv->data);
        }
        if (!strcmp(suplHost, sSuplInfo.suplHost) && suplPort == sSuplInfo.suplPort && s_is_supl_host_set) {
            RLOGD("%s(), the same supl is already set, don't repeat.", __FUNCTION__);
        } else if (ret == 0 && isGpsInited) {
            ATResponse *response = NULL;
            int err = -1;
            asprintf(&cmd, "AT+GPSCFG=\"agpssupl\",%s:%d", sSuplInfo.suplHost, sSuplInfo.suplPort);
            err = at_send_command(cmd, &response);
            free(cmd);
            if(err < 0 || response->success == 0) {
                RLOGD("%s send command set supl failed.", __FUNCTION__);
            } else {
                s_is_supl_host_set = true;
            }
            at_response_free(response);
        }
        free(suplHost);
    }
    /* end: modified by dongmeirong for AGPS interface adapt 20210207 */
    /* end: added by dongmeirong for AGPS requirement 20201117 */
    free(extra_gps_tlv);
}

/* begin: added by dongmeirong for AGPS requirement 20201117 */
// NOTICE: free suplHost by the callers.
void getSuplInfo(char **suplHost, int *suplPort) {
    pthread_mutex_lock(&s_gps_cfg_mutex);
    if (sSuplInfo.suplHostLen > 0) {
        asprintf(suplHost, "%s", sSuplInfo.suplHost);
        *suplPort = sSuplInfo.suplPort;
    }
    pthread_mutex_unlock(&s_gps_cfg_mutex);
}
/* end: added by dongmeirong for AGPS requirement 20201117 */

static void * GpsMainLoop(void *param) {
    struct sockaddr_un addr;
    struct sockaddr_un *p_addr = &addr;
    const char *name = "rild-gps";
    int type = SOCK_STREAM;
    int n;
    int err;

    int s = socket(AF_LOCAL, type, 0);
    if (s < 0) return NULL;

    memset (p_addr, 0, sizeof (*p_addr));
    p_addr->sun_family = AF_LOCAL;
    p_addr->sun_path[0] = 0;
    memcpy(p_addr->sun_path + 1, name, strlen(name) );

    n = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));

    if (bind(s, (struct sockaddr *) &addr,  strlen(name) + offsetof(struct sockaddr_un, sun_path) + 1) < 0) {
        return NULL;
    }

    if (type == SOCK_STREAM) {
        int ret;

        ret = listen(s, 1);

        if (ret < 0) {
            close(s);
            return NULL;
        }
    }

    for(;;) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;
        int ret;
        struct pollfd pollfds[1];
        GPS_TLV gps_tlv;
        GPS_TLV *extra_gps_tlv = NULL;

        alen = sizeof(addr);
        RLOGD("waiting for gps connect");
        fd = accept(s, &addr, &alen);
        if(fd < 0) {
            RLOGD("accept failed: %s\n", strerror(errno));
            continue;
        }

        fcntl(fd, F_SETFD, FD_CLOEXEC);

        RLOGD("reading gps cmd");
        fcntl(fd, F_SETFL, O_NONBLOCK);

        pollfds[0].fd = fd;
        pollfds[0].events = POLLIN;
        pollfds[0].revents = 0;
        gps_tlv.type = -1;
        gps_tlv.length = 0;
        extra_gps_tlv = NULL;

        do {
            do {
                ret = poll(pollfds, (nfds_t)1, -1);
            } while ((ret < 0) && (errno == EINTR));

            if (pollfds[0].revents & POLLIN) {
                ssize_t nreads;
                if (gps_tlv.length == 0) {
                    nreads = read(fd, &gps_tlv, sizeof(gps_tlv));
                    if (nreads <= 0) {
                        LOGE("%s read=%d errno: %d (%s)",  __func__, (int)nreads, errno, strerror(errno));
                        break;
                    }

                    if (nreads == 1) { //old gps hal only send gps_cmd
                        unsigned char gps_cmd = *((unsigned char *)&gps_tlv);
                        gps_tlv.type = gps_cmd;
                        gps_tlv.length = 0;
                    }

                    extra_gps_tlv = (GPS_TLV *)malloc(sizeof(gps_tlv) + gps_tlv.length);
                    extra_gps_tlv->type = gps_tlv.type;
                    extra_gps_tlv->length = 0;
                } else {
                    nreads = read(fd, extra_gps_tlv->data + extra_gps_tlv->length, gps_tlv.length);
                    if (nreads <= 0) {
                        LOGE("%s read=%d errno: %d (%s)",  __func__, (int)nreads, errno, strerror(errno));
                        break;
                    }
                    extra_gps_tlv->length += nreads;
                    gps_tlv.length -= nreads;
                }
            }
            else if (pollfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                break;
            }
        }
        while (gps_tlv.length);

        RLOGD("gps_tlv = {type=%d, length=%d}", gps_tlv.type, gps_tlv.length);
        if (extra_gps_tlv) {
            RLOGD("extra_gps_tlv = {type=%d, length=%d}", extra_gps_tlv->type, extra_gps_tlv->length);
        }

        if (extra_gps_tlv) {
            RIL_requestTimedCallback (onGPSStateChange, extra_gps_tlv, NULL);
        }
done:
        close(fd);
    }

    return NULL;
}

void meig_gps_init(void) {
    RLOGD("gps thread start");
    if (s_gps_thread == 0) {
        pthread_create(&s_gps_thread, NULL, GpsMainLoop, NULL);
    }
}
