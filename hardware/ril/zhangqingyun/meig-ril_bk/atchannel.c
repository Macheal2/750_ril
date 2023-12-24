/* //device/system/meig-ril/atchannel.c
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
#include "voice.h"
#include "sms.h"
#include "libmeigcm/meig_cm.h"
#include "atchannel.h"
#include "at_tok.h"
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
/*[zhaopf@meigsmart-2020-11-17]add for usb reconnection after wakeup { */
#include <termios.h>
/*[zhaopf@meigsmart-2020-11-17]add for usb reconnection after wakeup } */

#define LOG_NDEBUG 0
#define LOG_TAG "RIL-AT"
#include <utils/Log.h>

#include "misc.h"



#define NUM_ELEMS(x) (sizeof(x)/sizeof(x[0]))

#define MAX_AT_RESPONSE (8 * 1024)
#define HANDSHAKE_RETRY_COUNT 8
#define HANDSHAKE_TIMEOUT_MSEC 2000 //fixed by zhaopf, avoid send at too fast
/*[zhaopf@meigsmart-2020-0716]wait more time { */
/*Modify by zhaopengfei for unisoc modem at wait 40s 2023/01/11 Begin */
#define AT_COMMOND_TIMEOUT_20S (20000)
#define AT_COMMOND_TIMEOUT_40S (40000)
#define AT_COMMOND_TIMEOUT_MSEC ((curr_modem_info.info.sltn_type == UNISOC)?AT_COMMOND_TIMEOUT_40S:AT_COMMOND_TIMEOUT_20S)
/*Modify by zhaopengfei for unisoc modem at wait 40s 2023/01/11 End */

/*[zhaopf@meigsmart-2020-0716]wait more time } */
static pthread_t s_tid_reader;
static int s_fd = -1;    /* fd of the AT channel */
static ATUnsolHandler s_unsolHandler;

/* for input buffering */

static char s_ATBuffer[MAX_AT_RESPONSE+1];
static char *s_ATBufferCur = s_ATBuffer;
/*[zhaopf@meigsmart-2020-11-17]add for usb reconnection after wakeup { */
static usb_reconnected_callback s_onUsbReconnected = NULL;
/*[zhaopf@meigsmart-2020-11-17]add for usb reconnection after wakeup } */
/*[zhaopf@meigsmart-2020-1120]add for screen state monitor { */
extern int s_screen_state;
/*[zhaopf@meigsmart-2020-1120]add for screen state monitor } */

#if AT_DEBUG
void  AT_DUMP(const char*  prefix, const char*  buff, int  len)
{
    if (len < 0)
        len = strlen(buff);
    RLOGD("%.*s", len, buff);
}
#endif

/*
 * for current pending command
 * these are protected by s_commandmutex
 */

static pthread_mutex_t s_commandmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_at_commandmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_commandcond = PTHREAD_COND_INITIALIZER;


static ATCommandType s_type;
static const char *s_responsePrefix = NULL;
static const char *s_smsPDU = NULL;
static ATResponse *sp_response = NULL;

static void (*s_onTimeout)(void) = NULL;
static void (*s_onReaderClosed)(void) = NULL;
static int s_readerClosed;

static void onReaderClosed();
static int writeCtrlZ (const char *s);
static int writeline (const char *s);

#define NS_PER_S 1000000000
void setTimespecRelative(struct timespec *p_ts, long long msec)
{
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *) NULL);

    p_ts->tv_sec = tv.tv_sec + (msec / 1000);
    p_ts->tv_nsec = (tv.tv_usec + (msec % 1000) * 1000L ) * 1000L;
    /* assuming tv.tv_usec < 10^6 */
    if (p_ts->tv_nsec >= NS_PER_S) {
        p_ts->tv_sec++;
        p_ts->tv_nsec -= NS_PER_S;
    }
}

static void sleepMsec(long long msec)
{
    struct timespec ts;
    int err;

    ts.tv_sec = (msec / 1000);
    ts.tv_nsec = (msec % 1000) * 1000 * 1000;

    do {
        err = nanosleep (&ts, &ts);
    } while (err < 0 && errno == EINTR);
}



/** add an intermediate response to sp_response*/
static void addIntermediate(const char *line)
{
    ATLine *p_new;

    p_new = (ATLine  *) malloc(sizeof(ATLine));

    p_new->line = strdup(line);

    /* note: this adds to the head of the list, so the list
       will be in reverse order of lines received. the order is flipped
       again before passing on to the command issuer */
    p_new->p_next = sp_response->p_intermediates;
    sp_response->p_intermediates = p_new;
}


/**
 * returns 1 if line is a final response indicating error
 * See 27.007 annex B
 * WARNING: NO CARRIER and others are sometimes unsolicited
 */
static const char * s_finalResponsesError[] = {
    "ERROR",
    "+CMS ERROR:",
    "+CME ERROR:",
    "+CMEE ERROR:",
    "NO CARRIER", /* sometimes! */
    "NO ANSWER",
    "NO DIALTONE",
    "COMMAND NOT SUPPORT",
    "Qmi Send Message Error!",
    "Parameters error"
};
static int isFinalResponseError(const char *line)
{
    size_t i;

    for (i = 0 ; i < NUM_ELEMS(s_finalResponsesError) ; i++) {
        if (strStartsWith(line, s_finalResponsesError[i])) {
            return 1;
        }
    }

    return 0;
}

/**
 * returns 1 if line is a final response indicating success
 * See 27.007 annex B
 * WARNING: NO CARRIER and others are sometimes unsolicited
 */
static const char * s_finalResponsesSuccess[] = {
    "OK",
    "CONNECT"       /* some stacks start up data on another channel */
};
static int isFinalResponseSuccess(const char *line)
{
    size_t i;

    for (i = 0 ; i < NUM_ELEMS(s_finalResponsesSuccess) ; i++) {
        if (strStartsWith(line, s_finalResponsesSuccess[i])) {
            return 1;
        }
    }

    return 0;
}

#if 0
/**
 * returns 1 if line is a final response, either  error or success
 * See 27.007 annex B
 * WARNING: NO CARRIER and others are sometimes unsolicited
 */
static int isFinalResponse(const char *line)
{
    return isFinalResponseSuccess(line) || isFinalResponseError(line);
}
#endif

/**
 * returns 1 if line is the first line in (what will be) a two-line
 * SMS unsolicited response
 */
static const char * s_smsUnsoliciteds[] = {
    "+CMT:",
    "+CDS:",
    "+CBM:",
//wangbo add
    "+CMTI:",
    "+CMGR:",

};
static int isSMSUnsolicited(const char *line)
{
    size_t i;

    for (i = 0 ; i < NUM_ELEMS(s_smsUnsoliciteds) ; i++) {
        if (strStartsWith(line, s_smsUnsoliciteds[i])) {
            return 1;
        }
    }

    return 0;
}


/*[zhaopengfei@meigsmart-2020-05-22] add for get cell info list {*/
static const char * s_cellInfoPrefixList[] = {
"MCC:",
"MNC:",
"CELL ID:",
"PCI:",
"LAC ID:",
"eNBID:",
"PCELL eNBID:",
"BASIC_ID:",
"GLOBAL CELL ID:",
"PCELL GLOBAL CELL ID:",
"BAND:",
"BANDWIDTH:",
"DL CHANNEL:",
"UL CHANNEL:",
"RSSI:",
"RSRP:",
"RSRQ:",
"SINR:",
"UE CATEORY:",
"PATHLOSS:",
"SNR:",
"DUPLEX MODE:",
"CHANNEL:",
"RSCP:",
"BSIC:",
"PSC:",
"ECIO:",
"SIR:",
"SID:",
"NID:",
"BASIC ID:",
"SECTOR ID:",
"COLOR CODE:",
"IO:",
};
//fixed by zhaopf for const parameter
static int isCellInfoPrefix(const char *line)
{
    size_t i;

    for (i = 0 ; i < NUM_ELEMS(s_cellInfoPrefixList) ; i++) {
        if (strStartsWith(line, s_cellInfoPrefixList[i])) {
            return 1;
        }
    }

    return 0;
}
/*[zhaopengfei@meigsmart-2020-05-22] add for get cell info list }*/

/* begin: modified by dongmeirong for AT Ver adaption 20201217 */
static const char *s_sgswPrefixList[] = {
    "SoftwareVersion:",
    "InnerVersion:",
    "Build_date:",
};
static int isSgswPrefix(const char *line) {
    int i;
    for (i = 0; i < NUM_ELEMS(s_sgswPrefixList); i++) {
        if (strStartsWith(line, s_sgswPrefixList[i])) {
            return 1;
        }
    }
    return 0;
}
/* end: modified by dongmeirong for AT Ver adaption 20201217 */

/** assumes s_commandmutex is held */
static void handleFinalResponse(const char *line)
{
    sp_response->finalResponse = strdup(line);

    pthread_cond_signal(&s_commandcond);
}

static void handleUnsolicited(const char *line)
{
    if (s_unsolHandler != NULL) {
        s_unsolHandler(line, NULL);
    }
}

static void processLine(const char *line)
{
    pthread_mutex_lock(&s_commandmutex);
    if (sp_response == NULL) {
        /* no command pending */
        handleUnsolicited(line);
    } else if (isFinalResponseSuccess(line)) {
        sp_response->success = 1;
        handleFinalResponse(line);
    } else if (isFinalResponseError(line)) {
        sp_response->success = 0;
        handleFinalResponse(line);
    } else if (s_smsPDU != NULL && 0 == strcmp(line, "> ")) {
        // See eg. TS 27.005 4.3
        // Commands like AT+CMGS have a "> " prompt
        writeCtrlZ(s_smsPDU);
        s_smsPDU = NULL;
    } else switch (s_type) {
        case NO_RESULT:
            handleUnsolicited(line);
            break;
        case NUMERIC:
            if (sp_response->p_intermediates == NULL
                    && isdigit(line[0])
               ) {
                addIntermediate(line);
            } else {
                /* either we already have an intermediate response or
                   the line doesn't begin with a digit */
                handleUnsolicited(line);
            }
            break;
        case SINGLELINE:
            if (sp_response->p_intermediates == NULL
                    && strStartsWith (line, s_responsePrefix)
               ) {
                addIntermediate(line);
            } else {
                /* we already have an intermediate response */
                handleUnsolicited(line);
            }
            break;
        case MULTILINE:
            /*[zhaopengfei@meigsmart-2020-05-22] add for get cell info list {*/
            /* begin: modified by dongmeirong for AT Ver adaption 20201217 */
            if (strStartsWith (line, s_responsePrefix)
                || (0 == strcmp(s_responsePrefix, "+SGCELLINFOEX:") && isCellInfoPrefix(line))
                || (0 == strcmp(s_responsePrefix, "+SGSW") && isSgswPrefix(line))) {
            /* end: modified by dongmeirong for AT Ver adaption 20201217 */
            /*[zhaopengfei@meigsmart-2020-05-22] add for get cell info list }*/
                addIntermediate(line);
            } else {
                handleUnsolicited(line);
            }
            break;

        default: /* this should never be reached */
            RLOGE("Unsupported AT command type %d\n", s_type);
            handleUnsolicited(line);
            break;
        }

    pthread_mutex_unlock(&s_commandmutex);
}


/**
 * Returns a pointer to the end of the next line
 * special-cases the "> " SMS prompt
 *
 * returns NULL if there is no complete line
 */
static char * findNextEOL(char *cur)
{
    if (cur[0] == '>' && cur[1] == ' ' && cur[2] == '\0') {
        /* SMS prompt character...not \r terminated */
        return cur+2;
    }

    // Find next newline
    while (*cur != '\0' && *cur != '\r' && *cur != '\n') cur++;

    return *cur == '\0' ? NULL : cur;
}

/*[zhaopf@meigsmart-2020-1116]add for usb port retry open { */
#include "getdevinfo.h"
extern MODEM_INFO  curr_modem_info;
static void modem_info_init()
{
    int i;
    if (curr_modem_info.if_name != NULL) {
        free(curr_modem_info.if_name);
        curr_modem_info.if_name = NULL;
    }
    for(i = 0; i < NDIS_MULTI_NUM_MAX; i++) {
        if (curr_modem_info.vif_name[i] != NULL) {
            free(curr_modem_info.vif_name[i]);
            curr_modem_info.vif_name[i] = NULL;
        }
    }
    if (curr_modem_info.at_port_name != NULL) {
        free(curr_modem_info.at_port_name);
        curr_modem_info.at_port_name = NULL;
    }
    if (curr_modem_info.modem_port_name != NULL) {
        free(curr_modem_info.modem_port_name);
        curr_modem_info.modem_port_name = NULL;
    }
    return;
}

int retryOpenAtPort(){
     int fd, ret;
     int retry = 0;
     struct termios new_termios, old_termios;
     /*[zhaopf@meigsmart-2020-1217]add for modem connection state { */
    set_modem_state_connected(false);
    /*[zhaopf@meigsmart-2020-1217]add for modem connection state } */
/*yufeilong modify for cannot find at port after wake up from sleep 20230404 begin*/
    modem_info_init();
    while(1){
        RLOGI("try to find modem \n");
        if (get_modem_info(&curr_modem_info) > 0) {
            RLOGI("found it \n");
            if(curr_modem_info.at_port_name != NULL) {
                break;
            } else {
                RLOGI("---> didn't find at port \n");
                sleep(1);
                continue;
            }
         } else {
             modem_info_init();
             usleep(800*1000);
         }

    }
/*yufeilong modify for cannot find at port after wake up from sleep 20230404 end*/
     fd = open (curr_modem_info.at_port_name, O_RDWR);
     if(fd < 0) {
         RLOGI("%s cannot open, ....\n", curr_modem_info.at_port_name);
         return fd;
     }


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
        return 0;
    }
    if(s_onUsbReconnected){
        s_onUsbReconnected();
    }
    /*[zhaopf@meigsmart-2020-1217]add for modem connection state { */
    set_modem_state_connected(true);
    /*[zhaopf@meigsmart-2020-1217]add for modem connection state } */
    return fd;
}
/*[zhaopf@meigsmart-2020-1116]add for usb port retry open } */

/**
 * Reads a line from the AT channel, returns NULL on timeout.
 * Assumes it has exclusive read access to the FD
 *
 * This line is valid only until the next call to readline
 *
 * This function exists because as of writing, android libc does not
 * have buffered stdio.
 */
/*yufeilong modify for cannot  received sms after wake up from sleep 20230506 begin*/
void unsoclitedSMS() {
    int ret;
    pthread_attr_t attrSMS;
    pthread_t tid_report_sms;
    pthread_attr_init (&attrSMS);
    pthread_attr_setdetachstate(&attrSMS, PTHREAD_CREATE_DETACHED);

    ret = pthread_create(&tid_report_sms, &attrSMS, reportUnreadSMS, &attrSMS);

    if (ret < 0) {
       RLOGD("pthread_create failed");
    }

    return;
}
/*yufeilong modify for cannot  received sms after wake up from sleep 20230506 end*/
static const char *readline()
{
    ssize_t count;

    char *p_read = NULL;
    char *p_eol = NULL;
    char *ret;

    /* this is a little odd. I use *s_ATBufferCur == 0 to
     * mean "buffer consumed completely". If it points to a character, than
     * the buffer continues until a \0
     */
    if (*s_ATBufferCur == '\0') {
        /* empty buffer */
        s_ATBufferCur = s_ATBuffer;
        *s_ATBufferCur = '\0';
        p_read = s_ATBuffer;
    } else {   /* *s_ATBufferCur != '\0' */
        /* there's data in the buffer from the last read */

        // skip over leading newlines
        while (*s_ATBufferCur == '\r' || *s_ATBufferCur == '\n')
            s_ATBufferCur++;

        p_eol = findNextEOL(s_ATBufferCur);

        if (p_eol == NULL) {
            /* a partial line. move it up and prepare to read more */
            size_t len;

            len = strlen(s_ATBufferCur);

            memmove(s_ATBuffer, s_ATBufferCur, len + 1);
            p_read = s_ATBuffer + len;
            s_ATBufferCur = s_ATBuffer;
        }
        /* Otherwise, (p_eol !- NULL) there is a complete line  */
        /* that will be returned the while () loop below        */
    }

    while (p_eol == NULL) {
        if (0 == MAX_AT_RESPONSE - (p_read - s_ATBuffer)) {
            RLOGE("ERROR: Input line exceeded buffer\n");
            /* ditch buffer and start over again */
            s_ATBufferCur = s_ATBuffer;
            *s_ATBufferCur = '\0';
            p_read = s_ATBuffer;
        }

        do {
            count = read(s_fd, p_read,
                         MAX_AT_RESPONSE - (p_read - s_ATBuffer));
        } while (count < 0 && errno == EINTR);

        if (count > 0) {
            AT_DUMP( "<< ", p_read, count );

            p_read[count] = '\0';

            // skip over leading newlines
            while (*s_ATBufferCur == '\r' || *s_ATBufferCur == '\n')
                s_ATBufferCur++;

            p_eol = findNextEOL(s_ATBufferCur);
            p_read += count;
        } else if (count <= 0) {
            /* read error encountered or EOF reached */
            if(count == 0) {
                RLOGD("atchannel: EOF reached");
                /*[zhaopf@meigsmart-2020-11-17]add for usb reconnection after wakeup { */
#ifdef KEEP_ALIVE_WHEN_MODEM_LOST
/*[zhaopf@meigsmart-2020-1120]when screen is on, no reconnection { */
               if(1 == s_screen_state) {
                   RLOGI("screen is on, do nothing\n");
                   return NULL;
               }
/*[zhaopf@meigsmart-2020-1120]when screen is on, no reconnection } */

                sleep(2); //wait really lost
                close(s_fd);
                s_fd = -1;
                s_fd = retryOpenAtPort();
                if(s_fd > 0) {
                    RLOGD("retry ok\n");
/*yufeilong modify for cannot  received sms after wake up from sleep 20230404 begin*/
                    unsoclitedSMS();
                    RIL_requestTimedCallback (sendCallStateChanged, NULL, NULL);
/*yufeilong modify for cannot  received sms after wake up from sleep 20230404 end*/
                    continue;
                }
#endif
                /*[zhaopf@meigsmart-2020-11-17]add for usb reconnection after wakeup } */

            } else {
                RLOGD("atchannel: read error %s", strerror(errno));
            }
            return NULL;
        }
    }

    /* a full line in the buffer. Place a \0 over the \r and return */

    ret = s_ATBufferCur;
    *p_eol = '\0';
    s_ATBufferCur = p_eol + 1; /* this will always be <= p_read,    */
    /* and there will be a \0 at *p_read */

    RLOGD("AT< %s\n", ret);
    return ret;
}

/* begin: modified by dongmeirong for add network change listenner to CGREG 20210508 */
extern void initCxregStat();
static void onReaderClosed()
{
    if (s_onReaderClosed != NULL && s_readerClosed == 0) {

        pthread_mutex_lock(&s_commandmutex);

        s_readerClosed = 1;

        pthread_cond_signal(&s_commandcond);

        pthread_mutex_unlock(&s_commandmutex);

        s_onReaderClosed();
    }
    initCxregStat();
}
/* end: modified by dongmeirong for add network change listenner to CGREG 20210508 */


static void *readerLoop(void *arg __unused)
{
    for (;;) {
        const char * line;

        line = readline();

        if (line == NULL) {
            RLOGE("empty readline\n");
            break;
        }
        if(isSMSUnsolicited(line)) {
            char *line1;
            const char *line2;

            // The scope of string returned by 'readline()' is valid only
            // till next call to 'readline()' hence making a copy of line
            // before calling readline again.
            line1 = strdup(line);
            if(strStartsWith(line1,"+CDSI") || strStartsWith(line1,"+CMTI")) {
                line2=NULL;
            } else {
                line2 = readline();
                if (line2 == NULL) {
                    free(line1);
                    break;
                }
            }

            if (s_unsolHandler != NULL) {
                s_unsolHandler (line1, line2);
            }
            free(line1);
        } else {
            processLine(line);
        }
    }

    onReaderClosed();

    return NULL;
}

/**
 * Sends string s to the radio with a \r appended.
 * Returns AT_ERROR_* on error, 0 on success
 *
 * This function exists because as of writing, android libc does not
 * have buffered stdio.
 */
static int writeline (const char *s)
{
    size_t cur = 0;
    size_t len = strlen(s);
    ssize_t written;

    if (s_fd < 0 || s_readerClosed > 0) {
        return AT_ERROR_CHANNEL_CLOSED;
    }

    RLOGD("AT> %s\n", s);

    AT_DUMP( ">> ", s, strlen(s) );

    /* the main string */
    while (cur < len) {
        do {
            written = write (s_fd, s + cur, len - cur);
        } while (written < 0 && errno == EINTR);

        if (written < 0) {
            return AT_ERROR_GENERIC;
        }

        cur += written;
    }

    /* the \r  */

    do {
        written = write (s_fd, "\r" , 1);
    } while ((written < 0 && errno == EINTR) || (written == 0));

    if (written < 0) {
        return AT_ERROR_GENERIC;
    }

    return 0;
}
static int writeCtrlZ (const char *s)
{
    size_t cur = 0;
    size_t len = strlen(s);
    ssize_t written;

    //wangbo add
//char end = '0x1A';
//char end2 = '0x001A';
//const char end='0x1A';


    if (s_fd < 0 || s_readerClosed > 0) {
        return AT_ERROR_CHANNEL_CLOSED;
    }

    RLOGD("AT> %s^Z\n", s);

    AT_DUMP( ">* ", s, strlen(s) );

    /* the main string */
    while (cur < len) {
        do {
            //written = write (s_fd, s + cur, len - cur);
            written = write (s_fd, s + cur  , len - cur);

            //RLOGD("wangbo write AT> %s^Z, 032,cur =%d ,written %d,errno =%d \n", s,cur,written,errno);

        } while (written < 0 && errno == EINTR);

        if (written < 0) {
            return AT_ERROR_GENERIC;
        }

        cur += written;
    }

    /* the ^Z  */

    do {
//        written = write (s_fd, "\r" , 1);
//        written = write (s_fd, "\n" , 1);

        written = write (s_fd, "\032" , 1);

        //   written = write (s_fd, "0x001A" , 1);
        //written = write (s_fd, '0x1A' , 1);
//       written = write (s_fd, end , 1);

        RLOGD("write AT> %s^Z, 032,written %d,errno =%d \n", s,written,errno);
    } while ((written < 0 && errno == EINTR) || (written == 0));

    if (written < 0) {
        return AT_ERROR_GENERIC;
    }

    return 0;
}

static void clearPendingCommand()
{
    if (sp_response != NULL) {
        at_response_free(sp_response);
    }

    sp_response = NULL;
    s_responsePrefix = NULL;
    s_smsPDU = NULL;
}


/**
 * Starts AT handler on stream "fd'
 * returns 0 on success, -1 on error
 */
int at_open(int fd, ATUnsolHandler h)
{
    int ret;
    pthread_attr_t attr;

    s_fd = fd;
    s_unsolHandler = h;
    s_readerClosed = 0;

    s_responsePrefix = NULL;
    s_smsPDU = NULL;
    sp_response = NULL;

    pthread_attr_init (&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    ret = pthread_create(&s_tid_reader, &attr, readerLoop, &attr);

    if (ret < 0) {
        perror ("pthread_create");
        return -1;
    }


    return 0;
}

/*[zhaopf@meigsmart-2020-11-17]add for usb reconnection { */
typedef void (*usb_reconnected_callback) (void);
void at_set_on_usb_reconnected(void (*onUsbReconnected)(void)){

    s_onUsbReconnected = onUsbReconnected;
}
/*[zhaopf@meigsmart-2020-11-17]add for usb reconnection } */

/* FIXME is it ok to call this from the reader and the command thread? */
void at_close()
{
    if (s_fd >= 0) {
        close(s_fd);
    }
    s_fd = -1;

    pthread_mutex_lock(&s_commandmutex);

    s_readerClosed = 1;

    pthread_cond_signal(&s_commandcond);

    pthread_mutex_unlock(&s_commandmutex);

    /* the reader thread should eventually die */
}

static ATResponse * at_response_new()
{
    return (ATResponse *) calloc(1, sizeof(ATResponse));
}

void at_response_free(ATResponse *p_response)
{
    ATLine *p_line;

    if (p_response == NULL) return;

    p_line = p_response->p_intermediates;

    while (p_line != NULL) {
        ATLine *p_toFree;

        p_toFree = p_line;
        p_line = p_line->p_next;
        if (p_toFree->line != NULL) {
            free(p_toFree->line);
            p_toFree->line = NULL;
        }
        if (p_toFree != NULL) {
            free(p_toFree);
            p_toFree = NULL;
        }
    }

    free (p_response->finalResponse);
/*yufeilong modify for crash 20230404 begin*/
    p_response->finalResponse = NULL;
    free (p_response);
    p_response = NULL;
/*yufeilong modify for crash 20230404 end*/
}

/**
 * The line reader places the intermediate responses in reverse order
 * here we flip them back
 */
static void reverseIntermediates(ATResponse *p_response)
{
    ATLine *pcur,*pnext;

    pcur = p_response->p_intermediates;
    p_response->p_intermediates = NULL;

    while (pcur != NULL) {
        pnext = pcur->p_next;
        pcur->p_next = p_response->p_intermediates;
        p_response->p_intermediates = pcur;
        pcur = pnext;
    }
}

/**
 * Internal send_command implementation
 * Doesn't lock or call the timeout callback
 *
 * timeoutMsec == 0 means infinite timeout
 */

static int at_send_command_full_nolock (const char *command, ATCommandType type,
                                        const char *responsePrefix, const char *smspdu,
                                        long long timeoutMsec, ATResponse **pp_outResponse)
{
    int err = 0;
    struct timespec ts;

    if(sp_response != NULL) {
        err = AT_ERROR_COMMAND_PENDING;
        goto error;
    }

    err = writeline (command);

    if (err < 0) {
        goto error;
    }

    s_type = type;
    s_responsePrefix = responsePrefix;
    s_smsPDU = smspdu;
    sp_response = at_response_new();
/*yufeilong modify for crash 20230404 begin*/
    if (sp_response == NULL) {
        goto error;
    }
/*yufeilong modify for crash 20230404 end*/
    if (timeoutMsec != 0) {
        setTimespecRelative(&ts, timeoutMsec);
    }

    while (sp_response->finalResponse == NULL && s_readerClosed == 0) {
        if (timeoutMsec != 0) {
            err = pthread_cond_timedwait(&s_commandcond, &s_commandmutex, &ts);
        } else {
            err = pthread_cond_wait(&s_commandcond, &s_commandmutex);
        }

        if (err == ETIMEDOUT) {
            err = AT_ERROR_TIMEOUT;
            goto error;
        }
    }
/*yufeilong modify for crash 20230404 begin*/
    if ((pp_outResponse == NULL) && (sp_response != NULL)) {
/*yufeilong modify for crash 20230404 end*/
        at_response_free(sp_response);
    } else {
        /* line reader stores intermediate responses in reverse order */
        reverseIntermediates(sp_response);
        *pp_outResponse = sp_response;
    }

    sp_response = NULL;

    if(s_readerClosed > 0) {
        err = AT_ERROR_CHANNEL_CLOSED;
        goto error;
    }

    err = 0;
error:
    clearPendingCommand();

    return err;
}

/**
 * Internal send_command implementation
 *
 * timeoutMsec == 0 means infinite timeout
 */
static int at_send_command_full (const char *command, ATCommandType type,
                                 const char *responsePrefix, const char *smspdu,
                                 long long timeoutMsec, ATResponse **pp_outResponse)
{
    int err;

    if (0 != pthread_equal(s_tid_reader, pthread_self())) {
        /* cannot be called from reader thread */
        return AT_ERROR_INVALID_THREAD;
    }
/*[zhaopengfei@meigsmart-2020-05-22] improve at cmd mutex {*/
    pthread_mutex_lock(&s_at_commandmutex);
    pthread_mutex_lock(&s_commandmutex);

    err = at_send_command_full_nolock(command, type,
                                      responsePrefix, smspdu,
                                      timeoutMsec, pp_outResponse);

    pthread_mutex_unlock(&s_commandmutex);
    pthread_mutex_unlock(&s_at_commandmutex);
/*[zhaopengfei@meigsmart-2020-05-22] improve at cmd mutex }*/

    if (err == AT_ERROR_TIMEOUT && s_onTimeout != NULL) {
        /*Modify by zhaopengfei for unisoc modem at wait 40s one time 2023/01/16 Begin */
        if(curr_modem_info.info.sltn_type != UNISOC) {
            /*begin: added by yufeilong for modify send at no response 20220914 */
            RLOGD("at timeout ,try send AT:%s again\n",command );
            pthread_mutex_lock(&s_at_commandmutex);
            pthread_mutex_lock(&s_commandmutex);
            err = at_send_command_full_nolock(command, type,
                                      responsePrefix, smspdu,
                                      timeoutMsec, pp_outResponse);
            pthread_mutex_unlock(&s_commandmutex);
            pthread_mutex_unlock(&s_at_commandmutex);
            if (err == AT_ERROR_TIMEOUT && s_onTimeout != NULL) {
                s_onTimeout();
            }
            /*end: added by yufeilong for modify send at no response 20220914 */
        } else {
             s_onTimeout();
        }
        /*Modify by zhaopengfei for unisoc modem at wait 40s 2023/01/16 End */
    }

    return err;
}


/**
 * Issue a single normal AT command with no intermediate response expected
 *
 * "command" should not include \r
 * pp_outResponse can be NULL
 *
 * if non-NULL, the resulting ATResponse * must be eventually freed with
 * at_response_free
 */
int at_send_command (const char *command, ATResponse **pp_outResponse)
{
    int err;

    err = at_send_command_full (command, NO_RESULT, NULL,
                                NULL, AT_COMMOND_TIMEOUT_MSEC, pp_outResponse);

    return err;
}


int at_send_command_singleline (const char *command,
                                const char *responsePrefix,
                                ATResponse **pp_outResponse)
{
    int err;

    err = at_send_command_full (command, SINGLELINE, responsePrefix,
                                NULL, AT_COMMOND_TIMEOUT_MSEC, pp_outResponse);

    if (err == 0 && pp_outResponse != NULL
            && (*pp_outResponse)->success > 0
            && (*pp_outResponse)->p_intermediates == NULL
       ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}

/*[zhaopf@meigsmart-2020-0716]waiting without timeout { */
int at_send_command_singleline_wait (const char *command,
                                const char *responsePrefix,
                                ATResponse **pp_outResponse)
{
    int err;

    err = at_send_command_full (command, SINGLELINE, responsePrefix,
                                NULL, 0, pp_outResponse);

    if (err == 0 && pp_outResponse != NULL
            && (*pp_outResponse)->success > 0
            && (*pp_outResponse)->p_intermediates == NULL
       ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}
/*[zhaopf@meigsmart-2020-0716]waiting without timeout } */

int at_send_command_numeric (const char *command,
                             ATResponse **pp_outResponse)
{
    int err;

    err = at_send_command_full (command, NUMERIC, NULL,
                                NULL, AT_COMMOND_TIMEOUT_MSEC, pp_outResponse);

    if (err == 0 && pp_outResponse != NULL
            && (*pp_outResponse)->success > 0
            && (*pp_outResponse)->p_intermediates == NULL
       ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}


int at_send_command_sms (const char *command,
                         const char *pdu,
                         const char *responsePrefix,
                         ATResponse **pp_outResponse)
{
    int err;

    err = at_send_command_full (command, SINGLELINE, responsePrefix,
                                pdu, AT_COMMOND_TIMEOUT_MSEC, pp_outResponse);

    if (err == 0 && pp_outResponse != NULL
            && (*pp_outResponse)->success > 0
            && (*pp_outResponse)->p_intermediates == NULL
       ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}

int at_send_command_sms1 (const char *command,
                          const char *pdu,
                          const char *responsePrefix,
                          ATResponse **pp_outResponse)
{
    int err;

    err = at_send_command_full (command, SINGLELINE, responsePrefix,
                                pdu, AT_COMMOND_TIMEOUT_MSEC, pp_outResponse);

    if (err == 0 && pp_outResponse != NULL
            && (*pp_outResponse)->success > 0
            && (*pp_outResponse)->p_intermediates == NULL
       ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}


int at_send_command_multiline (const char *command,
                               const char *responsePrefix,
                               ATResponse **pp_outResponse)
{
    int err;

    err = at_send_command_full (command, MULTILINE, responsePrefix,
                                NULL, AT_COMMOND_TIMEOUT_MSEC, pp_outResponse);

    return err;
}


/** This callback is invoked on the command thread */
void at_set_on_timeout(void (*onTimeout)(void))
{
    s_onTimeout = onTimeout;
}

/**
 *  This callback is invoked on the reader thread (like ATUnsolHandler)
 *  when the input stream closes before you call at_close
 *  (not when you call at_close())
 *  You should still call at_close()
 */

void at_set_on_reader_closed(void (*onClose)(void))
{
    s_onReaderClosed = onClose;
}


/**
 * Periodically issue an AT command and wait for a response.
 * Used to ensure channel has start up and is active
 */

int at_handshake()
{
    int i;
    int err = 0;

    if (0 != pthread_equal(s_tid_reader, pthread_self())) {
        /* cannot be called from reader thread */
        return AT_ERROR_INVALID_THREAD;
    }

    pthread_mutex_lock(&s_commandmutex);


    for (i = 0 ; i < HANDSHAKE_RETRY_COUNT ; i++) {
        /* some stacks start with verbose off */
        err = at_send_command_full_nolock ("ATE0Q0V1", NO_RESULT,
                                           NULL, NULL, HANDSHAKE_TIMEOUT_MSEC, NULL);

        if (err == 0) {
            break;
        }
    }

    if (err == 0) {
        /* pause for a bit to let the input buffer drain any unmatched OK's
           (they will appear as extraneous unsolicited responses) */

        sleepMsec(HANDSHAKE_TIMEOUT_MSEC);
    }

    pthread_mutex_unlock(&s_commandmutex);

    return err;
}

/**
 * Returns error code from response
 * Assumes AT+CMEE=1 (numeric) mode
 */
AT_CME_Error at_get_cme_error(const ATResponse *p_response)
{
    int ret;
    int err;
    char *p_cur;

    if (p_response->success > 0) {
        return CME_SUCCESS;
    }

    if (p_response->finalResponse == NULL
            || !strStartsWith(p_response->finalResponse, "+CME ERROR:")
       ) {
        return CME_ERROR_NON_CME;
    }

    p_cur = p_response->finalResponse;
    err = at_tok_start(&p_cur);

    if (err < 0) {
        return CME_ERROR_NON_CME;
    }

    err = at_tok_nextint(&p_cur, &ret);

    if (err < 0) {
        return CME_ERROR_NON_CME;
    }

    return (AT_CME_Error) ret;
}

