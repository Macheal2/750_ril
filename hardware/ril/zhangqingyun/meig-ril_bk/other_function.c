/*otherfunction*/

/*when who why modified*/

#include <telephony/ril.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <alloca.h>
#include <getopt.h>
#include <sys/socket.h>
#include <cutils/sockets.h>
#include <cutils/properties.h>
#include <termios.h>

#define LOG_TAG "RIL"
#include "atchannel.h"
#include "at_tok.h"
#include "misc.h"
#include "ril_common.h"
#include "other_function.h"
/*[zhaopf@meigsmart-2020-1119]SRM815 do not use qcimi { */
#include "getdevinfo.h"
/*[zhaopf@meigsmart-2020-1119]SRM815 do not use qcimi } */
#include <utils/Log.h>

extern int cur_oper;
/*[zhaopf@meigsmart-2020-1119]SRM815 do not use qcimi { */
extern MODEM_INFO  curr_modem_info;
/*[zhaopf@meigsmart-2020-1119]SRM815 do not use qcimi } */

/* begin: added by dongmeirong for CIMI retry in case of ERROR 20210130 */
ATResponse *cimiAtCmd() {
    ATResponse *p_response = NULL;
    int err = -1;
    /* Sometimes CIMI returns error because of sim initialed slowly. We retry 10 times here.
    This will not postphone data call, if CIMI returns error, phone will not request SETUP_DATA_CALL. */
    int retry = 10;
    while (retry > 0) {
        /*[zhaopf@meigsmart-2020-1119]SRM815 do not use qcimi { */
        /* begin: modified by dongmeirong for AT Ver adaption 20201217 */
        //fix err by zhaopenfei 2022/09/05, only qcm modem support QCIMI
        if((QCM == curr_modem_info.info.sltn_type) && (curr_modem_info.info.at_version < AT_VERSION_2)) {
            at_response_free(p_response);
            err = at_send_command_numeric("AT+QCIMI", &p_response);
         }
        /* end: modified by dongmeirong for AT Ver adaption 20201217 */
        /*[zhaopf@meigsmart-2020-1119]SRM815 do not use qcimi { */
        if (err < 0 || p_response->success == 0) {
/*yufeilong modify crash issue 20230308 begin*/
            if (p_response != NULL) {
                at_response_free(p_response);
                p_response = NULL;
            }
/*yufeilong modify crash issue 20230308 end*/
            err = at_send_command_numeric("AT+CIMI", &p_response);
            if (err < 0 || p_response->success == 0) {
                retry--;
                usleep(500 * 1000); // sleep 500ms
                continue;
            }
        }
        break;
    }
/*yufeilong modify crash issue 20230308 begin*/
    if ((p_response != NULL) && (err < 0 || p_response->success == 0)) {
/*yufeilong modify crash issue 20230308 end*/
        at_response_free(p_response);
        p_response = NULL;
    }
    RLOGD("%s() leave, %d retry times remained.", __FUNCTION__, retry);
    return p_response;
}
/* end: added by dongmeirong for CIMI retry in case of ERROR 20210130 */

/* added by zte-yuyang begin */
void  requestSendUSSD(void *data , size_t datalen __unused, RIL_Token t)
{
    /**
     * RIL_REQUEST_SEND_USSD
     *
     * Send a USSD message
     *
     * If a USSD session already exists, the message should be sent in the
     * context of that session. Otherwise, a new session should be created.
     *
     * The network reply should be reported via RIL_UNSOL_ON_USSD
     *
     * Only one USSD session may exist at a time, and the session is assumed
     * to exist until:
     *   a) The android system invokes RIL_REQUEST_CANCEL_USSD
     *   b) The implementation sends a RIL_UNSOL_ON_USSD with a type code
     *      of "0" (USSD-Notify/no further action) or "2" (session terminated)
     *
     * "data" is a const char * containing the USSD request in UTF-8 format
     * "response" is NULL
     *
     * Valid errors:
     *  SUCCESS
     *  RADIO_NOT_AVAILABLE
     *  FDN_CHECK_FAILURE
     *  GENERIC_FAILURE
     *
     * See also: RIL_REQUEST_CANCEL_USSD, RIL_UNSOL_ON_USSD
     */

    const char *ussdRequest;
    ussdRequest = (char *)(data);
    int err;
    char *cmd;
    /*<dcs>: 3GPP TS 23.038 [25], we expect 0 is UTF-8*/
    /*zhangqingyun add for support ussd partial 2023-5-7 start*/
    asprintf(&cmd,"AT+CUSD=1,\"%s\",15",ussdRequest);
    /*zhangqingyun add for support ussd partial 2023-5-7 end*/
    err = at_send_command(cmd,NULL);

    if (err < 0 )
        goto error;

    free(cmd);

    RIL_onRequestComplete(t,RIL_E_SUCCESS,NULL,0);
    return;

error:
    RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
    return;

}
/* added by zte-yuyang end */

void requestCancelUSSD(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err = 0;
    err = at_send_command_numeric("AT+CUSD=2", &p_response);

    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    } else {
        RIL_onRequestComplete(t, RIL_E_SUCCESS,
                              p_response->p_intermediates->line, sizeof(char *));
    }
    at_response_free(p_response);

}

//[zhaopf@meigsmart-2021/05/10]modify for oem hook strings Begin
//[zhaopf@meigsmart-2021/05/10]modify for oem hook efs at strings Begin
void requestOemHookStrings(void *data, size_t datalen, RIL_Token t)
{
    int i,j = 0,  err, dataSize;
    const char ** cur;
    char *responseStr;
    long responseLen;
    char *line = NULL;
    ATResponse *p_response = NULL;
    bool bIsEfsAT = false;
    #define RESPONSE_LIST_COUNT    (6)
    ATResponse *p_responseList[RESPONSE_LIST_COUNT] = { NULL };
    char *p_responseStr[RESPONSE_LIST_COUNT] = { NULL };
    dataSize = (datalen / sizeof (char *));
    RLOGD("got OEM_HOOK_STRINGS: 0x%8p %lu, datasize=%d\n", data, (long)datalen, dataSize);
    if(dataSize > RESPONSE_LIST_COUNT){
         RLOGD("out of size, adjust to %d\n", RESPONSE_LIST_COUNT);
        dataSize = RESPONSE_LIST_COUNT;
    }

    for (i = dataSize, cur = (const char **)data ;
            i > 0 ; cur++, i --) {
        RLOGD("[%d]> '%s'", j, *cur);
        if(NULL != strstr(*cur, "NDISDUP")){
          RLOGD("not support ndisdup");
          goto error;
        }
        bIsEfsAT = false;
        //[zhaopf@meigsmart-2021/06/21] check if at valid Begin
        if((!strStartsWith(*cur,"at+")) &&
            (!strStartsWith(*cur,"AT+")) &&
            (!strStartsWith(*cur,"at$")) &&
            (!strStartsWith(*cur,"AT$")) &&
            (!strStartsWith(*cur,"at^")) &&
            (!strStartsWith(*cur,"AT^"))){
            RLOGD("not valid at cmd");
            goto error;
        }
        //[zhaopf@meigsmart-2021/06/21] check if at valid End
        p_response = NULL;

        if(strcasestr(*cur, "efsrw=0") != NULL){
            RLOGI("It's efs at");
            bIsEfsAT = true;
        }
        if(bIsEfsAT){
             err = at_send_command_singleline(*cur, "+EFSRW:", &p_response);
        } else {
             err = at_send_command(*cur,&p_response);
        }
        if(err < 0 || p_response->success == 0) {
            if(p_response != NULL && p_response->finalResponse != NULL ){
                RLOGD("Err finalResponse=%s\n", p_response->finalResponse);
                asprintf(&p_responseStr[j],"%s",p_response->finalResponse);
            } else {
                goto error;
            }
        } else {
            if(bIsEfsAT){
                line = p_response->p_intermediates->line;
                if(line != NULL) {
                    asprintf(&p_responseStr[j++],"%s",line);
                }
            }
            RLOGD("Succ finalResponse=%s\n", p_response->finalResponse);
            asprintf(&p_responseStr[j++],"%s",p_response->finalResponse);
        }
        at_response_free(p_response);

    }
    RIL_onRequestComplete(t, RIL_E_SUCCESS, p_responseStr, j*sizeof(char*));
    return;
error:

    RLOGE
    ("requestOemHookStrings must never return an error when radio is on");
    at_response_free(p_response);
    RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
    return;
}
//[zhaopf@meigsmart-2021/05/10]modify for oem hook efs at strings Begin
//[zhaopf@meigsmart-2021/05/10]modify for oem hook strings End

int myIsspace(char c)
{
    if(c =='\t'|| c =='\n'|| c ==' ')
        return 1;
    else
        return 0;
}
static void skipWhiteSpace(char **p_cur)
{
    if (*p_cur == NULL) return;

    while (**p_cur != '\0' && myIsspace(**p_cur)) {
        (*p_cur)++;
    }
}


void requestBasebandVersion(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err = 0;
    char *line;
    char *cmd = NULL;
    /*zhaopf@meigsmart-2021-0603 add for hangsheng custoemd baseband version begin */
    #define MAX_BASEBAND_VER_SIZE           (128)
    /*zhaopf@meigsmart-2021-0603 add for hangshengcustoemd  baseband version end */

    err = at_send_command_singleline("AT+SGSW","InnerVersion:",&p_response);
    if(err<0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    } else {
        line = p_response->p_intermediates->line;

        at_tok_start(&line);
        skipWhiteSpace(&line);
        /*zhaopf@meigsmart-2021-0603 add for hangsheng custoemd baseband version begin */
        if(NULL != strstr(BUILD_CUSTOMER, "HANGSHENG")){

            char modifiedVer[MAX_BASEBAND_VER_SIZE] = { 0x0 };
            char* delim = "_";
            int count = 0;
            char *p = NULL;

            strcat(modifiedVer, strtok(line, delim));
            while(( p = strtok(NULL, delim))){
                count++;
                if(count == 1 || count == 2){
                    continue;
                }
                strcat(modifiedVer, "_");
                 strcat(modifiedVer, p);
            }
            asprintf(&cmd, "%s", modifiedVer);
        } else {
            asprintf(&cmd, "MG_%s", line);
        }
        RLOGD("report version:%s\n", cmd);
       /*zhaopf@meigsmart-2021-0603 add for hangsheng custoemd baseband version end */
        RIL_onRequestComplete(t, RIL_E_SUCCESS, cmd, sizeof(char *));
        free(cmd);
    }
    at_response_free(p_response);

}


void requestGetIMEI(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err = 0;
    err = at_send_command_numeric("AT+GSN", &p_response);

    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    } else {
        RIL_onRequestComplete(t, RIL_E_SUCCESS,
                              p_response->p_intermediates->line, sizeof(char *));
    }
    at_response_free(p_response);
}

void requestGetIMEISV(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err = 0;
    char imeisv_str[3];
    int len;
    err = at_send_command_numeric("AT+GSN", &p_response);

    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    } else {
        len = strlen(p_response->p_intermediates->line);
        imeisv_str[0] = p_response->p_intermediates->line[len-2];
        imeisv_str[1] = p_response->p_intermediates->line[len-1];
        imeisv_str[2] = 0;
        RIL_onRequestComplete(t, RIL_E_SUCCESS,imeisv_str, sizeof(char *));
    }
    at_response_free(p_response);
}
//20170418 modify CIMI and QCIMI order
void requestGetIMSI(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err = 0;
    char *line=NULL;
    /* begin: added by dongmeirong for CIMI retry in case of ERROR 20210130 */
    p_response = cimiAtCmd();
    if (p_response == NULL) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }
    line = p_response->p_intermediates->line;
    RIL_onRequestComplete(t, RIL_E_SUCCESS, p_response->p_intermediates->line, sizeof(char *));
    /* end: added by dongmeirong for CIMI retry in case of ERROR 20210130 */
    at_response_free(p_response);
}

/* added by zte-yuyang begin */
void requestQueryClip(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    /**
    * Queries the status of the CLIP supplementary service
    *
    * (for MMI code "*#30#")
    *
    * "data" is NULL
    * "response" is an int *
    * (int *)response)[0] is 1 for "CLIP provisioned"
    *                           and 0 for "CLIP not provisioned"
    *                           and 2 for "unknown, e.g. no network etc"
    */

    int err;
    int* response[1];

    ATResponse *p_response = NULL;
    char *line;
    err = at_send_command_singleline("AT+CLIP?","+CLIP:",&p_response);
    if(err < 0 ||p_response->success == 0)
        goto error;
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0)
        goto error;
    err = at_tok_nextint(&line,response[0]);
    if(err < 0)
        goto error;

    RIL_onRequestComplete(t,RIL_E_SUCCESS, response, sizeof(response));
    at_response_free(p_response);
    return;

error:
    RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
    at_response_free(p_response);

}

/* added by zte-yuyang end */







