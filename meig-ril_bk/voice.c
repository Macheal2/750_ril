/*voice*/

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
#include "voice.h"
#include <utils/Log.h>
#include "getdevinfo.h"
//<!--[ODM][CLCC] gaoyunlai@forgechina.com.cn 20150506 modified for can not get the status of call when another hang up in call.
#define POLL_CALL_STATE
//end-->
/*zhangqingyun add 2022 0512 start */
extern MODEM_INFO curr_modem_info;
/*zhangqingyun add 2022 0522 end*/
static const struct timeval TIMEVAL_CALLSTATEPOLL = {0,500000};
extern int cur_oper;
int voice_handover_flag = 0;

/*called by callFromCLCCLine()*/
static int clccStateToRILState(int state, RIL_CallState *p_state)
{
    switch(state) {
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

/**
 * Note: directly modified line and has *p_call point directly into
 * modified line
 * called by requestGetCurrentCalls()
 */
int callFromCLCCLine(char *line, RIL_Call *p_call)
{
    //+CLCC: 1,0,2,0,0,\"+18005551212\",145
    //     index,isMT,state,mode,isMpty(,number,TOA)?

    int err;
    int state;
    int mode;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(p_call->index));
    if (err < 0) goto error;

    err = at_tok_nextbool(&line, &(p_call->isMT));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &state);
    if (err < 0) goto error;

    err = clccStateToRILState(state, &(p_call->state));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &mode);
    if (err < 0) goto error;
/*yufeilong adapt for SRM810 voice 20221123 begin*/
    p_call->isVoice = (mode == 0) || (mode == 3);
/*yufeilong adapt for SRM810 voice 20221123 end*/
    err = at_tok_nextbool(&line, &(p_call->isMpty));
    if (err < 0) goto error;

    if (at_tok_hasmore(&line)) {
        err = at_tok_nextstr(&line, &(p_call->number));

        /* tolerate null here */
        if (err < 0)
            return 0;
        // Some lame implementations return strings
        // like "NOT AVAILABLE" in the CLCC line
        if (p_call->number != NULL
                && 0 == strspn(p_call->number, "+0123456789")) {
            p_call->number = NULL;
        }
        err = at_tok_nextint(&line, &p_call->toa);
        if (err < 0) goto error;
    }
    return 0;

error:
    RLOGD("invalid CLCC line\n");
    return -1;
}


/*called by requestGetCurrentCalls()*/
void sendCallStateChanged(void *param)
{
    RIL_onUnsolicitedResponse (
        RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED,
        NULL, 0);
}

void requestGetCurrentCalls(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    int err;
    ATResponse *p_response;
    ATLine *p_cur;
    int countCalls;
    int countValidCalls;
    RIL_Call *p_calls;
    RIL_Call **pp_calls;
    int i;
    int needRepoll = 0;

#ifdef WORKAROUND_ERRONEOUS_ANSWER
    int prevIncomingOrWaitingLine;

    prevIncomingOrWaitingLine = s_incomingOrWaitingLine;
    s_incomingOrWaitingLine = -1;
#endif /*WORKAROUND_ERRONEOUS_ANSWER*/


//wangbo debug

    RLOGD("requestGetCurrentCalls --------------------------> start ");

    err = at_send_command_multiline ("AT+CLCC", "+CLCC:", &p_response);

    if (err != 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
        return;
    }

    /* count the calls */
    for (countCalls = 0, p_cur = p_response->p_intermediates
                                 ; p_cur != NULL; p_cur = p_cur->p_next) {
        countCalls++;
    }

    /* yes, there's an array of pointers and then an array of structures */

    pp_calls = (RIL_Call **)alloca(countCalls * sizeof(RIL_Call *));
    p_calls = (RIL_Call *)alloca(countCalls * sizeof(RIL_Call));
    memset (p_calls, 0, countCalls * sizeof(RIL_Call));

    /* init the pointer array */
    for(i = 0; i < countCalls ; i++) {
        pp_calls[i] = &(p_calls[i]);
    }

    for (countValidCalls = 0, p_cur = p_response->p_intermediates
                                      ; p_cur != NULL; p_cur = p_cur->p_next) {
        err = callFromCLCCLine(p_cur->line, p_calls + countValidCalls);

        if (err != 0) {
            continue;
        }

//<!--[ODM][CLCC] ton.wu@forgechina.com.cn 20150126 , isDataAllowed=flase when use 4G SIM card
        RLOGD("requestGetCurrentCalls p_calls[%d].isVoice=%d",
              countValidCalls, p_calls[countValidCalls].isVoice );
        if(p_calls[countValidCalls].isVoice == false) {
            continue;
        }
//end-->
#ifdef WORKAROUND_ERRONEOUS_ANSWER
        if (p_calls[countValidCalls].state == RIL_CALL_INCOMING
                || p_calls[countValidCalls].state == RIL_CALL_WAITING
           ) {
            s_incomingOrWaitingLine = p_calls[countValidCalls].index;
        }
#endif /*WORKAROUND_ERRONEOUS_ANSWER*/

        if (p_calls[countValidCalls].state != RIL_CALL_ACTIVE
                && p_calls[countValidCalls].state != RIL_CALL_HOLDING) {
            needRepoll = 1;
        }

        countValidCalls++;
    }
#ifdef WORKAROUND_ERRONEOUS_ANSWER
    // Basically:
    // A call was incoming or waiting
    // Now it's marked as active
    // But we never answered it
    //
    // This is probably a bug, and the call will probably
    // disappear from the call list in the next poll
    if (prevIncomingOrWaitingLine >= 0
            && s_incomingOrWaitingLine < 0
            && s_expectAnswer == 0
       ) {
        for (i = 0; i < countValidCalls ; i++) {

            if (p_calls[i].index == prevIncomingOrWaitingLine
                    && p_calls[i].state == RIL_CALL_ACTIVE
                    && s_repollCallsCount < REPOLL_CALLS_COUNT_MAX
               ) {
                RLOGD(
                    "Hit WORKAROUND_ERRONOUS_ANSWER case."
                    " Repoll count: %d\n", s_repollCallsCount);
                s_repollCallsCount++;
                goto error;
            }
        }
    }

    s_expectAnswer = 0;
    s_repollCallsCount = 0;
#endif /*WORKAROUND_ERRONEOUS_ANSWER*/

    RIL_onRequestComplete(t, RIL_E_SUCCESS, pp_calls,countValidCalls * sizeof (RIL_Call *));
//RIL_onRequestComplete(t, RIL_E_SUCCESS, p_calls,sizeof (RIL_Call ));
    at_response_free(p_response);

#ifdef POLL_CALL_STATE
    if (countValidCalls)    // We don't seem to get a "NO CARRIER" message from
        // smd, so we're forced to poll until the call ends.
#else
    if (needRepoll)
#endif
    {
        RIL_requestTimedCallback (sendCallStateChanged, NULL, &TIMEVAL_CALLSTATEPOLL);
    }


//wangbo
    RLOGD("requestGetCurrentCalls --------------------------> end");



    return;
#ifdef WORKAROUND_ERRONEOUS_ANSWER
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
#endif
}

void ReportIncomingCalls()
{
    int err;
    int countCalls;
    int countValidCalls;
    ATResponse *p_response = NULL;
    ATLine *p_cur;
    RIL_Call *p_calls;
    RIL_Call **pp_calls;

    RLOGD("ReportIncomingCalls --------------------------> start ");
    err = at_send_command_multiline ("AT+CLCC", "+CLCC:", &p_response);
    if (err != 0 || p_response->success == 0) {
        return;
    }

    /* count the calls */
    for (countCalls = 0, p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next) {
        countCalls++;
    }

    /* yes, there's an array of pointers and then an array of structures */
    p_calls = (RIL_Call *)alloca(countCalls * sizeof(RIL_Call));
    memset (p_calls, 0, countCalls * sizeof(RIL_Call));

    for (countValidCalls = 0, p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next) {
        err = callFromCLCCLine(p_cur->line, p_calls + countValidCalls);

        if (err != 0) {
            continue;
        }

        RLOGD("requestGetCurrentCalls p_calls[%d].isVoice=%d ,p_calls[%d].state=%d",
            countValidCalls, p_calls[countValidCalls].isVoice, countValidCalls, p_calls[countValidCalls].state);
        if(p_calls[countValidCalls].isVoice == false) {
            continue;
        }


        if (p_calls[countValidCalls].state == RIL_CALL_INCOMING) {
            RLOGD("call incoming");
            RIL_requestTimedCallback (sendCallStateChanged, NULL, NULL);
        }

        countValidCalls++;
    }
    return;
}
int meig_at_cops(int response[4])
{
    int err;
    ATResponse *p_response = NULL;
    char *line;
    char *oper;

    response[0] = response[1] = response[2] = response[3] = 0;

    err = at_send_command_singleline("AT+COPS=3,2;+COPS?", "+COPS:", &p_response);
    if ((err < 0) ||  (p_response == NULL) || (p_response->success == 0))
        goto error;

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

//+COPS:<mode>[,<format>[,<oper>][,<Act>]]
    err = at_tok_nextint(&line, &response[0]);
    if (err < 0) goto error;

    if (!at_tok_hasmore(&line)) goto error;

    err = at_tok_nextint(&line, &response[1]);
    if (err < 0) goto error;

    if (!at_tok_hasmore(&line)) goto error;

    err = at_tok_nextstr(&line, &oper);
    if (err < 0) goto error;
    response[2] = atoi(oper);

    if (!at_tok_hasmore(&line)) goto error;

    err = at_tok_nextint(&line, &response[3]);
    if (err < 0) goto error;

error:
    at_response_free(p_response);
    return response[3];
}


void requestDial(void *data, size_t datalen __unused, RIL_Token t)
{
    RIL_Dial *p_dial;
    char *cmd;
    const char *clir;
    int ret;
    int send_retry = 0;

    int cops_response[4] = {0};

    p_dial = (RIL_Dial *)data;

    switch (p_dial->clir) {
    case 1:
        clir = "I";
        break;  /*invocation*/
    case 2:
        clir = "i";
        break;  /*suppression*/
    default:
    case 0:
        clir = "";
        break;   /*subscription default*/
    }
    RLOGD("voice dial begin");


    meig_at_cops(cops_response);
    if(CHINA_TELECOM_OPER == cur_oper && curr_modem_info.info.at_version < AT_VERSION_2 && (curr_modem_info.info.sltn_type != HISI
/*yufeilong adapt for SLM770A voice dial 20230404 begin*/
        && curr_modem_info.info.sltn_type != ASR)) {
/*yufeilong adapt for SLM770A voice dial 20230404 end*/
        asprintf(&cmd, "AT+CDV=%s", p_dial->address);
        RLOGD("3GPP2 dail---> ");
    } else {
        asprintf(&cmd, "ATD%s%s;", p_dial->address, clir);
        RLOGD("3GPP dail---> ");
    }

//wangbo 2017/07/12 for cdma sms

//    asprintf(&cmd, "ATD%s%s;", p_dial->address, clir);

#if 0
    if ((ODM_CT_OPERATOR_3G == cur_oper) ||(ODM_CT_OPERATOR_4G == cur_oper)) {
        RLOGD("3GPP2 dail---> ");
        //wangbo 2017/08/05 add for norise
        at_send_command("AT+CLVL= 7", NULL);
        at_send_command("AT+CMIC= 6", NULL);


        asprintf(&cmd, "AT+CDV%s%s;", p_dial->address, clir);
    } else {
        RLOGD("3GPP dail---> ");
        //wangbo 2017/08/05 add for norise
        if(ODM_CU_OPERATOR == cur_oper) {
            at_send_command("AT+CLVL= 7", NULL);
            at_send_command("AT+CMIC= 4", NULL);
        }

        asprintf(&cmd, "ATD%s%s;", p_dial->address, clir);
    }
#endif

    ret = at_send_command(cmd, NULL);

    free(cmd);

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

void  requestGetMute(void *data, size_t datalen, RIL_Token t)
{
    int response = 0;
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response,sizeof(response));
}

void requestDTMFStart(void *data, size_t datalen __unused, RIL_Token t)
{
    char c = ((char *)data)[0];
    char *cmd;
	#ifdef MEIG_CTS_ENABLE
	RLOGD("run cts test ");
	#else
    at_send_command("AT+CMUT=1", NULL);
    asprintf(&cmd, "AT+VTS=%c", (int)c);
    at_send_command(cmd, NULL);

#if 0
    if(c=='*')
        at_send_command("AT+WFSH", NULL);
#endif
//  end-->
    free(cmd);
    #endif
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

void requestDTMFStop(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    #ifdef MEIG_CTS_ENABLE
    RLOGD("run cts test ");
	#else
	at_send_command("AT+CMUT=0", NULL);
	#endif
	RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

void requestDTMF(void *data, size_t datalen __unused, RIL_Token t)
{
    char c = ((char *)data)[0];
    char *cmd;
    asprintf(&cmd, "AT+VTS=%c", (int)c);
    at_send_command(cmd, NULL);
    free(cmd);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);

}

void requestSeparateConnection(void *data, size_t datalen __unused, RIL_Token t)
{
    char  cmd[12];
    int   party = ((int*)data)[0];

    // Make sure that party is in a valid range.
    // (Note: The Telephony middle layer imposes a range of 1 to 7.
    // It's sufficient for us to just make sure it's single digit.)
    if (party > 0 && party < 10) {
        sprintf(cmd, "AT+CHLD=2%d", party);
        at_send_command(cmd, NULL);
        RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    } else {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    }
}

void requestUDUB(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    /* user determined user busy */
    /* sometimes used: ATH */
    at_send_command("ATH", NULL);
    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

void requestConference(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    // 3GPP 22.030 6.5.5
    // "Adds a held call to the conversation"
    at_send_command("AT+CHLD=3", NULL);
    /* success or failure is ignored by the upper layer here.
         it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

void requestAnswer(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    at_send_command("ATA", NULL);
#ifdef WORKAROUND_ERRONEOUS_ANSWER
    s_expectAnswer = 1;
#endif  /* WORKAROUND_ERRONEOUS_ANSWER */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

void requestSwitchWaitingOrHoldingAndActive(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    // 3GPP 22.030 6.5.5
    // "Places all active calls (if any exist) on hold and accepts
    //  the other (held or waiting) call."
    at_send_command("AT+CHLD=2", NULL);

#ifdef WORKAROUND_ERRONEOUS_ANSWER
    s_expectAnswer = 1;
#endif /* WORKAROUND_ERRONEOUS_ANSWER */

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

void requestHangupForegroundResumeBackground(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    // 3GPP 22.030 6.5.5
    // "Releases all active calls (if any exist) and accepts
    //  the other (held or waiting) call."
    //at_send_command("AT+CHLD=1", NULL);
    //at_send_command("AT+CHUP", NULL);
    RLOGD("Forge cur oper=%d",cur_oper);
    if(CHINA_TELECOM_OPER == cur_oper && curr_modem_info.info.at_version < AT_VERSION_2 && curr_modem_info.info.sltn_type != ASR
/*yufeilong modify for SLM790 can not ring off 20230403 begin*/
        && curr_modem_info.info.sltn_type != HISI) {
/*yufeilong modify for SLM790 can not ring off 20230403 end*/
        at_send_command("AT+CHV", NULL);
        if(1 == voice_handover_flag) {
            //OnResumeLTENetwork();
            voice_handover_flag = 0;
        }
    } else {
        at_send_command("AT+CHUP", NULL);//modified by zte-zhaoming
    }

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

void requestHangupWaitingOrBackground(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    // 3GPP 22.030 6.5.5
    // "Releases all held calls or sets User Determined User Busy
    //  (UDUB) for a waiting call."
    //at_send_command("AT+CHLD=0", NULL);
    //at_send_command("AT+CHUP", NULL);
    RLOGD("Forge cur oper=%d",cur_oper);
    if(CHINA_TELECOM_OPER == cur_oper && curr_modem_info.info.at_version < AT_VERSION_2 && curr_modem_info.info.sltn_type != ASR
/*yufeilong modify for SLM790 can not ring off 20230403 begin*/
        && curr_modem_info.info.sltn_type != HISI) {
/*yufeilong modify for SLM790 can not ring off 20230403 end*/
        at_send_command("AT+CHV", NULL);
    } else {
        at_send_command("AT+CHUP", NULL);//modified by zte-zhaoming
    }

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

void requestHangup(void *data __unused, size_t datalen __unused, RIL_Token t)
{

    //int *p_line;
    int ret;
    //char *cmd;
    //p_line = (int *)data;

    // 3GPP 22.030 6.5.5
    // "Releases a specific active call X"

    //asprintf(&cmd, "AT+CHLD=1%d", p_line[0]);

    //#ifdef ZTE_MODIFY_BY_JOEY.MING
    //ret = at_send_command(cmd, NULL);
    RLOGD("Forge cur oper1=%d",cur_oper);
    if(CHINA_TELECOM_OPER == cur_oper && curr_modem_info.info.at_version < AT_VERSION_2 && curr_modem_info.info.sltn_type != ASR
/*yufeilong modify for SLM790 can not ring off 20230403 begin*/
        && curr_modem_info.info.sltn_type != HISI) {
/*yufeilong modify for SLM790 can not ring off 20230403 end*/
        ret = at_send_command("AT+CHV", NULL);
    } else {
        ret = at_send_command("AT+CHUP", NULL);
        ret = at_send_command("AT+CHV", NULL);  //[zhaopf@meigsmart-2022-0714]double assurance
    }

    //#endif

    //free(cmd);
    /* success or failure is ignored by the upper layer here.
    it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

/* added by zte-yuyang begin */
void  requestGetClir(void *data __unused, size_t datalen __unused, RIL_Token t)
{
    /** Gets current CLIR status
    * "data" is NULL
    * "response" is int *
    * ((int *)data)[0] is "n" parameter from TS 27.007 7.7
    * ((int *)data)[1] is "m" parameter from TS 27.007 7.7
    */
    int err;
    int *response[2];
    ATResponse *p_response;
    char* line;

    err = at_send_command_singleline("AT+CLIR?","+CLIR:",&p_response);
    if (err != 0 || p_response->success == 0)
        goto error;

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0)
        goto error;

    err = at_tok_nextint(&line, &response[0]);
    if (err < 0)
        goto error;

    err = at_tok_nextint(&line, &response[1]);
    if (err < 0)
        goto error;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
    at_response_free(p_response);
    return;

error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
    return;
}

void  requestSetClir(void *data, size_t datalen __unused, RIL_Token t)
{
    /**
     * "data" is int *
     * ((int *)data)[0] is "n" parameter from TS 27.007 7.7
     *
     * "response" is NULL
     */
    int err;
    char *cmd;
    asprintf(&cmd, "AT+CLIR=%d", ((int *)data)[0]);

    err = at_send_command(cmd,NULL);
    if (err < 0)
        goto error;
    free(cmd);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;

error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

void requestQueryCallWaiting(void *data, size_t datalen __unused, RIL_Token t)
{
    /**
    * "data" is const int *
    * ((const int *)data)[0] is the TS 27.007 service class to query.
    * "response" is a const int *
    * ((const int *)response)[0] is 0 for "disabled" and 1 for "enabled"
    *
    * If ((const int *)response)[0] is = 1, then ((const int *)response)[1]
    * must follow, with the TS 27.007 service class bit vector of services
    * for which call waiting is enabled.
    *
    * For example, if ((const int *)response)[0]  is 1 and
    * ((const int *)response)[1] is 3, then call waiting is enabled for data
    * and voice and disabled for everything else
    */
    int err;
    int i;
    int skip;
    ATLine *p_cur;
    int *response[2];
    char*cmd;
#define  SERVICE_NUMBER 5
    //const int SERVICE_NUMBER = 5;
    int response_enable[SERVICE_NUMBER] = {0};//0:disable;1:enable
    int response_class[SERVICE_NUMBER] = {0};//service class
    ATResponse *p_response = NULL;
    /* generally,the service_class is 2,it means data*/
    int service_class = ((const int *)data)[0];
    asprintf(&cmd,"AT+CCWA=1,%d",service_class);
    memset(response, 0, sizeof(response));

    err = at_send_command_multiline(cmd,"+CCWA:", &p_response);
    free(cmd);
    /* we expect 3 lines here:
    * +CCWA: 1,1
    * +CCWA: 1,2
    * +CCWA: 1,4
    */

    if (err != 0) goto error;

    for (i = 0, p_cur = p_response->p_intermediates
                        ; p_cur != NULL ; p_cur = p_cur->p_next, i++) {
        char *line = p_cur->line;
        err = at_tok_start(&line);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &response_enable[i]);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &response_class[i]);
        if (err < 0)
            goto error;
    }

    for(i = 0; i<SERVICE_NUMBER; i++) {
        if(response_enable[i] == 1 ) {
            *(response[0]) = 1;
            *(response[1]) += response_class[i];
        }

    }
    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
    at_response_free(p_response);
    return;

error:
    RLOGD("******** requestQueryCallWaiting is failed ********");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

void requestSetCallWaiting(void *data, size_t datalen __unused, RIL_Token t)
{
    /**
    * "data" is const int *
    * ((const int *)data)[0] is 0 for "disabled" and 1 for "enabled"
    * ((const int *)data)[1] is the TS 27.007 service class bit vector of
    *                           services to modify
    * "response" is NULL
    */
    int err = 0;
    char*cmd = NULL;
    int enable = ((const int *)data)[0];
    int service_class = ((const int *)data)[1];

    asprintf(&cmd,"AT+CCWA=%d,%d",enable,service_class);
    err = at_send_command(cmd,NULL);
    if (err < 0)
        goto error;
    free(cmd);
    RIL_onRequestComplete(t,RIL_E_SUCCESS,NULL,0);

error:
    RIL_onRequestComplete(t,RIL_E_GENERIC_FAILURE,NULL,0);
}

/* added by zte-yuyang end */



