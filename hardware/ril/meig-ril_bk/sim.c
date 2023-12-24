/*sim*/
/*when who why modified*/
/*021207 gaojing add get the pin retry count */

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
#include "sim.h"
#include <utils/Log.h>
#include "getdevinfo.h"

extern int cur_oper;
static int sim_pin_retry = 3;     //number of retries remaining for pin
static int sim_puk_retry = 10;    //number of retries remaining for puk
static struct timeval TIMEVAL_DELAYINIT = {0,0}; // will be set according to property value

/* begin: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/
extern const struct timeval TIMEVAL_1;
extern const struct timeval TIMEVAL_60;
/*zhangqingyun add support adn record load 2022 04 29 start*/
extern MODEM_INFO curr_modem_info;
/*zhangqingyun add support adn record load 2022 04 29 end*/
#ifdef POLL_SIM_ABSENT_RESET_MODULE
static int s_detect_sim_count = 3;
extern SIM_Status getSIMStatus();
#endif
/* endif: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/

#if 1 //usim -> sim
typedef struct __TLV {
    unsigned char tag;
    unsigned char len;
    unsigned char data[0];
} TLV;

static int hexCharToInt(char c)
{
    if (c >= '0' && c <= '9') return (c - '0');
    if (c >= 'A' && c <= 'F') return (c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return (c - 'a' + 10);
    return 0;
}

static int hexStringToBytes(const char * s, unsigned char *d)
{
    int sz, i;

    if (!s || !strlen(s))
        return 0;

    sz = strlen(s) / 2;

    for (i = 0; i < sz ; i++) {
        d[i] = (unsigned char) ((hexCharToInt(s[i*2 + 0]) << 4) | hexCharToInt(s[i*2 + 1]));
    }

    return sz;
}

static TLV * getTLV(const unsigned char *d, unsigned char tag)
{
    TLV *tlv = (TLV *)d;
    int sz = tlv->len;

    tlv++; //skip head

    while (sz) {
        if (tlv->tag != tag) {
            tlv = (TLV *)(((char *)tlv) + sizeof(TLV) + tlv->len);
            sz -= sizeof(TLV) + tlv->len;
        } else {
#if 0
            int i;
            printf("{%02x, %02x, ", tlv->tag, tlv->len);
            for (i = 0; i < tlv->len; i++)
                printf("%02x, ", tlv->data[i]);
            printf("}\n");
#endif
            return tlv;
        }
    }
    return NULL;
}

//frameworks\base\telephony\java\com\android\internal\telephony\IccFileHandler.java
//from TS 11.11 9.1 or elsewhere

const int EF_ICCID  = 0x2fe2;
const int COMMAND_READ_BINARY = 0xb0;
const int COMMAND_UPDATE_BINARY = 0xd6;
const int COMMAND_READ_RECORD = 0xb2;
const int COMMAND_UPDATE_RECORD = 0xdc;
const int COMMAND_SEEK = 0xa2;
const int COMMAND_GET_RESPONSE = 0xc0;
const int GET_RESPONSE_EF_IMG_SIZE_BYTES = 10;
const int GET_RESPONSE_EF_SIZE_BYTES = 15;

//***** types of files  TS 11.11 9.3
static const int EF_TYPE_TRANSPARENT = 0;
static const int EF_TYPE_LINEAR_FIXED = 1;
static const int EF_TYPE_CYCLIC = 3;

//***** types of files  TS 11.11 9.3
const int TYPE_RFU = 0;
const int TYPE_MF  = 1;
const int TYPE_DF  = 2;
const int TYPE_EF  = 4;

// Byte order received in response to COMMAND_GET_RESPONSE
// Refer TS 51.011 Section 9.2.1
const int RESPONSE_DATA_RFU_1 = 0;
const int RESPONSE_DATA_RFU_2 = 1;

const int RESPONSE_DATA_FILE_SIZE_1 = 2;
const int RESPONSE_DATA_FILE_SIZE_2 = 3;

const int RESPONSE_DATA_FILE_ID_1 = 4;
const int RESPONSE_DATA_FILE_ID_2 = 5;
const int RESPONSE_DATA_FILE_TYPE = 6;
const int RESPONSE_DATA_RFU_3 = 7;
const int RESPONSE_DATA_ACCESS_CONDITION_1 = 8;
const int RESPONSE_DATA_ACCESS_CONDITION_2 = 9;
const int RESPONSE_DATA_ACCESS_CONDITION_3 = 10;
const int RESPONSE_DATA_FILE_STATUS = 11;
const int RESPONSE_DATA_LENGTH = 12;
const int RESPONSE_DATA_STRUCTURE = 13;
const int RESPONSE_DATA_RECORD_LENGTH = 14;


//wangbo 2017/12/20 add
void usim2sim(RIL_SIM_IO_Response *psr)
{
    int sz;
    int i;
    unsigned char usim_data[1024];
    unsigned char sim_data[15] = {0};
    static char new_response[31];
    TLV * tlv;
    const char bytesToHexString[] = "0123456789abcdef";

    if (!psr->simResponse)
        return;

    if (!strlen(psr->simResponse)) {
        psr->simResponse = NULL;
        return;
    }

    if (strlen(psr->simResponse) < 4)
        return;

    sz = hexStringToBytes(psr->simResponse, usim_data);

    if (usim_data[0] != 0x62) {
        //LOGD("CRSM: not usim");
        return;
    }

    if (usim_data[1] != (sz - 2)) {
        //LOGD("CRSM: error usim len");
        return;
    }

    tlv = getTLV(usim_data, 0x80);
    if (tlv) {
        //LOGD("CRSM: FILE_SIZE %02X%02X", tlv->data[0], tlv->data[1]);
        sim_data[RESPONSE_DATA_FILE_SIZE_1] = tlv->data[0];
        sim_data[RESPONSE_DATA_FILE_SIZE_2] = tlv->data[1];
    }

    tlv = getTLV(usim_data, 0x83);
    if (tlv) {
        //LOGD("CRSM: FILE_ID %02X%02X", tlv->data[0], tlv->data[1]);
        sim_data[RESPONSE_DATA_FILE_ID_1] = tlv->data[0];
        sim_data[RESPONSE_DATA_FILE_ID_2] = tlv->data[1];
    }

    tlv = getTLV(usim_data, 0x82);
    if (tlv) {
        int filetype = (tlv->data[0] >> 3) & 0x7;
        int efstruct = (tlv->data[0] >> 0) & 0x7;
        //LOGD("CRSM: len: %d, %02x %02x %02x %02x %02x", tlv->len, tlv->data[0], tlv->data[1], tlv->data[2], tlv->data[3], tlv->data[4]);

        //File type:
        if ((filetype == 0) || (filetype == 1)) {
            //LOGD("CRSM: FILE_TYPE_EF");
            sim_data[RESPONSE_DATA_FILE_TYPE] = TYPE_EF;
        } else if ((filetype == 7) && (efstruct == 0)) {
            //LOGD("CRSM: TYPE_DF");
            sim_data[RESPONSE_DATA_FILE_TYPE] = TYPE_DF;
        } else {
            //LOGD("CRSM: TYPE_RFU");
            sim_data[RESPONSE_DATA_FILE_TYPE] = TYPE_RFU;
        }

        //EF struct
        if (efstruct == 1) {
            //LOGD("CRSM: EF_TYPE_TRANSPARENT");
            sim_data[RESPONSE_DATA_STRUCTURE] = EF_TYPE_TRANSPARENT;
        } else if (efstruct == 2) {
            //LOGD("CRSM: EF_TYPE_LINEAR_FIXED");
            sim_data[RESPONSE_DATA_STRUCTURE] = EF_TYPE_LINEAR_FIXED;
        } else if (efstruct == 3) {
            //LOGD("CRSM: EF_TYPE_CYCLIC");
            sim_data[RESPONSE_DATA_STRUCTURE] = EF_TYPE_CYCLIC;
        } else {
            //LOGD("CRSM: EF_TYPE_UNKNOWN");
        }

        if ((efstruct == 2) || (efstruct == 3)) {
            if (tlv->len == 5) {
                sim_data[RESPONSE_DATA_RECORD_LENGTH] = ((tlv->data[2] << 8) + tlv->data[3]) & 0xFF;
                //LOGD("CRSM: RESPONSE_DATA_RECORD_LENGTH %d", sim_data[RESPONSE_DATA_RECORD_LENGTH]);
            } else {
                //LOGD("CRSM: must contain Record length and Number of records");
            }
        }
    }

    for (i = 0; i < 15; i++) {
        new_response[i*2 + 0] =  bytesToHexString[0x0f & (sim_data[i] >> 4)];
        new_response[i*2 + 1] =  bytesToHexString[0x0f & sim_data[i]];
    }
    new_response[30] = '\0';

    psr->simResponse = new_response;

//see telephony\src\java\com\android\internal\telephony\uicc\IccIoResult.java
#if 0
    /**
     * true if this operation was successful
     * See GSM 11.11 Section 9.4
     * (the fun stuff is absent in 51.011)
     */
    public boolean success() {
        return sw1 == 0x90 || sw1 == 0x91 || sw1 == 0x9e || sw1 == 0x9f;
    }
#endif
    if (psr->sw1 == 0x90 || psr->sw1 == 0x91 || psr->sw1 == 0x9e || psr->sw1 == 0x9f)
        ;
    else
        psr->sw1 = 0x90;

    return;
}
#endif
///
const char * SmartCardCmd[6] = {"53494d31","53494d32","53494d33","53494D31","53494D32","53494D33"};
void  requestSIM_IO(void *data, size_t datalen __unused, RIL_Token t)
{
    ATResponse *p_response = NULL;
    RIL_SIM_IO_Response sr;
    int err;
    char *cmd = NULL;
    RIL_SIM_IO_v6 *p_args;
    char *line;
    int i = 0;
    ATResponse *qccid_response = NULL;
    char iccid_low = 0;

    memset(&sr, 0, sizeof(sr));

    p_args = (RIL_SIM_IO_v6 *)data;

    RLOGD("file id is:%d",p_args->fileid);
    //zhangqingyun add for adnrecord load 20220428 start
    #if 0
    /*[zhaopf@meigsmart.com-2021/06/10]add for phone num support { */
    if(p_args->fileid != 12258 && p_args->fileid != 28480) {
    /*[zhaopf@meigsmart.com-2021/06/10]add for phone num support } */
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        RLOGD("file id is:%d this file id should return",p_args->fileid);
        return;
    }
    #endif

    //zhangqingyun add for just return not read sim io since this sim file is not necessary
    /*f(p_args->fileid == 28480 || p_args->fileid == 28589 || p_args->fileid == 28617 || p_args->fileid == 28618 ||p_args->fileid == 28433 || p_args->fileid ==28619 || p_args->fileid == 28472 || p_args->fileid == 28435 || p_args->fileid ==28621 || p_args->fileid ==28613 || p_args->fileid ==28438 || p_args->fileid == 28437 || p_args->fileid == 28478 || p_args->fileid == 28514 ||  p_args->fileid == 28633  p_args->fileid == 28539){
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                 RLOGD("file id is:%d this file id should return",p_args->fileid);
                 return;
    }
     RLOGD("file id is:%d",p_args->fileid);*/

    /* FIXME handle pin2 */
#if 1 //meig
    if (p_args->command == COMMAND_GET_RESPONSE) {
        p_args->p3 = 0;
    }
#endif
    //zhangqingyun add 20220418 start hisi solution to add path id
    if (curr_modem_info.info.sltn_type == HISI){
        if (p_args->data == NULL) {
            RLOGD("[%s]: p_args->data is NULL", __func__);
            asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d,,\"%s\"",
                 p_args->command, p_args->fileid,
                 p_args->p1, p_args->p2, p_args->p3,p_args->path);
        } else {
            #if 1 //meig
                asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d,\"%s\",\"%s\"",
            #else
                asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d,%s",
            #endif
                 p_args->command, p_args->fileid,
                 p_args->p1, p_args->p2, p_args->p3, p_args->data,p_args->path);
        }
    }

    else {

            if (p_args->data == NULL) {
            RLOGD("[%s]: p_args->data is NULL", __func__);
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d",
                 p_args->command, p_args->fileid,
                 p_args->p1, p_args->p2, p_args->p3);
    } else {
#if 1 //meig
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d,\"%s\"",
#else
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d,%s",
#endif
                 p_args->command, p_args->fileid,
                 p_args->p1, p_args->p2, p_args->p3, p_args->data);
    }
    }
    /*zhangqingyun add for support read adn record end */
    err = at_send_command_singleline(cmd, "+CRSM:", &p_response);

    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(sr.sw1));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(sr.sw2));
    if (err < 0) goto error;

    if (at_tok_hasmore(&line)) {
        err = at_tok_nextstr(&line, &(sr.simResponse));
        if (err < 0) goto error;
    }

#if 1 //meig
//see telephony\src\java\com\android\internal\telephony\uicc\IccFileHandler.java handleMessage() -> case EVENT_GET_BINARY_SIZE_DONE:
    if (p_args->command == COMMAND_GET_RESPONSE)
        usim2sim(&sr);
#endif

    RLOGD("[%s]: RIL_SIM_IO_Response Complete sr.sw1=%d, sr.sw2=%d, sr.simResponse=%s",
          __func__, sr.sw1, sr.sw2, sr.simResponse);

#ifdef MEIG_REPORT_SIGNAL_STRENGTH
    if ((p_args->fileid == EF_ICCID) && (p_args->command == COMMAND_READ_BINARY)) {
        requestSignalStrength(NULL, 0, NULL);
    }
#endif

    if (p_args->fileid == EF_ICCID && sr.simResponse == NULL)
        goto error;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &sr, sizeof(sr));
    at_response_free(p_response);
    free(cmd);
    /*zhangqingyun add for support sim refresh 20220507 start*/
    bool needRefresh = false;
    RLOGD("refersh begain fileid is:%d,command is:%d, sr.sw1 is:%d",p_args->fileid,p_args->command,sr.sw1);
    if((p_args->fileid == 0x6f3a) && (p_args->command == 0xdc) && (sr.sw1 == 0x90 || sr.sw1 == 0x91)){
        int i =0 ;
        for (i = 0; i < 6; i++){
            if(strncmp(p_args->data, SmartCardCmd[i],strlen(SmartCardCmd[i])) == 0 ){
                RLOGD("flag refresh is true");
                needRefresh = true;
                break;
            }
        }
    }
    if(needRefresh){
        p_response = NULL;
        char * reset_cmd = NULL;
        int reset_retry = 3;
        asprintf(&reset_cmd, "%s", "AT+CFUN=1,1");
        while(reset_retry --) {
            usleep(500000);
            RLOGD("sendd cfun 1 1 to reboot module");
            err = at_send_command_singleline(reset_cmd, "", &p_response);
            if(err < 0 || p_response->success == 0){
                if(p_response != NULL){
                    at_response_free(p_response);
                }
                continue;
            } else {
                at_response_free(p_response);
                break;
            }

        }
    }
    /*zhangqingyun add for support sim refresh 20220507 end*/
    return;
error:
    if (p_args->fileid == EF_ICCID/* && ql_is_EC20 && strStartsWith(ql_product_version, "EC20CE")*/) {
        sr.sw1 = 144;
        sr.sw2 = 0;
        sr.simResponse = NULL;
        if (p_args->command == COMMAND_GET_RESPONSE) {
            sr.simResponse = "0000000a2fe2040000000000000000";
        } else if (p_args->command == COMMAND_READ_BINARY) {
#define TELCOMM_DUMMY_ICCID "98681031098310024233"
            err = at_send_command_singleline(cmd, "+ICCID:", &qccid_response);
            if (err < 0 || qccid_response == NULL || qccid_response->success == 0) {
                sr.simResponse = TELCOMM_DUMMY_ICCID;
            } else {
                line = qccid_response->p_intermediates->line;
                if (0 == at_tok_start(&line) && 0 == at_tok_nextstr(&line, &sr.simResponse)) {
                    for (i = 0; i < strlen(sr.simResponse); i+=2) {
                        if ((strlen(sr.simResponse) - 1) < (i+1)) {
                            RLOGD("[%s:%d] array out of index, invalid iccid length.\n", __func__, __LINE__);
                            sr.simResponse = TELCOMM_DUMMY_ICCID;
                        } else {
                            iccid_low = sr.simResponse[i];
                            sr.simResponse[i] = sr.simResponse[i+1];
                            sr.simResponse[i+1] = iccid_low;
                        }
                    }
                } else {
                    RLOGD("[%s:%d] at_tok_start or at_tok_nextstr failed.\n", __func__, __LINE__);
                    sr.simResponse = TELCOMM_DUMMY_ICCID;
                }
            }
        }
        if (sr.simResponse != NULL) {
            RIL_onRequestComplete(t, RIL_E_SUCCESS, &sr, sizeof(sr));
            at_response_free(p_response);
            free(cmd);
            if (NULL != qccid_response) {
                at_response_free(qccid_response);
                qccid_response = NULL;
            }
            return;
        }
    }
    RLOGD("%s error\n", __func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
    free(cmd);
    if (NULL != qccid_response) {
        at_response_free(qccid_response);
    }
}


#if 0 //wangbo 2017/12/20
void  requestSIM_IO(void *data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    RIL_SIM_IO_Response sr;
    int err;
    char *cmd = NULL;
    RIL_SIM_IO_v5 *p_args;
    char *line;

    memset(&sr, 0, sizeof(sr));

    p_args = (RIL_SIM_IO_v5 *)data;

    /* FIXME handle pin2 */

    if (p_args->data == NULL) {
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d",
                 p_args->command, p_args->fileid,
                 p_args->p1, p_args->p2, p_args->p3);
    } else {
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d,%s",
                 p_args->command, p_args->fileid,
                 p_args->p1, p_args->p2, p_args->p3, p_args->data);
    }

    err = at_send_command_singleline(cmd, "+CRSM:", &p_response);

    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(sr.sw1));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(sr.sw2));
    if (err < 0) goto error;

    if (at_tok_hasmore(&line)) {
        err = at_tok_nextstr(&line, &(sr.simResponse));
        if (err < 0) goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &sr, sizeof(sr));
    at_response_free(p_response);
    free(cmd);

    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
    free(cmd);
}

#endif

/* begin: modified by dongmeirong for PIN set and change 20210126 */
//duanshitao add for sim pin and puk 20101122
void  requestQueryFacilityLock(void*  data, size_t  datalen __unused, RIL_Token  t)
{
    ATResponse   *p_response = NULL;
    int           err;
    char*         cmd = NULL;
    const char**  strings = (const char**)data;
    SIM_Status    sim_sta = SIM_ABSENT;
    int  response;
    char *line;

    if (strcmp("SC", strings[0]) == 0) {
        RLOGD("%s() query pin enable state.", __FUNCTION__);
    }
#if 0
    else if(strcmp("FD", strings[0]) == 0) {
        //#ifndef ODM_MODODR_2
        if( ODM_CT_OPERATOR_3G==cur_oper || ODM_CT_OPERATOR_4G==cur_oper) {
            response =1;
            RIL_onRequestComplete(t, RIL_E_SUCCESS,  &response, sizeof(int *));
            return ;
        }
        //#endif
    }
#endif
    asprintf(&cmd, "AT+CLCK=\"%s\",2", strings[0]);
    err = at_send_command_singleline(cmd, "+CLCK:", &p_response);
    if (err < 0 || p_response->success == 0) {
        at_response_free(p_response);
        free(cmd);
        asprintf(&cmd, "AT+QCLCK=\"%s\",2", strings[0]);
        err = at_send_command_singleline(cmd, "+QCLCK:", &p_response);
        if (err < 0 || p_response->success == 0)
        {
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            goto error;
        }
    }
    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        goto error;
    }

    err = at_tok_nextint(&line, &response);
    if (err < 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        goto error;
    }
    RLOGD("Query sim status response is %d\n",response);

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
error:
    at_response_free(p_response);
    free(cmd);
}
/* end: modified by dongmeirong for PIN set and change 20210126 */
/*[zhaopf@meigsmart-2021/05/10] add for hangsheng customed adc read begin */
void  requestReadADCEX(void*  data, size_t  datalen __unused, RIL_Token  t)
{
    int err;
    int adcVal = 0;

    char responseStr[PROPERTY_VALUE_MAX] = { 0x0 };
    char valStr[PROPERTY_VALUE_MAX] = { 0x0 };
    ATResponse *p_response = NULL;
    char *line;
    memset(responseStr, 0x0, PROPERTY_VALUE_MAX);

    err = at_send_command_singleline("AT+ADCREAD=0","+ADCREAD:",&p_response);
    if(err < 0 || p_response->success == 0) {
        goto error;
    }
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if(err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line,&adcVal);
    if(err < 0) {
        goto error;
    }
    RLOGD("adcVal is:%d",adcVal);
    snprintf(valStr, PROPERTY_VALUE_MAX, "%d", adcVal/1000);
    snprintf(responseStr, PROPERTY_VALUE_MAX, "^ADCREADEX: %d", adcVal/1000);
    RLOGD("send adcval %s", responseStr);
    property_set("sys.modem.adcval", valStr);
    if(NULL != t) {
        RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, sizeof(char*));
    }
    return;

error:
    RLOGD("requestReadADCEX must never return an error when radio is on");
    if(NULL != t){
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    }
    at_response_free(p_response);

}
/*[zhaopf@meigsmart-2021/05/10] add for hangsheng customed adc read end */

void  requestSetFacilityLock(void*  data, size_t  datalen __unused, RIL_Token  t)
{
    ATResponse   *p_response = NULL;
    ATResponse     *pin_response =NULL;
    int           err;
    char*         cmd = NULL;
    const char**  strings = (const char**)data;
    //int response = -1;
    char pin = 0;
    int rc=0;
    int response[2];
    char *nettypeline;

    if (strcmp("SC", strings[0]) == 0) {
        pin = 1;
    }

    asprintf(&cmd, "AT+CLCK=\"%s\",%s,\"%s\"", strings[0], strings[1], strings[2]);

    err = at_send_command(cmd, &p_response);

    if (err < 0 || p_response->success == 0) {
        at_response_free(p_response);
        free(cmd);
        asprintf(&cmd, "AT+QCLCK=\"%s\",%s,\"%s\"", strings[0], strings[1], strings[2]);
        err = at_send_command(cmd, &p_response);
        if (err < 0 || p_response->success == 0) {
            if (pin == 1) {
                //rc = at_send_command_singleline("AT+ZPINPUK=?", "+ZPINPUK:",&pin_response);
                rc = at_send_command_singleline("AT+SGPINPUK=?", "+SGPINPUK:",&pin_response);

                if (rc < 0 || pin_response->success == 0) {
                    at_response_free(pin_response);
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                    goto error;
                }

                nettypeline = pin_response->p_intermediates->line;
                rc = at_tok_start(&nettypeline);
                if (rc < 0) {
                    at_response_free(pin_response);
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                    goto error;
                }

                rc= at_tok_nextint(&nettypeline, &(response[0]));
                if (rc < 0) {
                    at_response_free(pin_response);
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                    goto error;
                }
                at_response_free(pin_response);
                RLOGD("signal test pin retry count is %d\n",response[0]);
            }
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, &response[0], sizeof(int));
        } else {
            if (pin == 1) {
                response[0]=3;
                RIL_onRequestComplete(t, RIL_E_SUCCESS, &response[0], sizeof(int));
            }
        }
    } else {
        if (pin == 1) {
            response[0]=3;
            RIL_onRequestComplete(t, RIL_E_SUCCESS, &response[0], sizeof(int));
        }
    }

error:
    at_response_free(p_response);
    free(cmd);
}

/* begin: modified by dongmeirong for PIN enter adaption 20210125 */
// return: 0 -- success; -1 -- fail
static int getPinPukRtryTimesOld(int *pinTimes, int *pukTimes) {
    ATResponse   *p_response = NULL;
    int           err;
    char *line = NULL;

    err = at_send_command_singleline("AT+SGPINPUK", "+SGPINPUK:", &p_response);
    if (err < 0 || p_response->success == 0) goto error;

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) goto error;

    // pin times
    err = at_tok_nextint(&line, pinTimes);
    if (err < 0) goto error;

    // puk times
    err = at_tok_nextint(&line, pukTimes);
    if (err < 0) goto error;

    at_response_free(p_response);
    return 0;
error:
    at_response_free(p_response);
    return -1;
}

// return: 0 -- sueccess; 1 -- generic failure; 2 -- incorrect password
static int requestEnterSimPinOld(void*  data, size_t datalen, RIL_Token  t) {
    ATResponse   *p_response = NULL;
    int           err;
    char*         cmd = NULL;
    const char**  strings = (const char**)data;
    int response[2] = {0};
    int times = 0;
    SIM_Status simStatus = SIM_PIN;

    if (datalen == 2 * sizeof(char *)) {
        asprintf(&cmd, "AT+QCPIN=%s", strings[0]);
        simStatus = SIM_PIN;
    } else if (datalen == 3 * sizeof(char *)) {
        asprintf(&cmd, "AT+QCPIN=%s, %s", strings[0], strings[1]);
    }
    err = at_send_command(cmd, &p_response);
    if (err < 0 || p_response->success == 0) {
        err = getPinPukRtryTimesOld(&response[0], &response[1]);
        if (err < 0) goto error;
        at_response_free(p_response);
        free(cmd);
        times = simStatus == SIM_PIN ? response[0] : response[1];
        RIL_onRequestComplete(t, RIL_E_PASSWORD_INCORRECT, &times, sizeof(int));
        return 2;
    } else {
        RLOGD("QCPIN enter else to set the retry count is 3\n");
        times = simStatus == SIM_PIN ? 3 : 10;
        at_response_free(p_response);
        free(cmd);
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &times, sizeof(int));
        TIMEVAL_DELAYINIT.tv_sec = 5;
        RIL_requestTimedCallback(initializeCallback_unlockPin, NULL, &TIMEVAL_DELAYINIT);
        return 0;
    }
error:
    at_response_free(p_response);
    free(cmd);
    return 1;
}


// return: 0 -- success; -1 -- fail
static int getPinPukRetryTimes(int *pinTimes, int *pukTimes) {
    ATResponse   *p_response = NULL;
    int           err;
    char *line = NULL;
    char *skip = NULL;

    err = at_send_command_singleline("AT^CPIN?", "^CPIN:", &p_response);
    if (err < 0 || p_response->success == 0) goto error;

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) goto error;
    // skip code
    err = at_tok_nextstr(&line, &skip);
    if (err < 0) goto error;
    // skip times
    err = at_tok_nextint(&line, pinTimes);

    // puk_times
    err = at_tok_nextint(&line, pukTimes);
    if (err < 0) goto error;

    // pin_times
    err = at_tok_nextint(&line, pinTimes);
    if (err < 0) goto error;

    at_response_free(p_response);
    return 0;
error:
    at_response_free(p_response);
    return -1;
}

void  requestEnterSimPin(void*  data, size_t        datalen, RIL_Token  t)
{
    ATResponse   *p_response = NULL;
    int           err;
    char*         cmd = NULL;
    const char**  strings = (const char**)data;
    int response[2] = {0};
    int times = 0;
    char *line = NULL;
    SIM_Status simStatus = SIM_PIN;

    if (datalen == 2 * sizeof(char *)) {
        asprintf(&cmd, "AT+CPIN=%s", strings[0]);
    } else if (datalen == 3 * sizeof(char *)) {
        asprintf(&cmd, "AT+CPIN=\"%s\",\"%s\"", strings[0], strings[1]);
        simStatus = SIM_PUK;
    } else {
        goto error;
    }
    err = at_send_command(cmd, &p_response);

    if (err < 0 || p_response->success == 0) {
        RLOGD("Try to get the retry pin count.");
        err = getPinPukRetryTimes(&response[0], &response[1]);
        if (err < 0) goto error;
        times = simStatus == SIM_PIN ? response[0] : response[1];
        RIL_onRequestComplete(t, RIL_E_PASSWORD_INCORRECT, &times, sizeof(int));
    } else {
        RLOGD("Reset the retry count is %d\n");
        times = simStatus == SIM_PIN ? 3 : 10;
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &times, sizeof(int));
        TIMEVAL_DELAYINIT.tv_sec = 5;
        RIL_requestTimedCallback(initializeCallback_unlockPin, NULL, &TIMEVAL_DELAYINIT);
    }
    at_response_free(p_response);
    free(cmd);
    return;
error:
    err = requestEnterSimPinOld(data, datalen, t);
    if (err == 1) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    }
    at_response_free(p_response);
    free(cmd);
}
/* end: modified by dongmeirong for PIN enter adaption 20210125 */

void  requestChangeSimPin(void*  data, size_t  datalen __unused, RIL_Token  t)
{
    ATResponse   *p_response = NULL;
    ATResponse   *pin_response = NULL;
    int           err;
    char*         cmd = NULL;
    const char**  strings = (const char**)data;
    int response[2];
    int rc;
    char *nettypeline,*nettypestr;

    asprintf(&cmd, "AT+CPWD=\"SC\",\"%s\",\"%s\"", strings[0], strings[1]);

    err = at_send_command(cmd, &p_response);

    if (err < 0 || p_response->success == 0) {
        at_response_free(p_response);
        free(cmd);
        asprintf(&cmd, "AT+QCPWD=\"SC\",\"%s\",\"%s\"", strings[0], strings[1]);
        err = at_send_command(cmd, &p_response);
        if (err < 0 || p_response->success == 0) {
            rc = at_send_command_singleline("AT+SGPINPUK=?", "+SGPINPUK:",&pin_response);
            if (rc < 0 || pin_response->success == 0) {
                at_response_free(pin_response);
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);//zhangqingyun add for cts test
                goto error;
            }
            nettypeline = pin_response->p_intermediates->line;
            rc = at_tok_start(&nettypeline);
            if (rc < 0) {
                at_response_free(pin_response);
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);//zhangqingyun add for cts test
                goto error;
            }
            rc = at_tok_nextint(&nettypeline, &(response[0]));
            if (rc < 0) {
                at_response_free(pin_response);
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);//zhangqingyun add for cts test
                goto error;
            }
            at_response_free(pin_response);
            RLOGD("signal test changepin the retry count is %d\n",response[0]);
            RIL_onRequestComplete(t, RIL_E_PASSWORD_INCORRECT, &response[0], sizeof(int *));
        } else {
            response[0]=3;
            RIL_onRequestComplete(t, RIL_E_SUCCESS, &response[0], sizeof(int));
        }
    } else {
        response[0]=3;
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &response[0], sizeof(int));
    }

error:
    at_response_free(p_response);
    free(cmd);
}
//duanshitao add for sim pin and puk 20101122 end

/* begin: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/
#ifdef POLL_SIM_ABSENT_RESET_MODULE
void detectSimAbsent(void *param __unused) {
    SIM_Status simStatus = SIM_ABSENT;
    simStatus = getSIMStatus();
    if (simStatus != SIM_NOT_READY && simStatus != SIM_ABSENT
        && simStatus != RUIM_NOT_READY && simStatus != RUIM_ABSENT) {
        s_detect_sim_count = 3;
        RLOGD("%s sim exist, status = %d", __FUNCTION__, simStatus);
        RIL_requestTimedCallback(detectSimAbsent, NULL, &TIMEVAL_60);
        return;
    }
    s_detect_sim_count--;
    RLOGD("%s getSimStatus, count remains %d", __FUNCTION__, s_detect_sim_count);
    if (s_detect_sim_count > 0) {
        RIL_requestTimedCallback(detectSimAbsent, NULL, &TIMEVAL_1);
    } else {
        at_send_command("AT+RESET", NULL);
        s_detect_sim_count = 3;
        RIL_requestTimedCallback(detectSimAbsent, NULL, &TIMEVAL_60);
    }
}
#endif
/* end: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/

