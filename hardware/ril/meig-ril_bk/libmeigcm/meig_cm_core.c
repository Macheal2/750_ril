#include "common.h"
#include "meig_cm.h"
#include "../getdevinfo.h"

extern char *strndup (const char *__string, size_t __n);
extern MODEM_INFO curr_modem_info;


enum peripheral_ep_type {
    DATA_EP_TYPE_RESERVED    = 0x0,
    DATA_EP_TYPE_HSIC    = 0x1,
    DATA_EP_TYPE_HSUSB    = 0x2,
    DATA_EP_TYPE_PCIE    = 0x3,
    DATA_EP_TYPE_EMBEDDED    = 0x4,
    DATA_EP_TYPE_BAM_DMUX    = 0x5,
};

typedef struct {
    UINT rx_urb_size;
    enum peripheral_ep_type ep_type;
    UINT iface_id;
    UCHAR MuxId;
} QMAP_SETTING;

typedef struct {
    int ipFamily;
    int pdpIndex;
} NW_INTERFACE_PARAM;



#define qmi_rsp_check_and_return() do { \
        if (err < 0 || pResponse == NULL) { \
            dbg_time("%s err = %d", __func__, err); \
            return err; \
        } \
        pMUXMsg = &pResponse->MUXMsg; \
        if (le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXResult) || le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXError)) { \
            USHORT QMUXError = le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXError); \
            dbg_time("%s QMUXResult = 0x%x, QMUXError = 0x%x", __func__, \
                le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXResult), QMUXError); \
            free(pResponse); \
            return QMUXError; \
        } \
} while(0)

#define qmi_rsp_check() do { \
        if (err < 0 || pResponse == NULL) { \
            dbg_time("%s err = %d", __func__, err); \
            return err; \
        } \
        pMUXMsg = &pResponse->MUXMsg; \
        if (le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXResult) || le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXError)) { \
            USHORT QMUXError = le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXError); \
            dbg_time("%s QMUXResult = 0x%x, QMUXError = 0x%x", __func__, \
                le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXResult), QMUXError); \
        } \
} while(0)







//static uint32_t WdsConnectionIPv4Handle = 0;
//static uint32_t WdsConnectionIPv6Handle = 0;
static int s_is_cdma = 0;
static int s_hdr_personality = 0; // 0x01-HRPD, 0x02-eHRPD
int qmidevice_control_fd[2];
static int signal_control_fd[2];
pthread_t gQmiThreadID;
int gCMInited = 0;
CM_DEV_CONTEXT gCMDevContext;


static qmi_uim_fci_value_type p2ToFciValue(int p2) {
    switch (p2) {
        case UIM_P2_VALUE_FCI:
            return QMI_UIM_FCI_VALUE_FCI;
        case UIM_P2_VALUE_FCP:
            return QMI_UIM_FCI_VALUE_FCP;
        case UIM_P2_VALUE_FMD:
            return QMI_UIM_FCI_VALUE_FMD;
        case UIM_P2_VALUE_NO_DATA:
            return QMI_UIM_FCI_VALUE_NO_DATA;
        default:
            return QMI_UIM_FCI_VALUE_FCI;
    }
}

#ifdef CONFIG_KEEP_CONNECTION
static void main_send_event_to_qmidevice(int triger_event)
{
    write(qmidevice_control_fd[0], &triger_event, sizeof(triger_event));

}



static void send_signo_to_main(int signo)
{
    write(signal_control_fd[0], &signo, sizeof(signo));
}
#endif

void qmidevice_send_event_to_main(int triger_event)
{
//#ifdef CONFIG_KEEP_CONNECTION
    write(qmidevice_control_fd[1], &triger_event, sizeof(triger_event));
//#else
//#endif
}


static char *qstrcpy(char *to, const char *from)   //no __strcpy_chk
{
    char *save = to;
    for (; (*to = *from) != '\0'; ++from, ++to);
    return(save);
}

static char *apducpy_with_length(unsigned char *to, unsigned char *from,int length)   //no __strcpy_chk
{
    int i = 0;
    char *save = to;
    for (i = 0; i < length ; ++from, ++to){
		*to = *from;
                i++;
	}
    return(save);
}

static int s_9x07 = -1;

typedef USHORT (*CUSTOMQMUX)(PQMUX_MSG pMUXMsg, void *arg);

// To retrieve the ith (Index) TLV
PQMI_TLV_HDR GetTLV (PQCQMUX_MSG_HDR pQMUXMsgHdr, int TLVType)
{
    int TLVFind = 0;
    USHORT Length = le16_to_cpu(pQMUXMsgHdr->Length);
    PQMI_TLV_HDR pTLVHdr = (PQMI_TLV_HDR)(pQMUXMsgHdr + 1);

    while (Length >= sizeof(QMI_TLV_HDR)) {
        TLVFind++;
        if (TLVType > 0x1000) {
            if ((TLVFind + 0x1000) == TLVType)
                return pTLVHdr;
        } else  if (pTLVHdr->TLVType == TLVType) {
            return pTLVHdr;
        }

        Length -= (le16_to_cpu((pTLVHdr->TLVLength)) + sizeof(QMI_TLV_HDR));
        pTLVHdr = (PQMI_TLV_HDR)(((UCHAR *)pTLVHdr) + le16_to_cpu(pTLVHdr->TLVLength) + sizeof(QMI_TLV_HDR));
    }

    return NULL;
}

static USHORT GetQMUXTransactionId(void)
{
    static int TransactionId = 0;
    if (++TransactionId > 0xFFFF)
        TransactionId = 1;
    return TransactionId;
}

static PQCQMIMSG ComposeQMUXMsg(UCHAR QMIType, USHORT Type, CUSTOMQMUX customQmuxMsgFunction, void *arg)
{
    UCHAR QMIBuf[WDM_DEFAULT_BUFSIZE];
    PQCQMIMSG pRequest = (PQCQMIMSG)QMIBuf;
    int Length;

    memset(QMIBuf, 0x00, sizeof(QMIBuf));
    pRequest->QMIHdr.IFType = USB_CTL_MSG_TYPE_QMI;
    pRequest->QMIHdr.CtlFlags = 0x00;
    pRequest->QMIHdr.QMIType = QMIType;
    pRequest->QMIHdr.ClientId = gCMDevContext.qmiclientId[QMIType] & 0xFF;

    if (gCMDevContext.qmiclientId[QMIType] == 0) {
        dbg_time("QMIType %d has no clientID", QMIType);
        return NULL;
    }

    pRequest->MUXMsg.QMUXHdr.CtlFlags = QMUX_CTL_FLAG_SINGLE_MSG | QMUX_CTL_FLAG_TYPE_CMD;
    pRequest->MUXMsg.QMUXHdr.TransactionId = cpu_to_le16(GetQMUXTransactionId());
    pRequest->MUXMsg.QMUXMsgHdr.Type = cpu_to_le16(Type);
    if (customQmuxMsgFunction)
        pRequest->MUXMsg.QMUXMsgHdr.Length = cpu_to_le16(customQmuxMsgFunction(&pRequest->MUXMsg, arg) - sizeof(QCQMUX_MSG_HDR));
    else
        pRequest->MUXMsg.QMUXMsgHdr.Length = cpu_to_le16(0x0000);

    pRequest->QMIHdr.Length = cpu_to_le16(le16_to_cpu(pRequest->MUXMsg.QMUXMsgHdr.Length) + sizeof(QCQMUX_MSG_HDR) + sizeof(QCQMUX_HDR)
                                          + sizeof(QCQMI_HDR) - 1);
    Length = le16_to_cpu(pRequest->QMIHdr.Length) + 1;

    pRequest = (PQCQMIMSG)malloc(Length);
    if (pRequest == NULL) {
        dbg_time("%s fail to malloc", __func__);
    } else {
        memcpy(pRequest, QMIBuf, Length);
    }

    return pRequest;
}

#if 0
static PQCQMIMSG ComposeQMUXMsg(int pdpIndex, UCHAR QMIType, USHORT Type, CUSTOMQMUX customQmuxMsgFunction, void *arg)
{
    UCHAR QMIBuf[WDM_DEFAULT_BUFSIZE];
    PQCQMIMSG pRequest = (PQCQMIMSG)QMIBuf;
    int Length;

    memset(QMIBuf, 0x00, sizeof(QMIBuf));
    pRequest->QMIHdr.IFType = USB_CTL_MSG_TYPE_QMI;
    pRequest->QMIHdr.CtlFlags = 0x00;
    pRequest->QMIHdr.QMIType = QMIType;
    if(QMIType == QMUX_TYPE_WDS_IPV6) {
        pRequest->QMIHdr.ClientId = gCMDevContext.wdsClient[pdpIndex].v6clientId & 0xFF;
    } else {
        pRequest->QMIHdr.ClientId = gCMDevContext.wdsClient[pdpIndex].v4clientId & 0xFF;
    }

    if (pRequest->QMIHdr.ClientId == 0) {
        dbg_time("QMIType %d has no clientID", QMIType);
        return NULL;
    }

    pRequest->MUXMsg.QMUXHdr.CtlFlags = QMUX_CTL_FLAG_SINGLE_MSG | QMUX_CTL_FLAG_TYPE_CMD;
    pRequest->MUXMsg.QMUXHdr.TransactionId = cpu_to_le16(GetQMUXTransactionId());
    pRequest->MUXMsg.QMUXMsgHdr.Type = cpu_to_le16(Type);
    if (customQmuxMsgFunction)
        pRequest->MUXMsg.QMUXMsgHdr.Length = cpu_to_le16(customQmuxMsgFunction(&pRequest->MUXMsg, arg) - sizeof(QCQMUX_MSG_HDR));
    else
        pRequest->MUXMsg.QMUXMsgHdr.Length = cpu_to_le16(0x0000);

    pRequest->QMIHdr.Length = cpu_to_le16(le16_to_cpu(pRequest->MUXMsg.QMUXMsgHdr.Length) + sizeof(QCQMUX_MSG_HDR) + sizeof(QCQMUX_HDR)
                                          + sizeof(QCQMI_HDR) - 1);
    Length = le16_to_cpu(pRequest->QMIHdr.Length) + 1;

    pRequest = (PQCQMIMSG)malloc(Length);
    if (pRequest == NULL) {
        dbg_time("%s fail to malloc", __func__);
    } else {
        memcpy(pRequest, QMIBuf, Length);
    }

    return pRequest;
}
#endif

#if 0
static USHORT NasSetEventReportReq(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->SetEventReportReq.TLVType = 0x10;
    pMUXMsg->SetEventReportReq.TLVLength = 0x04;
    pMUXMsg->SetEventReportReq.ReportSigStrength = 0x00;
    pMUXMsg->SetEventReportReq.NumTresholds = 2;
    pMUXMsg->SetEventReportReq.TresholdList[0] = -113;
    pMUXMsg->SetEventReportReq.TresholdList[1] = -50;
    return sizeof(QMINAS_SET_EVENT_REPORT_REQ_MSG);
}

static USHORT WdsSetEventReportReq(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->EventReportReq.TLVType = 0x10;          // 0x10 -- current channel rate indicator
    pMUXMsg->EventReportReq.TLVLength = 0x0001;        // 1
    pMUXMsg->EventReportReq.Mode = 0x00;             // 0-do not report; 1-report when rate changes

    pMUXMsg->EventReportReq.TLV2Type = 0x11;         // 0x11
    pMUXMsg->EventReportReq.TLV2Length = 0x0005;       // 5
    pMUXMsg->EventReportReq.StatsPeriod = 0x00;      // seconds between reports; 0-do not report
    pMUXMsg->EventReportReq.StatsMask = 0x000000ff;        //

    pMUXMsg->EventReportReq.TLV3Type = 0x12;          // 0x12 -- current data bearer indicator
    pMUXMsg->EventReportReq.TLV3Length = 0x0001;        // 1
    pMUXMsg->EventReportReq.Mode3 = 0x01;             // 0-do not report; 1-report when changes

    pMUXMsg->EventReportReq.TLV4Type = 0x13;          // 0x13 -- dormancy status indicator
    pMUXMsg->EventReportReq.TLV4Length = 0x0001;        // 1
    pMUXMsg->EventReportReq.DormancyStatus = 0x00;    // 0-do not report; 1-report when changes
    return sizeof(QMIWDS_SET_EVENT_REPORT_REQ_MSG);
}

static USHORT DmsSetEventReportReq(PQMUX_MSG pMUXMsg)
{
    PPIN_STATUS pPinState = (PPIN_STATUS)(&pMUXMsg->DmsSetEventReportReq + 1);
    PUIM_STATE pUimState = (PUIM_STATE)(pPinState + 1);
    // Pin State
    pPinState->TLVType = 0x12;
    pPinState->TLVLength = 0x01;
    pPinState->ReportPinState = 0x01;
    // UIM State
    pUimState->TLVType = 0x15;
    pUimState->TLVLength = 0x01;
    pUimState->UIMState = 0x01;
    return sizeof(QMIDMS_SET_EVENT_REPORT_REQ_MSG) + sizeof(PIN_STATUS) + sizeof(UIM_STATE);
}
#endif

static USHORT WdsStartNwInterfaceReq(PQMUX_MSG pMUXMsg, void *arg)
{
    PQMIWDS_TECHNOLOGY_PREFERECE pTechPref;
    PQMIWDS_AUTH_PREFERENCE pAuthPref;
    PQMIWDS_USERNAME pUserName;
    PQMIWDS_PASSWD pPasswd;
    PQMIWDS_APNNAME pApnName;
    PQMIWDS_IP_FAMILY_TLV pIpFamily;
    USHORT TLVLength = 0;
    UCHAR *pTLV;
    PROFILE_T *profile = (PROFILE_T *)arg;
    const char *profile_user = profile->user;
    const char *profile_password = profile->password;
    int profile_auth = profile->auth;

    if (s_is_cdma && (profile_user == NULL || profile_user[0] == '\0') && (profile_password == NULL || profile_password[0] == '\0')) {
        profile_user = "ctnet@mycdma.cn";
        profile_password = "vnet.mobi";
        profile_auth = 2; //chap
    }

    pTLV = (UCHAR *)(&pMUXMsg->StartNwInterfaceReq + 1);
    pMUXMsg->StartNwInterfaceReq.Length = 0;

    // Set technology Preferece
    pTechPref = (PQMIWDS_TECHNOLOGY_PREFERECE)(pTLV + TLVLength);
    pTechPref->TLVType = 0x30;
    pTechPref->TLVLength = cpu_to_le16(0x01);
    if (s_is_cdma == 0)
        pTechPref->TechPreference = 0x01;
    else
        pTechPref->TechPreference = 0x02;
    TLVLength +=(le16_to_cpu(pTechPref->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    // Set APN Name
    if (profile->apn && !s_is_cdma) { //cdma no apn
        pApnName = (PQMIWDS_APNNAME)(pTLV + TLVLength);
        pApnName->TLVType = 0x14;
        pApnName->TLVLength = cpu_to_le16(strlen(profile->apn));
        qstrcpy((char *)&pApnName->ApnName, profile->apn);
        TLVLength +=(le16_to_cpu(pApnName->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // Set User Name
    if (profile_user) {
        pUserName = (PQMIWDS_USERNAME)(pTLV + TLVLength);
        pUserName->TLVType = 0x17;
        pUserName->TLVLength = cpu_to_le16(strlen(profile_user));
        qstrcpy((char *)&pUserName->UserName, profile_user);
        TLVLength += (le16_to_cpu(pUserName->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // Set Password
    if (profile_password) {
        pPasswd = (PQMIWDS_PASSWD)(pTLV + TLVLength);
        pPasswd->TLVType = 0x18;
        pPasswd->TLVLength = cpu_to_le16(strlen(profile_password));
        qstrcpy((char *)&pPasswd->Passwd, profile_password);
        TLVLength += (le16_to_cpu(pPasswd->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // Set Auth Protocol
    if (profile_user && profile_password) {
        pAuthPref = (PQMIWDS_AUTH_PREFERENCE)(pTLV + TLVLength);
        pAuthPref->TLVType = 0x16;
        pAuthPref->TLVLength = cpu_to_le16(0x01);
        pAuthPref->AuthPreference = profile_auth; // 0 ~ None, 1 ~ Pap, 2 ~ Chap, 3 ~ MsChapV2
        TLVLength += (le16_to_cpu(pAuthPref->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // Add IP Family Preference
    pIpFamily = (PQMIWDS_IP_FAMILY_TLV)(pTLV + TLVLength);
    pIpFamily->TLVType = 0x19;
    pIpFamily->TLVLength = cpu_to_le16(0x01);
    pIpFamily->IpFamily = profile->curIpFamily;
    TLVLength += (le16_to_cpu(pIpFamily->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    //Set Profile Index
    if (profile->pdp && !s_is_cdma) { //cdma only support one pdp, so no need to set profile index
        PQMIWDS_PROFILE_IDENTIFIER pProfileIndex = (PQMIWDS_PROFILE_IDENTIFIER)(pTLV + TLVLength);
        pProfileIndex->TLVLength = cpu_to_le16(0x01);
        pProfileIndex->TLVType = 0x31;
        dbg_time("setupdata pdp=%d\n", profile->pdp);
        pProfileIndex->ProfileIndex = profile->pdp; //profile->pdp;
        if (s_is_cdma && s_hdr_personality == 0x02) {
            pProfileIndex->TLVType = 0x32; //profile_index_3gpp2
            pProfileIndex->ProfileIndex = 101;
        }
        TLVLength += (le16_to_cpu(pProfileIndex->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    return sizeof(QMIWDS_START_NETWORK_INTERFACE_REQ_MSG) + TLVLength;
}

static USHORT WdsStopNwInterfaceReq(PQMUX_MSG pMUXMsg, void *arg)
{
    NW_INTERFACE_PARAM* nwIntfParam = (NW_INTERFACE_PARAM*)arg;
    pMUXMsg->StopNwInterfaceReq.TLVType = 0x01;
    pMUXMsg->StopNwInterfaceReq.TLVLength = cpu_to_le16(0x04);
    if (nwIntfParam->ipFamily== IpFamilyV4)
        pMUXMsg->StopNwInterfaceReq.Handle =  cpu_to_le32(gCMDevContext.wdsConnV4HandleList[nwIntfParam->pdpIndex]);
    else
        pMUXMsg->StopNwInterfaceReq.Handle =  cpu_to_le32(gCMDevContext.wdsConnV6HandleList[nwIntfParam->pdpIndex]);
    return sizeof(QMIWDS_STOP_NETWORK_INTERFACE_REQ_MSG);
}

static USHORT WdsSetClientIPFamilyPref(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->SetClientIpFamilyPrefReq.TLVType = 0x01;
    pMUXMsg->SetClientIpFamilyPrefReq.TLVLength = cpu_to_le16(0x01);
    pMUXMsg->SetClientIpFamilyPrefReq.IpPreference = *((UCHAR *)arg);
    return sizeof(QMIWDS_SET_CLIENT_IP_FAMILY_PREF_REQ_MSG);
}
/*zhangqingyun add for support body sar 2023-3-21 start*/
static USHORT BodySarSetSarValue(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->SetAutoConnectReq.TLVType = 0x01;
    pMUXMsg->SetAutoConnectReq.TLVLength = cpu_to_le16(0x04);
    pMUXMsg->SetAutoConnectReq.autoconnect_setting = *((QMISAR_VALUE *)arg);
    return sizeof(QMIBODYSAR_SET_SAR_VALUE_REQ);
}

/*zhangqingyun add for support body sar 2023-3-21 end*/
/*zhangqingyun add for support esim 2023-7-21 start*/
static USHORT SimOpenChannelSetAidValue(PQMUX_MSG pMUXMsg, void *arg)
{
    PQMISIM_OPEN_CHANNEL_SLOT_ID_REQ pSlotId;
    PQMISIM_OPEN_CHANNEL_AID_REQ pAid;
    PQMISIM_OPEN_CHANNEL_FCI_VALUE_REQ pFciValue;

    UCHAR *pTLV;
    USHORT TLVLength = 0;

    QMI_UIM_DATA_TYPE *p_qmi_uim_data = (QMI_UIM_DATA_TYPE*) arg;
    pTLV = (UCHAR *)(&pMUXMsg->SimOpenChannel + 1);
    pMUXMsg->SimOpenChannel.Length = 0;

    // slotId
    pSlotId = (PQMISIM_OPEN_CHANNEL_SLOT_ID_REQ) (pTLV + TLVLength);
    pSlotId->TLVType = 0x01;
    pSlotId->TLVLength = cpu_to_le16(0x01);
    pSlotId->SlotIdValue = 0x01;
    TLVLength +=(le16_to_cpu(pSlotId->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    if (p_qmi_uim_data->data_len > 0) {
        pAid = (PQMISIM_OPEN_CHANNEL_AID_REQ) (pTLV + TLVLength);
        pAid->TLVType = 0x10;
        pAid->TLVLength = cpu_to_le16(p_qmi_uim_data->data_len +1); //bufferlen +sizeof(aidlen)
        pAid->AID_Length = p_qmi_uim_data->data_len;
        memcpy(pAid->AID_VALUE, p_qmi_uim_data->data_ptr, 32); //aid buffer
        TLVLength +=(le16_to_cpu(pAid->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    if (p_qmi_uim_data->fci_value != -1) {
        pFciValue = (PQMISIM_OPEN_CHANNEL_FCI_VALUE_REQ) (pTLV + TLVLength);
        pFciValue->TLVType = 0x12;
        pFciValue->TLVLength = cpu_to_le16(0x01);
        pFciValue->fci_value = cpu_to_le32(p_qmi_uim_data->fci_value);
        TLVLength +=(le16_to_cpu(pFciValue->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }
    dbg_time("%s data_len = %d, fci_value = %d", __FUNCTION__, p_qmi_uim_data->data_len, p_qmi_uim_data->fci_value);
    return sizeof(QMISIM_OPEN_CHANNEL_VALUE_REQ) + TLVLength;

#if 0
    pMUXMsg->SimOpenChannel.TLVType = 0x01;
	pMUXMsg->SimOpenChannel.TLVLength    = cpu_to_le16(0x01);
	pMUXMsg->SimOpenChannel.SlotIdValue  = 0x01;//enumeration
	QMI_UIM_DATA_TYPE* p_qmi_uim_data = (QMI_UIM_DATA_TYPE*)arg;
	//pMUXMsg->SimOpenChannel.TLVLength2 = cpu_to_le16(+1); //aid length+ aid_buffer
	dbg_time("%s buffer is: data[0] is %x, length is :%d \n", __FUNCTION__, p_qmi_uim_data->data_ptr[0], p_qmi_uim_data->data_len);
	if (p_qmi_uim_data->data_len > 0) {
    	pMUXMsg->SimOpenChannel.TLVType2 = 0x10;
    	pMUXMsg->SimOpenChannel.TLVLength2 = cpu_to_le16(p_qmi_uim_data->data_len +1); //bufferlen +sizeof(aidlen)
    	pMUXMsg->SimOpenChannel.AID_Length = p_qmi_uim_data->data_len;
    	//pMUXMsg->SimOpenChannel.AID_VALUE  = p_qmi_uim_data->data_ptr;
    	memcpy(pMUXMsg->SimOpenChannel.AID_VALUE, p_qmi_uim_data->data_ptr, 32); //aid buffer
   }
    return sizeof(QMISIM_OPEN_CHANNEL_VALUE_REQ);
#endif
}

static USHORT SimCloseChannelSetChannelId(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->SimCloseChannel.TLVType = 0x01;
	pMUXMsg->SimCloseChannel.TLVLength    = cpu_to_le16(0x01);
	pMUXMsg->SimCloseChannel.SlotIdValue  = 0x01;//enumeration only support single esim?
	pMUXMsg->SimCloseChannel.TLVType2 = 0x11;
	//pMUXMsg->SimOpenChannel.TLVLength2 = cpu_to_le16(+1); //aid length+ aid_buffer
	pMUXMsg->SimCloseChannel.TLVLength2 = cpu_to_le16(0x01); //
	pMUXMsg->SimCloseChannel.ChannelId = *((UCHAR*)arg);  //int to unsigned char ? error may happen
	pMUXMsg->SimCloseChannel.TLVType3 = 0x13;
	pMUXMsg->SimCloseChannel.TLVLength3 = cpu_to_le16(0x01);
	pMUXMsg->SimCloseChannel.Terminal_application = 0x00;
    return sizeof(QMISIM_CLOSE_CHANNEL_VALUE_REQ);
}
static USHORT SimGetSimAtr(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->GetSimAtr.TLVType = 0x01;
	pMUXMsg->GetSimAtr.TLVLength    = cpu_to_le16(0x01);
	pMUXMsg->GetSimAtr.slot  = *((UCHAR*)arg);//enumeration only support single esim?
    return sizeof(QMIUIM_GET_ATR_REQ_MSG);
}

static USHORT SimGetSimEid(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->GetSimEid.TLVType = 0x01;
	pMUXMsg->GetSimEid.TLVLength    = cpu_to_le16(0x01);
	pMUXMsg->GetSimEid.slot  = *((UCHAR*)arg);//enumeration only support single esim?
    return sizeof(QMIUIM_GET_EID_REQ_MSG);
}

#if 0
static USHORT SimSendApduLogicChannel(PQMUX_MSG pMUXMsg, void *arg)
{
    QMI_UIM_APDU_TYPE* apdu_params = (QMI_UIM_APDU_TYPE*)(arg);
    pMUXMsg->SimTransmitApduLogicChannel.TLVType = 0x01;
	pMUXMsg->SimTransmitApduLogicChannel.TLVLength    = cpu_to_le16(0x01);
	pMUXMsg->SimTransmitApduLogicChannel.SlotIdValue  = 0x01;//enumeration only support single esim?
    //tlv3 do something to dynamic get channel_id
    #if 1
	//tlv4
	pMUXMsg->SimTransmitApduLogicChannel.TLVType4 = 0x11;
	pMUXMsg->SimTransmitApduLogicChannel.TLVLength4    = cpu_to_le16(0x01);
	//temp change
	#if 0 
	RLOGD("SimSendApduLogicChannel apdu data len is:%d",apdu_params->data_len);
	if(apdu_params->data_len == 170){
		RLOGD("170 length apdu use procedure_types 00");
	    pMUXMsg->SimTransmitApduLogicChannel.procedure_types  = 0x00;
	}else {
		RLOGD("none 170 length apdu use procedure_types 01");
		pMUXMsg->SimTransmitApduLogicChannel.procedure_types  = 0x01;
	}
	#endif
	//according to 80-nv-304, some exception may happen when this set to 0x01
	//in the future to determine long apdu psss such as 1889 excption;
	//apdu value always put in the last,since some error happen when put it in the middle
	pMUXMsg->SimTransmitApduLogicChannel.procedure_types  = 0x00;
	#endif
	pMUXMsg->SimTransmitApduLogicChannel.TLVType2 = 0x02;
	//pMUXMsg->SimOpenChannel.TLVLength2 = cpu_to_le16(+1); //aid length+ aid_buffer
	pMUXMsg->SimTransmitApduLogicChannel.TLVLength2 = cpu_to_le16(apdu_params->data_len+2); //
	pMUXMsg->SimTransmitApduLogicChannel.apdu_len = apdu_params->data_len;  //int to unsigned char ? error may happen
	apducpy_with_length((PCHAR)&pMUXMsg->SimTransmitApduLogicChannel.raw_apdu, (unsigned char*)apdu_params->data_ptr,apdu_params->data_len);
	
    if ((unsigned char)apdu_params->channel_id) {
        pMUXMsg->SimTransmitApduLogicChannel.TLVType3 = 0x10;
        pMUXMsg->SimTransmitApduLogicChannel.TLVLength3    = cpu_to_le16(0x01);
        pMUXMsg->SimTransmitApduLogicChannel.channel_id  = (unsigned char)apdu_params->channel_id;
        RLOGD("channel id is:%d",pMUXMsg->SimTransmitApduLogicChannel.channel_id);
    }
    return sizeof(QMISIM_TRANSMIT_APDU_LOGIC_CHANNEL_VALUE_REQ) + apdu_params->data_len-1; ////some error may happpen????
}
#else
static USHORT SimSendApduLogicChannel(PQMUX_MSG pMUXMsg, void *arg)
{
    PQMISIM_OPEN_CHANNEL_SLOT_ID_REQ pSlotId;
    PQMISIM_TRANSMIT_APDU_PROCEDURE_TYPE_REQ pProcedure;
    PQMISIM_TRANSMIT_APDU_RAW_APDU_VALUE_REQ pRawApdu;
    PQMISIM_TRANSMIT_CHANNEL_ID_VALUE_REQ channelId;

    UCHAR *pTLV;
    USHORT TLVLength = 0;

    QMI_UIM_APDU_TYPE* apdu_params = (QMI_UIM_APDU_TYPE*)(arg);
    pTLV = (UCHAR *)(&pMUXMsg->SimTransmitApduLogicChannel + 1);
    pMUXMsg->SimTransmitApduLogicChannel.Length = 0;

    // slotId
    pSlotId = (PQMISIM_OPEN_CHANNEL_SLOT_ID_REQ) (pTLV + TLVLength);
    pSlotId->TLVType = 0x01;
    pSlotId->TLVLength = cpu_to_le16(0x01);
    pSlotId->SlotIdValue = 0x01;
    TLVLength +=(le16_to_cpu(pSlotId->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    // procedure type
    pProcedure = (PQMISIM_OPEN_CHANNEL_SLOT_ID_REQ) (pTLV + TLVLength);
    pProcedure->TLVType = 0x11;
    pProcedure->TLVLength = cpu_to_le16(0x01);
    if (apdu_params->channel_id) {
        pProcedure->procedure_types = 0x01;
    } else {
        pProcedure->procedure_types = 0x01;
    }
    TLVLength +=(le16_to_cpu(pProcedure->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    // channelId
    if (apdu_params->channel_id) {
        channelId = (PQMISIM_TRANSMIT_APDU_PROCEDURE_TYPE_REQ) (pTLV + TLVLength);
        channelId->TLVType = 0x10;
        channelId->TLVLength = cpu_to_le16(0x01);
        channelId->channel_id = apdu_params->channel_id;
        TLVLength +=(le16_to_cpu(channelId->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    pRawApdu = (PQMISIM_TRANSMIT_APDU_RAW_APDU_VALUE_REQ) (pTLV + TLVLength);
    pRawApdu->TLVType = 0x02;
    pRawApdu->TLVLength = cpu_to_le16(apdu_params->data_len + 2); // bufferlen +sizeof(apduLen)
    pRawApdu->apdu_len = apdu_params->data_len;
    apducpy_with_length(pRawApdu->raw_apdu, (unsigned char*)apdu_params->data_ptr, apdu_params->data_len);
    TLVLength +=(le16_to_cpu(pRawApdu->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    return sizeof(QMISIM_TRANSMIT_APDU_LOGIC_CHANNEL_VALUE_REQ) + TLVLength;
}
#endif

/*zhangqingyun add for support cts 2023-12-6 satart*/
static USHORT DmsSetModemActivityCalculation(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->TriggerModemActivityCalculation.TLVType = 0x10; //80-16656-4-rev-aaa_qmi_dms
    pMUXMsg->TriggerModemActivityCalculation.TLVLength = cpu_to_le16(0x01);
    pMUXMsg->TriggerModemActivityCalculation.enable_statistics = *((UCHAR *)arg);
    return sizeof(QMIDMS_SET_TRIGGER_MODEM_ACTIVITY_INFO_CALCULATION);
}
/*zhangqingyun add for support cts 2023-12-6 end*/
/*zhangqingyun add for support esim 2023-7-21 end*/
static USHORT WdsSetAutoConnect(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->SetAutoConnectReq.TLVType = 0x01;
    pMUXMsg->SetAutoConnectReq.TLVLength = cpu_to_le16(0x01);
    pMUXMsg->SetAutoConnectReq.autoconnect_setting = *((UCHAR *)arg);
    return sizeof(QMIWDS_SET_AUTO_CONNECT_REQ_MSG);
}


static USHORT WdsSetQMUXBindMuxDataPort(PQMUX_MSG pMUXMsg, void *arg)
{
    QMAP_SETTING *qmap_settings = (QMAP_SETTING *)arg;

    pMUXMsg->BindMuxDataPortReq.TLVType = 0x10;
    pMUXMsg->BindMuxDataPortReq.TLVLength = cpu_to_le16(0x08);
    pMUXMsg->BindMuxDataPortReq.ep_type = cpu_to_le32(qmap_settings->ep_type);
    pMUXMsg->BindMuxDataPortReq.iface_id = cpu_to_le32(qmap_settings->iface_id);
    dbg_time("ep type is:%d\n,iface_id is:%d\n",pMUXMsg->BindMuxDataPortReq.ep_type,pMUXMsg->BindMuxDataPortReq.iface_id);
    pMUXMsg->BindMuxDataPortReq.TLV2Type = 0x11;
    pMUXMsg->BindMuxDataPortReq.TLV2Length = cpu_to_le16(0x01);
    pMUXMsg->BindMuxDataPortReq.MuxId = qmap_settings->MuxId;
    pMUXMsg->BindMuxDataPortReq.TLV3Type = 0x13;
    pMUXMsg->BindMuxDataPortReq.TLV3Length = cpu_to_le16(0x04);
    pMUXMsg->BindMuxDataPortReq.client_type = cpu_to_le32(1); //WDS_CLIENT_TYPE_TETHERED
    return sizeof(QMIWDS_BIND_MUX_DATA_PORT_REQ_MSG);
}

static USHORT WdaSetDataFormat(PQMUX_MSG pMUXMsg, void *arg)
{
    QMAP_SETTING *qmap_settings = (QMAP_SETTING *)arg;

    if (qmap_settings->rx_urb_size == 0) {
        PQMIWDS_ADMIN_SET_DATA_FORMAT_TLV_QOS pWdsAdminQosTlv;
        PQMIWDS_ADMIN_SET_DATA_FORMAT_TLV linkProto;
        PQMIWDS_ADMIN_SET_DATA_FORMAT_TLV dlTlp;

        pWdsAdminQosTlv = (PQMIWDS_ADMIN_SET_DATA_FORMAT_TLV_QOS)(&pMUXMsg->QMUXMsgHdr + 1);
        pWdsAdminQosTlv->TLVType = 0x10;
        pWdsAdminQosTlv->TLVLength = cpu_to_le16(0x0001);
        pWdsAdminQosTlv->QOSSetting = 0; /* no-QOS header */

        linkProto = (PQMIWDS_ADMIN_SET_DATA_FORMAT_TLV)(pWdsAdminQosTlv + 1);
        linkProto->TLVType = 0x11;
        linkProto->TLVLength = cpu_to_le16(4);
        linkProto->Value = cpu_to_le32(0x01);     /* Set Ethernet  mode */

        dlTlp = (PQMIWDS_ADMIN_SET_DATA_FORMAT_TLV)(linkProto + 1);;
        dlTlp->TLVType = 0x13;
        dlTlp->TLVLength = cpu_to_le16(4);
        dlTlp->Value = cpu_to_le32(0x00);

        if (sizeof(*linkProto) != 7 )
            dbg_time("%s sizeof(*linkProto) = %zu, is not 7!", __func__, sizeof(*linkProto) );

        return sizeof(QCQMUX_MSG_HDR) + sizeof(*pWdsAdminQosTlv) + sizeof(*linkProto) + sizeof(*dlTlp);
    } else {
        //Indicates whether the Quality of Service(QOS) data format is used by the client.
        pMUXMsg->SetDataFormatReq.QosDataFormatTlv.TLVType = 0x10;
        pMUXMsg->SetDataFormatReq.QosDataFormatTlv.TLVLength = cpu_to_le16(0x0001);
        pMUXMsg->SetDataFormatReq.QosDataFormatTlv.QOSSetting = 0; /* no-QOS header */
        //Underlying Link Layer Protocol
        pMUXMsg->SetDataFormatReq.UnderlyingLinkLayerProtocolTlv.TLVType = 0x11;
        pMUXMsg->SetDataFormatReq.UnderlyingLinkLayerProtocolTlv.TLVLength = cpu_to_le16(4);
        pMUXMsg->SetDataFormatReq.UnderlyingLinkLayerProtocolTlv.Value = cpu_to_le32(0x02);     /* Set IP  mode */
        //Uplink (UL) data aggregation protocol to be used for uplink data transfer.
        pMUXMsg->SetDataFormatReq.UplinkDataAggregationProtocolTlv.TLVType = 0x12;
        pMUXMsg->SetDataFormatReq.UplinkDataAggregationProtocolTlv.TLVLength = cpu_to_le16(4);
        pMUXMsg->SetDataFormatReq.UplinkDataAggregationProtocolTlv.Value = cpu_to_le32(0x09); //UL QMAP is enabled //0x05
        //Downlink (DL) data aggregation protocol to be used for downlink data transfer
        pMUXMsg->SetDataFormatReq.DownlinkDataAggregationProtocolTlv.TLVType = 0x13;
        pMUXMsg->SetDataFormatReq.DownlinkDataAggregationProtocolTlv.TLVLength = cpu_to_le16(4);
        pMUXMsg->SetDataFormatReq.DownlinkDataAggregationProtocolTlv.Value = cpu_to_le32(0x05); //UL QMAP is enabled
        //Maximum number of datagrams in a single aggregated packet on downlink
        pMUXMsg->SetDataFormatReq.DownlinkDataAggregationMaxDatagramsTlv.TLVType = 0x15;
        pMUXMsg->SetDataFormatReq.DownlinkDataAggregationMaxDatagramsTlv.TLVLength = cpu_to_le16(4);
        pMUXMsg->SetDataFormatReq.DownlinkDataAggregationMaxDatagramsTlv.Value = cpu_to_le32(qmap_settings->rx_urb_size/512);
        //Maximum size in bytes of a single aggregated packet allowed on downlink
        pMUXMsg->SetDataFormatReq.DownlinkDataAggregationMaxSizeTlv.TLVType = 0x16;
        pMUXMsg->SetDataFormatReq.DownlinkDataAggregationMaxSizeTlv.TLVLength = cpu_to_le16(4);
        pMUXMsg->SetDataFormatReq.DownlinkDataAggregationMaxSizeTlv.Value = cpu_to_le32(qmap_settings->rx_urb_size);
        //Peripheral End Point ID
        pMUXMsg->SetDataFormatReq.epTlv.TLVType = 0x17;
        pMUXMsg->SetDataFormatReq.epTlv.TLVLength = cpu_to_le16(8);
        pMUXMsg->SetDataFormatReq.epTlv.ep_type = cpu_to_le32(qmap_settings->ep_type);
        pMUXMsg->SetDataFormatReq.epTlv.iface_id = cpu_to_le32(qmap_settings->iface_id);

        return sizeof(QMIWDS_ADMIN_SET_DATA_FORMAT_REQ_MSG);
    }
}
#ifdef MEIG_NEW_FEATURE
static USHORT SimAuthenticationSetValue(PQMUX_MSG pMUXMsg, void *arg)
{
    PQMIUIM_AUTH_AID_VALUE_REQ pAid;
    PQMIUIM_AUTH_DATA_VALUE_REQ pAuthData;

    UCHAR *pTLV;
    USHORT TLVLength = 0;

    uim_authentication_data_type *auth_info = (uim_authentication_data_type*) arg;

    pTLV = (UCHAR *)(&pMUXMsg->UimAuthentication + 1);
    pMUXMsg->UimAuthentication.Length = 0;

    // AID
    pAid = (PQMIUIM_AUTH_AID_VALUE_REQ) (pTLV + TLVLength);
    pAid->TLVType = 0x01;
    pAid->TLVLength = cpu_to_le16(auth_info->aid_len + 2); // bufferlen + aidlen + sessionType
    pAid->session_type = 0x00;
    pAid->aid_len = auth_info->aid_len;
    if (pAid->aid_len) {
        memcpy(&(pAid->aid), auth_info->aid_buffer, pAid->aid_len);
    }
    TLVLength += (le16_to_cpu(pAid->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    dbg_time("%s TLVLength = %d", __FUNCTION__, TLVLength);
    // auth data
    pAuthData = (PQMIUIM_AUTH_DATA_VALUE_REQ) (pTLV + TLVLength);
    pAuthData->TLVType = 0x02;
    pAuthData->TLVLength = cpu_to_le16(auth_info->auth_data_len + 3); // bufferlen + datalen + context
    pAuthData->dataLen = auth_info->auth_data_len;
    pAuthData->context = auth_info->context;
    if (pAuthData->dataLen) {
        memcpy(&(pAuthData->authData), auth_info->auth_data, auth_info->auth_data_len); //aid buffer
    }
    TLVLength +=(le16_to_cpu(pAuthData->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    dbg_time("%s aidlen = %d, context = %d, authlen = %d, TLVLength = %d",
        __FUNCTION__, auth_info->aid_len, auth_info->context, auth_info->auth_data_len, TLVLength);
    return sizeof(QMIUIM_AUTH_TLV_HDR) + TLVLength;
}
#endif

#ifdef START_KEEP_ALIVE
static USHORT StartKeepAliveSetValue(PQMUX_MSG pMUXMsg, void *arg) {
    PQMIWDS_KEEP_ALIVE_TYPE_VALUE_REQ pAliveType;

    UCHAR *pTLV;
    USHORT TLVLength = 0;

    wds_modem_assisted_ka_start_req_msg_type *ka_info = (wds_modem_assisted_ka_start_req_msg_type *) arg;

    pTLV = (UCHAR *)(&pMUXMsg->WdsStartKeepAlive + 1);
    pMUXMsg->UimAuthentication.Length = 0;

    // keep alive type
    pAliveType = (PQMIWDS_KEEP_ALIVE_TYPE_VALUE_REQ) (pTLV + TLVLength);
    pAliveType->TLVType = 0x01;
    pAliveType->TLVLength = cpu_to_le16(0x04); // bufferlen + aidlen + sessionType
    pAliveType->keepAliveType = ka_info->keep_alive_type;
    TLVLength += (le16_to_cpu(pAliveType->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    // timer value
    if (ka_info->timer_value_valid) {
        PQMIWDS_KEEP_ALIVE_TIMER_VALUE_REQ pAliveTimer;
        pAliveTimer = (PQMIWDS_KEEP_ALIVE_TYPE_VALUE_REQ) (pTLV + TLVLength);
        pAliveTimer->TLVType = 0x10;
        pAliveTimer->TLVLength = cpu_to_le16(0x04); // bufferlen + aidlen + sessionType
        pAliveTimer->timerValue = ka_info->timer_value;
        TLVLength += (le16_to_cpu(pAliveTimer->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // dest ipv4 address
    if (ka_info->dest_ipv4_address_valid) {
        PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV4_ADDR destIpv4Address;
        destIpv4Address = (PQMIWDS_KEEP_ALIVE_TYPE_VALUE_REQ) (pTLV + TLVLength);
        destIpv4Address->TLVType = 0x11;
        destIpv4Address->TLVLength = cpu_to_le16(0x04); // bufferlen + aidlen + sessionType
        destIpv4Address->IPV4Address = ka_info->dest_ipv4_address ;
        TLVLength += (le16_to_cpu(destIpv4Address->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // dest ipv6 address
    if (ka_info->dest_ipv6_address_valid) {
        PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV6_ADDR destIpv6Address;
        destIpv6Address = (PQMIWDS_KEEP_ALIVE_TYPE_VALUE_REQ) (pTLV + TLVLength);
        destIpv6Address->TLVType = 0x12;
        destIpv6Address->TLVLength = cpu_to_le16(0x016); // bufferlen + aidlen + sessionType
        memcpy(destIpv6Address->IPV6Address, ka_info->dest_ipv6_address, 16);
        TLVLength += (le16_to_cpu(destIpv6Address->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // source ipv4 address
    if (ka_info->source_ipv4_address_valid) {
        PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV4_ADDR srcIpv4Address;
        srcIpv4Address = (PQMIWDS_KEEP_ALIVE_TYPE_VALUE_REQ) (pTLV + TLVLength);
        srcIpv4Address->TLVType = 0x13;
        srcIpv4Address->TLVLength = cpu_to_le16(0x04); // bufferlen + aidlen + sessionType
        srcIpv4Address->IPV4Address = ka_info->dest_ipv4_address ;
        TLVLength += (le16_to_cpu(srcIpv4Address->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // source ipv6 address
    if (ka_info->source_ipv6_address_valid) {
        PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV6_ADDR srcIpv6Address;
        srcIpv6Address = (PQMIWDS_KEEP_ALIVE_TYPE_VALUE_REQ) (pTLV + TLVLength);
        srcIpv6Address->TLVType = 0x14;
        srcIpv6Address->TLVLength = cpu_to_le16(0x016); // bufferlen + aidlen + sessionType
        memcpy(srcIpv6Address->IPV6Address, ka_info->dest_ipv6_address, 16);
        TLVLength += (le16_to_cpu(srcIpv6Address->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // dest port
    if (ka_info->dest_port_valid) {
        PQMIWDS_KEEP_ALIVE_PORT_VALUE_REQ destPort;
        destPort = (PQMIWDS_KEEP_ALIVE_TYPE_VALUE_REQ) (pTLV + TLVLength);
        destPort->TLVType = 0x15;
        destPort->TLVLength = cpu_to_le16(0x02); // bufferlen + aidlen + sessionType
        destPort->port = ka_info->dest_port;
        TLVLength += (le16_to_cpu(destPort->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // source port
    if (ka_info->dest_port_valid) {
        PQMIWDS_KEEP_ALIVE_PORT_VALUE_REQ sourcePort;
        sourcePort = (PQMIWDS_KEEP_ALIVE_TYPE_VALUE_REQ) (pTLV + TLVLength);
        sourcePort->TLVType = 0x16;
        sourcePort->TLVLength = cpu_to_le16(0x02); // bufferlen + aidlen + sessionType
        sourcePort->port = ka_info->dest_port;
        TLVLength += (le16_to_cpu(sourcePort->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    return sizeof(QMIWDS_KA_TLV_HDR) + TLVLength;
}
#endif

#ifdef CONFIG_SIM
static USHORT DmsUIMVerifyPinReqSend(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->UIMVerifyPinReq.TLVType = 0x01;
    pMUXMsg->UIMVerifyPinReq.PINID = 0x01; //Pin1, not Puk
    pMUXMsg->UIMVerifyPinReq.PINLen = strlen((const char *)arg);
    qstrcpy((PCHAR)&pMUXMsg->UIMVerifyPinReq.PINValue, ((const char *)arg));
    pMUXMsg->UIMVerifyPinReq.TLVLength = cpu_to_le16(2 + strlen((const char *)arg));
    return sizeof(QMIDMS_UIM_VERIFY_PIN_REQ_MSG) + (strlen((const char *)arg) - 1);
}

static USHORT UimVerifyPinReqSend(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->UIMUIMVerifyPinReq.TLVType = 0x01;
    pMUXMsg->UIMUIMVerifyPinReq.TLVLength = cpu_to_le16(0x02);
    pMUXMsg->UIMUIMVerifyPinReq.Session_Type = 0x00;
    pMUXMsg->UIMUIMVerifyPinReq.Aid_Len = 0x00;
    pMUXMsg->UIMUIMVerifyPinReq.TLV2Type = 0x02;
    pMUXMsg->UIMUIMVerifyPinReq.TLV2Length = cpu_to_le16(2 + strlen((const char *)arg));
    pMUXMsg->UIMUIMVerifyPinReq.PINID = 0x01;  //Pin1, not Puk
    pMUXMsg->UIMUIMVerifyPinReq.PINLen= strlen((const char *)arg);
    qstrcpy((PCHAR)&pMUXMsg->UIMUIMVerifyPinReq.PINValue, ((const char *)arg));
    return sizeof(QMIUIM_VERIFY_PIN_REQ_MSG) + (strlen((const char *)arg) - 1);
}

#ifdef CONFIG_IMSI_ICCID
static USHORT UimReadTransparentIMSIReqSend(PQMUX_MSG pMUXMsg, void *arg)
{
    PREAD_TRANSPARENT_TLV pReadTransparent;

    pMUXMsg->UIMUIMReadTransparentReq.TLVType =  0x01;
    pMUXMsg->UIMUIMReadTransparentReq.TLVLength = cpu_to_le16(0x02);
    if (!strcmp((char *)arg, "EF_ICCID")) {
        pMUXMsg->UIMUIMReadTransparentReq.Session_Type = 0x06;
        pMUXMsg->UIMUIMReadTransparentReq.Aid_Len = 0x00;

        pMUXMsg->UIMUIMReadTransparentReq.TLV2Type = 0x02;
        pMUXMsg->UIMUIMReadTransparentReq.file_id = cpu_to_le16(0x2FE2);
        pMUXMsg->UIMUIMReadTransparentReq.path_len = 0x02;
        pMUXMsg->UIMUIMReadTransparentReq.path[0] = 0x00;
        pMUXMsg->UIMUIMReadTransparentReq.path[1] = 0x3F;
    } else if(!strcmp((char *)arg, "EF_IMSI")) {
        pMUXMsg->UIMUIMReadTransparentReq.Session_Type = 0x00;
        pMUXMsg->UIMUIMReadTransparentReq.Aid_Len = 0x00;

        pMUXMsg->UIMUIMReadTransparentReq.TLV2Type = 0x02;
        pMUXMsg->UIMUIMReadTransparentReq.file_id = cpu_to_le16(0x6F07);
        pMUXMsg->UIMUIMReadTransparentReq.path_len = 0x04;
        pMUXMsg->UIMUIMReadTransparentReq.path[0] = 0x00;
        pMUXMsg->UIMUIMReadTransparentReq.path[1] = 0x3F;
        pMUXMsg->UIMUIMReadTransparentReq.path[2] = 0xFF;
        pMUXMsg->UIMUIMReadTransparentReq.path[3] = 0x7F;
    }

    pMUXMsg->UIMUIMReadTransparentReq.TLV2Length = cpu_to_le16(3 +  pMUXMsg->UIMUIMReadTransparentReq.path_len);

    pReadTransparent = (PREAD_TRANSPARENT_TLV)(&pMUXMsg->UIMUIMReadTransparentReq.path[pMUXMsg->UIMUIMReadTransparentReq.path_len]);
    pReadTransparent->TLVType = 0x03;
    pReadTransparent->TLVLength = cpu_to_le16(0x04);
    pReadTransparent->Offset = cpu_to_le16(0x00);
    pReadTransparent->Length = cpu_to_le16(0x00);

    return (sizeof(QMIUIM_READ_TRANSPARENT_REQ_MSG) + pMUXMsg->UIMUIMReadTransparentReq.path_len + sizeof(READ_TRANSPARENT_TLV));
}
#endif
#endif

#ifdef CONFIG_APN
static USHORT WdsGetProfileSettingsReqSend(PQMUX_MSG pMUXMsg, void *arg)
{
    PROFILE_T *profile = (PROFILE_T *)arg;
    pMUXMsg->GetProfileSettingsReq.Length = cpu_to_le16(sizeof(QMIWDS_GET_PROFILE_SETTINGS_REQ_MSG) - 4);
    pMUXMsg->GetProfileSettingsReq.TLVType = 0x01;
    pMUXMsg->GetProfileSettingsReq.TLVLength = cpu_to_le16(0x02);
    pMUXMsg->GetProfileSettingsReq.ProfileType = 0x00; // 0 ~ 3GPP, 1 ~ 3GPP2
    pMUXMsg->GetProfileSettingsReq.ProfileIndex = profile->pdp; //profile->pdp;
    return sizeof(QMIWDS_GET_PROFILE_SETTINGS_REQ_MSG);
}

static USHORT WdsModifyProfileSettingsReq(PQMUX_MSG pMUXMsg, void *arg)
{
    USHORT TLVLength = 0;
    UCHAR *pTLV;
    PROFILE_T *profile = (PROFILE_T *)arg;
    PQMIWDS_PDPTYPE pPdpType;

    pMUXMsg->ModifyProfileSettingsReq.Length = cpu_to_le16(sizeof(QMIWDS_MODIFY_PROFILE_SETTINGS_REQ_MSG) - 4);
    pMUXMsg->ModifyProfileSettingsReq.TLVType = 0x01;
    pMUXMsg->ModifyProfileSettingsReq.TLVLength = cpu_to_le16(0x02);
    pMUXMsg->ModifyProfileSettingsReq.ProfileType = 0x00; // 0 ~ 3GPP, 1 ~ 3GPP2
    pMUXMsg->ModifyProfileSettingsReq.ProfileIndex = profile->pdp; //zpf

    pTLV = (UCHAR *)(&pMUXMsg->ModifyProfileSettingsReq + 1);

    pPdpType = (PQMIWDS_PDPTYPE)(pTLV + TLVLength);
    pPdpType->TLVType = 0x11;
    pPdpType->TLVLength = cpu_to_le16(0x01);
// 0 ?C PDP-IP (IPv4)
// 1 ?C PDP-PPP
// 2 ?C PDP-IPv6
// 3 ?C PDP-IPv4v6
    if (profile->IsDualIPSupported)
        pPdpType->PdpType = 3;
    else if (profile->enable_ipv6)
        pPdpType->PdpType = 2;
    else
        pPdpType->PdpType = 0;
    TLVLength +=(le16_to_cpu(pPdpType->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    // Set APN Name
    if (profile->apn) {
        PQMIWDS_APNNAME pApnName = (PQMIWDS_APNNAME)(pTLV + TLVLength);
        pApnName->TLVType = 0x14;
        pApnName->TLVLength = cpu_to_le16(strlen(profile->apn));
        qstrcpy((char *)&pApnName->ApnName, profile->apn);
        TLVLength +=(le16_to_cpu(pApnName->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // Set User Name
    if (profile->user) {
        PQMIWDS_USERNAME pUserName = (PQMIWDS_USERNAME)(pTLV + TLVLength);
        pUserName->TLVType = 0x1B;
        pUserName->TLVLength = cpu_to_le16(strlen(profile->user));
        qstrcpy((char *)&pUserName->UserName, profile->user);
        TLVLength += (le16_to_cpu(pUserName->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // Set Password
    if (profile->password) {
        PQMIWDS_PASSWD pPasswd = (PQMIWDS_PASSWD)(pTLV + TLVLength);
        pPasswd->TLVType = 0x1C;
        pPasswd->TLVLength = cpu_to_le16(strlen(profile->password));
        qstrcpy((char *)&pPasswd->Passwd, profile->password);
        TLVLength +=(le16_to_cpu(pPasswd->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    // Set Auth Protocol
    if (profile->user && profile->password) {
        PQMIWDS_AUTH_PREFERENCE pAuthPref = (PQMIWDS_AUTH_PREFERENCE)(pTLV + TLVLength);
        pAuthPref->TLVType = 0x1D;
        pAuthPref->TLVLength = cpu_to_le16(0x01);
        pAuthPref->AuthPreference = profile->auth; // 0 ~ None, 1 ~ Pap, 2 ~ Chap, 3 ~ MsChapV2
        TLVLength += (le16_to_cpu(pAuthPref->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    return sizeof(QMIWDS_MODIFY_PROFILE_SETTINGS_REQ_MSG) + TLVLength;
}


/*zhaopengfei@meigsmart.com-2021-0729 create new apn when modify failed Begin */
static USHORT WdsCreateProfileSettingsReq(PQMUX_MSG pMUXMsg, void *arg)
{
    USHORT TLVLength = 0;
    UCHAR *pTLV;
    PROFILE_T *profile = (PROFILE_T *)arg;
    PQMIWDS_PDPTYPE pPdpType;

    pMUXMsg->CreateProfileSettingsReq.Length = cpu_to_le16(sizeof(QMIWDS_CREATE_PROFILE_SETTINGS_REQ_MSG) - 4);
    pMUXMsg->CreateProfileSettingsReq.TLVType = 0x01;
    pMUXMsg->CreateProfileSettingsReq.TLVLength = cpu_to_le16(0x01);
    pMUXMsg->CreateProfileSettingsReq.ProfileType = 0x00; // 0 ~ 3GPP, 1 ~ 3GPP2

    pTLV = (UCHAR *)(&pMUXMsg->CreateProfileSettingsReq + 1);


#if 0
    pPdpContext = (PQMIWDS_PDPCONTEXT)(pTLV + TLVLength);
    pPdpContext->TLVType = 0x25;
    pPdpContext->TLVLength = cpu_to_le16(0x01);
    pPdpContext->PdpContext = (1 == profile->pdp)? profile->pdp:(profile->pdp+8);
    TLVLength +=(le16_to_cpu(pPdpContext->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
#endif




    pPdpType = (PQMIWDS_PDPTYPE)(pTLV + TLVLength);
    pPdpType->TLVType = 0x11;
    pPdpType->TLVLength = cpu_to_le16(0x01);
// 0 ?C PDP-IP (IPv4)
// 1 ?C PDP-PPP
// 2 ?C PDP-IPv6
// 3 ?C PDP-IPv4v6
    if (profile->IsDualIPSupported)
        pPdpType->PdpType = 3;
    else if (profile->enable_ipv6)
        pPdpType->PdpType = 2;
    else
        pPdpType->PdpType = 0;
    TLVLength +=(le16_to_cpu(pPdpType->TLVLength) + sizeof(QCQMICTL_TLV_HDR));

    // Set APN Name
    if (profile->apn) {
        PQMIWDS_APNNAME pApnName = (PQMIWDS_APNNAME)(pTLV + TLVLength);
        pApnName->TLVType = 0x14;
        pApnName->TLVLength = cpu_to_le16(strlen(profile->apn));
        qstrcpy((char *)&pApnName->ApnName, profile->apn);
        TLVLength +=(le16_to_cpu(pApnName->TLVLength) + sizeof(QCQMICTL_TLV_HDR));
    }

    return sizeof(QMIWDS_CREATE_PROFILE_SETTINGS_REQ_MSG) + TLVLength;
}

#endif

static USHORT WdsGetRuntimeSettingReq(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->GetRuntimeSettingsReq.TLVType = 0x10;
    pMUXMsg->GetRuntimeSettingsReq.TLVLength = cpu_to_le16(0x04);
    // the following mask also applies to IPV6
    pMUXMsg->GetRuntimeSettingsReq.Mask = cpu_to_le32(QMIWDS_GET_RUNTIME_SETTINGS_MASK_IPV4DNS_ADDR |
                                          QMIWDS_GET_RUNTIME_SETTINGS_MASK_IPV4_ADDR |
                                          QMIWDS_GET_RUNTIME_SETTINGS_MASK_MTU |
                                          QMIWDS_GET_RUNTIME_SETTINGS_MASK_IPV4GATEWAY_ADDR); // |
    // QMIWDS_GET_RUNTIME_SETTINGS_MASK_PCSCF_SV_ADDR |
    // QMIWDS_GET_RUNTIME_SETTINGS_MASK_PCSCF_DOM_NAME;

    return sizeof(QMIWDS_GET_RUNTIME_SETTINGS_REQ_MSG);
}

static PQCQMIMSG s_pRequest;
static PQCQMIMSG s_pResponse;
static PQCQMIMSG s_pUnsolInd = NULL; //zpf

static pthread_mutex_t s_commandmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_commandcond = PTHREAD_COND_INITIALIZER;

static int is_response(const PQCQMIMSG pRequest, const PQCQMIMSG pResponse)
{
    if ((pRequest->QMIHdr.QMIType == pResponse->QMIHdr.QMIType)
        && (pRequest->QMIHdr.ClientId == pResponse->QMIHdr.ClientId)) {
        USHORT requestTID, responseTID;
        if (pRequest->QMIHdr.QMIType == QMUX_TYPE_CTL) {
            requestTID = pRequest->CTLMsg.QMICTLMsgHdr.TransactionId;
            responseTID = pResponse->CTLMsg.QMICTLMsgHdr.TransactionId;
        } else {
            requestTID = le16_to_cpu(pRequest->MUXMsg.QMUXHdr.TransactionId);
            responseTID = le16_to_cpu(pResponse->MUXMsg.QMUXHdr.TransactionId);
        }
        return (requestTID == responseTID);
    }
    return 0;
}


int (*qmidev_send)(PROFILE_T *profile, PQCQMIMSG pRequest);

int QmiThreadSendQMITimeout(PROFILE_T *profile, PQCQMIMSG pRequest, PQCQMIMSG *ppResponse, unsigned msecs)
{
    int ret;

    static int flag = 0;
    if (!flag) {
        cond_setclock_attr(&s_commandcond, CLOCK_MONOTONIC);
        flag = 1;
    }

    if (!pRequest)
        return -EINVAL;

    pthread_mutex_lock(&s_commandmutex);
    if (ppResponse)
        *ppResponse = NULL;

    dump_qmi(pRequest, le16_to_cpu(pRequest->QMIHdr.Length) + 1);

    s_pRequest = pRequest;
    s_pResponse = NULL;

    ret = qmidev_send(profile, pRequest);

    if (ret == 0) {
        ret = pthread_cond_timeout_np(&s_commandcond, &s_commandmutex, msecs);
        if (!ret) {
            if (s_pResponse && ppResponse) {
                *ppResponse = s_pResponse;
            } else {
                if (s_pResponse) {
                    free(s_pResponse);
                    s_pResponse = NULL;
                }
            }
        } else {
            dbg_time("%s pthread_cond_timeout_np timeout", __func__);
        }
    }

    pthread_mutex_unlock(&s_commandmutex);

    return ret;
}

int QmiThreadSendQMI(PROFILE_T *profile, PQCQMIMSG pRequest, PQCQMIMSG *ppResponse)
{
    return QmiThreadSendQMITimeout(profile, pRequest, ppResponse, 30 * 1000);
}



void* voiceNetworkStateChangeThreadTask(void *arg)
{
    CM_NAS_REG_STATE reg_state;
    CM_CS_ATTACH_STATE cs_state;
    CM_PS_ATTACH_STATE ps_state;
    PQMINAS_SERVING_SYSTEM_IND_MSG_TLV_SRV_SYS pServingSystemTlv = NULL;


    pServingSystemTlv = (PQMINAS_SERVING_SYSTEM_IND_MSG_TLV_SRV_SYS)GetTLV(&s_pUnsolInd->MUXMsg.QMUXMsgHdr, 0x01);
    if (pServingSystemTlv) {
        reg_state = pServingSystemTlv->RegistrationState;
        cs_state = pServingSystemTlv->CsAttachState;
        ps_state = pServingSystemTlv->PsAttachState;
        if (gCMDevContext.registerStateChanged)
        {
            gCMDevContext.registerStateChanged(reg_state, cs_state, ps_state);
        }
    }
    return (void*)NULL;
}

void OnVoiceNetworkStateChange(PQCQMIMSG pResponse)
{
    pthread_t callback_thread_id;
    pthread_attr_t cm_thread_attr;
    pthread_attr_init(&cm_thread_attr);
    pthread_attr_setdetachstate(&cm_thread_attr, PTHREAD_CREATE_DETACHED);

    if(pResponse->QMIHdr.QMIType != QMUX_TYPE_NAS) {
        return;
    }

    if (s_pUnsolInd) {
        free(s_pUnsolInd);
        s_pUnsolInd = NULL;
    }
    s_pUnsolInd = malloc(le16_to_cpu(pResponse->QMIHdr.Length) + 1);
    if (s_pUnsolInd == NULL) {
        dbg_time("fail malloc for s_pUnsolInd");
        return;
    }
    memcpy(s_pUnsolInd, pResponse, le16_to_cpu(pResponse->QMIHdr.Length) + 1);

    if (pthread_create( &callback_thread_id, &cm_thread_attr, voiceNetworkStateChangeThreadTask, (void *)(s_pUnsolInd)) != 0) {
        dbg_time("%s Failed to create meig_cm: %d (%s)", __func__, errno, strerror(errno));
    }


}

void* DataCallListChangeThreadTask(void *arg)
{


    int* pPdpIndex = (int*)arg;
    PQMIWDS_GET_PKT_SRVC_STATUS_IND_MSG_TLV_PSS pPacketServiceState = NULL;
    PQMIWDS_GET_PKT_SRVC_STATUS_IND_MSG_IP_FML pIpFamily= NULL;


    pPacketServiceState = (PQMIWDS_GET_PKT_SRVC_STATUS_IND_MSG_TLV_PSS)GetTLV(&s_pUnsolInd->MUXMsg.QMUXMsgHdr, 0x01);
    pIpFamily =  (PQMIWDS_GET_PKT_SRVC_STATUS_IND_MSG_IP_FML)GetTLV(&s_pUnsolInd->MUXMsg.QMUXMsgHdr, 0x12);
    if (pPacketServiceState && pIpFamily) {

        if(gCMDevContext.dataCallListChanged)   gCMDevContext.dataCallListChanged((*pPdpIndex), pIpFamily->IpFamily, pPacketServiceState->ConnectionStatus);
    }

    return (void*)NULL;

}

void OnDataCallListChange(PQCQMIMSG pResponse)
{
    int i;
    static int pdpIndex;
    pthread_attr_t cm_thread_attr;
    pthread_attr_init(&cm_thread_attr);
    pthread_attr_setdetachstate(&cm_thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_t callback_thread_id;
    if(pResponse->QMIHdr.QMIType != QMUX_TYPE_WDS) {
        return;
    }

    if (s_pUnsolInd) {
        free(s_pUnsolInd);
        s_pUnsolInd = NULL;
    }
    s_pUnsolInd = malloc(le16_to_cpu(pResponse->QMIHdr.Length) + 1);
    if (s_pUnsolInd == NULL) {
        dbg_time("fail malloc for s_pUnsolInd");
        return;
    }
    memcpy(s_pUnsolInd, pResponse, le16_to_cpu(pResponse->QMIHdr.Length) + 1);

    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
    pdpIndex = -1;
    for(i = 0; i < gCMDevContext.qmap_mode; i++) {
        if(pResponse->QMIHdr.ClientId == gCMDevContext.wdsClient[i].v4clientId && gCMDevContext.dataCallListChanged) {
            pdpIndex = i;
            break;
        }
    }
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */

    if(pdpIndex >= 0) {
        if (pthread_create( &callback_thread_id, &cm_thread_attr, DataCallListChangeThreadTask, (void *)(&pdpIndex)) != 0) {
            dbg_time("%s Failed to create meig_cm: %d (%s)", __func__, errno, strerror(errno));
        }
    }

}



void* QMIDeviceDisconnectedThreadTask(void *arg)
{
    if(gCMDevContext.hardwareRemoved) gCMDevContext.hardwareRemoved();
    return (void*)NULL;

}


void OnQMIDeviceDisconnected()
{
    int i;
    static int pdpIndex;
    pthread_attr_t cm_thread_attr;
    pthread_attr_init(&cm_thread_attr);
    pthread_attr_setdetachstate(&cm_thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_t callback_thread_id;

    if (pthread_create( &callback_thread_id, &cm_thread_attr, QMIDeviceDisconnectedThreadTask, NULL) != 0) {
            dbg_time("%s Failed to create meig_cm: %d (%s)", __func__, errno, strerror(errno));
     }

}

//
void QmiThreadRecvQMI(PQCQMIMSG pResponse)
{
    pthread_mutex_lock(&s_commandmutex);
    if (pResponse == NULL) {
        if (s_pRequest) {
            free(s_pRequest);
            s_pRequest = NULL;
            s_pResponse = NULL;
            pthread_cond_signal(&s_commandcond);
        }
        pthread_mutex_unlock(&s_commandmutex);
        return;
    }
    dump_qmi(pResponse, le16_to_cpu(pResponse->QMIHdr.Length) + 1);
    if (s_pRequest && is_response(s_pRequest, pResponse)) {
        free(s_pRequest);
        s_pRequest = NULL;
        s_pResponse = malloc(le16_to_cpu(pResponse->QMIHdr.Length) + 1);
        if (s_pResponse != NULL) {
            memcpy(s_pResponse, pResponse, le16_to_cpu(pResponse->QMIHdr.Length) + 1);
        }
        pthread_cond_signal(&s_commandcond);
    } else if ((pResponse->QMIHdr.QMIType == QMUX_TYPE_NAS)
               && (le16_to_cpu(pResponse->MUXMsg.QMUXMsgHdrResp.Type) == QMINAS_SERVING_SYSTEM_IND)) {
        //qmidevice_send_event_to_main(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED);
        OnVoiceNetworkStateChange(pResponse);
    } else if ((pResponse->QMIHdr.QMIType == QMUX_TYPE_WDS)
               && (le16_to_cpu(pResponse->MUXMsg.QMUXMsgHdrResp.Type) == QMIWDS_GET_PKT_SRVC_STATUS_IND)) {
        //qmidevice_send_event_to_main(RIL_UNSOL_DATA_CALL_LIST_CHANGED);
        OnDataCallListChange(pResponse);
    } else if ((pResponse->QMIHdr.QMIType == QMUX_TYPE_NAS)
               && (le16_to_cpu(pResponse->MUXMsg.QMUXMsgHdrResp.Type) == QMINAS_SYS_INFO_IND)) {
        qmidevice_send_event_to_main(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED);
        //OnVoiceNetworkStateChange(pResponse);
    } else {
        if (1) //zhangqingyun
            dbg_time("nobody care this qmi msg!!");
    }
    pthread_mutex_unlock(&s_commandmutex);
}

int requestSetEthMode(CM_DEV_CONTEXT *cmDevContext, int pdpIndex)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse = NULL;
    PQMUX_MSG pMUXMsg;
    int err;
    PQMIWDS_ADMIN_SET_DATA_FORMAT_TLV linkProto;
    UCHAR IpPreference;
    UCHAR autoconnect_setting = 0;
    QMAP_SETTING qmap_settings = {0, 0, 0, 0};
    dbg_time("%s[%d] entry", __FUNCTION__, __LINE__);
    
    if (cmDevContext->qmap_mode) {
        cmDevContext->rawIP = 1;
        s_9x07 = cmDevContext->rawIP;
        qmap_settings.MuxId = cmDevContext->profileList[pdpIndex].muxid;

        if (qmidev_is_pciemhi(cmDevContext->qmichannel)) { //SDX20_PCIE
            qmap_settings.rx_urb_size = 32*1024; //SDX24&SDX55 support 32KB
            qmap_settings.ep_type = DATA_EP_TYPE_PCIE;
            qmap_settings.iface_id = 0x04;
        } else { // for MDM9x07&MDM9x40&SDX20 USB
            qmap_settings.rx_urb_size = 32*1024; //SDX24&SDX55 support 32KB
            qmap_settings.ep_type = DATA_EP_TYPE_HSUSB;
        /*yufeilong add for modified automatic adaptive net port 221027 start*/
            qmap_settings.iface_id = 0x05;
            dbg_time("requestSetEthMode  iface_id = %d rx_urb_size is:%d\n", qmap_settings.iface_id,qmap_settings.rx_urb_size);
        /*yufeilong add for modified automatic adaptive net port 221027 end*/
        }

        if (qmidev_is_gobinet(cmDevContext->qmichannel)) { //GobiNet set data format in GobiNet driver
            goto skip_WdaSetDataFormat;
        } else if (cmDevContext->qmap_mode > 1) {//QMAP MUX enabled, set data format in meig-qmi-proxy
            goto skip_WdaSetDataFormat;
        }
    }
    
    pRequest = ComposeQMUXMsg(QMUX_TYPE_WDS_ADMIN, QMIWDS_ADMIN_SET_DATA_FORMAT_REQ, WdaSetDataFormat, (void *)&qmap_settings);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    linkProto = (PQMIWDS_ADMIN_SET_DATA_FORMAT_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x11);
    if (linkProto != NULL) {
        cmDevContext->rawIP = (le32_to_cpu(linkProto->Value) == 2);
        //s_9x07 = cmDevContext->rawIP;
    }

    linkProto = (PQMIWDS_ADMIN_SET_DATA_FORMAT_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x16);
    if (linkProto != NULL && cmDevContext->qmap_mode) {
        qmap_settings.rx_urb_size = le32_to_cpu(linkProto->Value);
        dbg_time("qmap_settings.rx_urb_size = %u", qmap_settings.rx_urb_size); //must same as rx_urb_size defined in GobiNet&qmi_wwan driver
    }

    free(pResponse);

skip_WdaSetDataFormat:
    if (cmDevContext->profileList[pdpIndex].enable_ipv6) {
        if (cmDevContext->profileList[pdpIndex].qmapnet_adapter) {
            // bind wds mux data port
            dbg_time("%s[%d] bind data port", __FUNCTION__, __LINE__);
            pRequest = ComposeQMUXMsg(QMUX_TYPE_WDS, QMIWDS_BIND_MUX_DATA_PORT_REQ, WdsSetQMUXBindMuxDataPort, (void *)&qmap_settings);
            err = QmiThreadSendQMI(&cmDevContext->profileList[pdpIndex], pRequest, &pResponse);
            qmi_rsp_check_and_return();
            if (pResponse) free(pResponse);
        }

        // set ipv6
        IpPreference = IpFamilyV6;
        pRequest = ComposeQMUXMsg( QMUX_TYPE_WDS_IPV6, QMIWDS_SET_CLIENT_IP_FAMILY_PREF_REQ, WdsSetClientIPFamilyPref, (void *)&IpPreference);
        err = QmiThreadSendQMI(&cmDevContext->profileList[pdpIndex], pRequest, &pResponse);
        qmi_rsp_check_and_return();
        if (pResponse) free(pResponse);
    } else {
        if (cmDevContext->profileList[pdpIndex].qmapnet_adapter) {
            // bind wds mux data port
            dbg_time("%s[%d] bind data port", __FUNCTION__, __LINE__);
            pRequest = ComposeQMUXMsg( QMUX_TYPE_WDS, QMIWDS_BIND_MUX_DATA_PORT_REQ, WdsSetQMUXBindMuxDataPort, (void *)&qmap_settings);
            err = QmiThreadSendQMI(&cmDevContext->profileList[pdpIndex], pRequest, &pResponse);
            qmi_rsp_check_and_return();
            if (pResponse) free(pResponse);
        }

        // set ipv4
        IpPreference = IpFamilyV4;
        pRequest = ComposeQMUXMsg( QMUX_TYPE_WDS, QMIWDS_SET_CLIENT_IP_FAMILY_PREF_REQ, WdsSetClientIPFamilyPref, (void *)&IpPreference);
        err = QmiThreadSendQMI(&cmDevContext->profileList[pdpIndex], pRequest, &pResponse);
        if (pResponse) free(pResponse);
    }

    if (cmDevContext->profileList[pdpIndex].IsDualIPSupported) {
        if (cmDevContext->profileList[pdpIndex].qmapnet_adapter) {
            // bind wds ipv6 mux data port
            dbg_time("%s[%d] bind data port", __FUNCTION__, __LINE__);
            pRequest = ComposeQMUXMsg( QMUX_TYPE_WDS_IPV6, QMIWDS_BIND_MUX_DATA_PORT_REQ, WdsSetQMUXBindMuxDataPort, (void *)&qmap_settings);
            err = QmiThreadSendQMI(&cmDevContext->profileList[pdpIndex], pRequest, &pResponse);
            qmi_rsp_check_and_return();
            if (pResponse) free(pResponse);
        }

        // set ipv6
        IpPreference = IpFamilyV6;
        pRequest = ComposeQMUXMsg( QMUX_TYPE_WDS_IPV6, QMIWDS_SET_CLIENT_IP_FAMILY_PREF_REQ, WdsSetClientIPFamilyPref, (void *)&IpPreference);
        err = QmiThreadSendQMI(&cmDevContext->profileList[pdpIndex], pRequest, &pResponse);
        qmi_rsp_check_and_return();
        if (pResponse) free(pResponse);
    }

    pRequest = ComposeQMUXMsg( QMUX_TYPE_WDS, QMIWDS_SET_AUTO_CONNECT_REQ, WdsSetAutoConnect, (void *)&autoconnect_setting);
    QmiThreadSendQMI(&cmDevContext->profileList[pdpIndex], pRequest, &pResponse);
    if (pResponse) free(pResponse);

    return 0;
}

#ifdef CONFIG_SIM
int requestGetPINStatus(CMSIM_Status *pSIMStatus)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    PQMIDMS_UIM_PIN_STATUS pPin1Status = NULL;
    //PQMIDMS_UIM_PIN_STATUS pPin2Status = NULL;

    if (s_9x07 && gCMDevContext.qmiclientId[QMUX_TYPE_UIM])
        pRequest = ComposeQMUXMsg(QMUX_TYPE_UIM, QMIUIM_GET_CARD_STATUS_REQ, NULL, NULL);
    else
        pRequest = ComposeQMUXMsg(QMUX_TYPE_DMS, QMIDMS_UIM_GET_PIN_STATUS_REQ, NULL, NULL);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    pPin1Status = (PQMIDMS_UIM_PIN_STATUS)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x11);
    //pPin2Status = (PQMIDMS_UIM_PIN_STATUS)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x12);

    if (pPin1Status != NULL) {
        if (pPin1Status->PINStatus == QMI_PIN_STATUS_NOT_VERIF) {
            *pSIMStatus = CM_SIM_PIN;
        } else if (pPin1Status->PINStatus == QMI_PIN_STATUS_BLOCKED) {
            *pSIMStatus = CM_SIM_PUK;
        } else if (pPin1Status->PINStatus == QMI_PIN_STATUS_PERM_BLOCKED) {
            *pSIMStatus = SIM_BAD;
        }
    }

    free(pResponse);
    return 0;
}

int CMRequestGetSIMStatus(CMSIM_Status *pSIMStatus)   //RIL_REQUEST_GET_SIM_STATUS
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    const char * CMSIM_Status_String[] = {
        "CM_SIM_ABSENT",
        "CM_SIM_NOT_READY",
        "CM_SIM_READY", /* CM_SIM_READY means the radio state is RADIO_STATE_CM_SIM_READY */
        "CM_SIM_PIN",
        "CM_SIM_PUK",
        "CM_SIM_NETWORK_PERSONALIZATION"
    };

    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    if (s_9x07 && gCMDevContext.qmiclientId[QMUX_TYPE_UIM])
        pRequest = ComposeQMUXMsg(QMUX_TYPE_UIM, QMIUIM_GET_CARD_STATUS_REQ, NULL, NULL);
    else
        pRequest = ComposeQMUXMsg(QMUX_TYPE_DMS, QMIDMS_UIM_GET_STATE_REQ, NULL, NULL);

    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    *pSIMStatus = CM_SIM_ABSENT;
    if (s_9x07 && gCMDevContext.qmiclientId[QMUX_TYPE_UIM]) {
        PQMIUIM_CARD_STATUS pCardStatus = NULL;
        PQMIUIM_PIN_STATE pPINState = NULL;
        UCHAR CardState = 0x01;
        UCHAR PIN1State = QMI_PIN_STATUS_NOT_VERIF;
        //UCHAR PIN1Retries;
        //UCHAR PUK1Retries;
        //UCHAR PIN2State;
        //UCHAR PIN2Retries;
        //UCHAR PUK2Retries;

        pCardStatus = (PQMIUIM_CARD_STATUS)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x10);
        if (pCardStatus != NULL) {
            pPINState = (PQMIUIM_PIN_STATE)((PUCHAR)pCardStatus + sizeof(QMIUIM_CARD_STATUS) + pCardStatus->AIDLength);
            CardState  = pCardStatus->CardState;
            if (pPINState->UnivPIN == 1) {
                PIN1State = pCardStatus->UPINState;
                //PIN1Retries = pCardStatus->UPINRetries;
                //PUK1Retries = pCardStatus->UPUKRetries;
            } else {
                PIN1State = pPINState->PIN1State;
                //PIN1Retries = pPINState->PIN1Retries;
                //PUK1Retries = pPINState->PUK1Retries;
            }
            //PIN2State = pPINState->PIN2State;
            //PIN2Retries = pPINState->PIN2Retries;
            //PUK2Retries = pPINState->PUK2Retries;
        }

        *pSIMStatus = CM_SIM_ABSENT;
        if ((CardState == 0x01) &&  ((PIN1State == QMI_PIN_STATUS_VERIFIED)|| (PIN1State == QMI_PIN_STATUS_DISABLED))) {
            *pSIMStatus = CM_SIM_READY;
        } else if (CardState == 0x01) {
            if (PIN1State == QMI_PIN_STATUS_NOT_VERIF) {
                *pSIMStatus = CM_SIM_PIN;
            }
            if ( PIN1State == QMI_PIN_STATUS_BLOCKED) {
                *pSIMStatus = CM_SIM_PUK;
            } else if (PIN1State == QMI_PIN_STATUS_PERM_BLOCKED) {
                *pSIMStatus = SIM_BAD;
            } else if (PIN1State == QMI_PIN_STATUS_NOT_INIT || PIN1State == QMI_PIN_STATUS_VERIFIED || PIN1State == QMI_PIN_STATUS_DISABLED) {
                *pSIMStatus = CM_SIM_READY;
            }
        } else if (CardState == 0x00 || CardState == 0x02) {
        } else {
        }
    } else {
        //UIM state. Values:
        // 0x00  UIM initialization completed
        // 0x01  UIM is locked or the UIM failed
        // 0x02  UIM is not present
        // 0x03  Reserved
        // 0xFF  UIM state is currently
        //unavailable
        if (pResponse->MUXMsg.UIMGetStateResp.UIMState == 0x00) {
            *pSIMStatus = CM_SIM_READY;
        } else if (pResponse->MUXMsg.UIMGetStateResp.UIMState == 0x01) {
            *pSIMStatus = CM_SIM_ABSENT;
            err = requestGetPINStatus(pSIMStatus);
        } else if ((pResponse->MUXMsg.UIMGetStateResp.UIMState == 0x02) || (pResponse->MUXMsg.UIMGetStateResp.UIMState == 0xFF)) {
            *pSIMStatus = CM_SIM_ABSENT;
        } else {
            *pSIMStatus = CM_SIM_ABSENT;
        }
    }
    dbg_time("%s SIMStatus: %s", __func__, CMSIM_Status_String[*pSIMStatus]);

    free(pResponse);

    return 0;
}

int CMRequestEnterSimPin(const CHAR *pPinCode)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;

    if (s_9x07 && gCMDevContext.qmiclientId[QMUX_TYPE_UIM])
        pRequest = ComposeQMUXMsg(QMUX_TYPE_UIM, QMIUIM_VERIFY_PIN_REQ, UimVerifyPinReqSend, (void *)pPinCode);
    else
        pRequest = ComposeQMUXMsg(QMUX_TYPE_DMS, QMIDMS_UIM_VERIFY_PIN_REQ, DmsUIMVerifyPinReqSend, (void *)pPinCode);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    free(pResponse);
    return 0;
}

#ifdef CONFIG_IMSI_ICCID
int requestGetICCID(void)   //RIL_REQUEST_GET_IMSI
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    PQMIUIM_CONTENT pUimContent;
    int err;

    if (s_9x07 && gCMDevContext.qmiclientId[QMUX_TYPE_UIM]) {
        pRequest = ComposeQMUXMsg(QMUX_TYPE_UIM, QMIUIM_READ_TRANSPARENT_REQ, UimReadTransparentIMSIReqSend, (void *)"EF_ICCID");
        err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    } else {
        return 0;
    }
    qmi_rsp_check_and_return();

    pUimContent = (PQMIUIM_CONTENT)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x11);
    if (pUimContent != NULL) {
        static char DeviceICCID[32] = {'\0'};
        int i = 0, j = 0;

        for (i = 0, j = 0; i < le16_to_cpu(pUimContent->content_len); ++i) {
            char charmaps[] = "0123456789ABCDEF";

            DeviceICCID[j++] = charmaps[(pUimContent->content[i] & 0x0F)];
            DeviceICCID[j++] = charmaps[((pUimContent->content[i] & 0xF0) >> 0x04)];
        }
        DeviceICCID[j] = '\0';

        dbg_time("%s DeviceICCID: %s", __func__, DeviceICCID);
    }

    free(pResponse);
    return 0;
}

int requestGetIMSI(void)   //RIL_REQUEST_GET_IMSI
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    PQMIUIM_CONTENT pUimContent;
    int err;

    if (s_9x07 && gCMDevContext.qmiclientId[QMUX_TYPE_UIM]) {
        pRequest = ComposeQMUXMsg(QMUX_TYPE_UIM, QMIUIM_READ_TRANSPARENT_REQ, UimReadTransparentIMSIReqSend, (void *)"EF_IMSI");
        err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    } else {
        return 0;
    }
    qmi_rsp_check_and_return();

    pUimContent = (PQMIUIM_CONTENT)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x11);
    if (pUimContent != NULL) {
        static char DeviceIMSI[32] = {'\0'};
        int i = 0, j = 0;

        for (i = 0, j = 0; i < le16_to_cpu(pUimContent->content[0]); ++i) {
            if (i != 0)
                DeviceIMSI[j++] = (pUimContent->content[i+1] & 0x0F) + '0';
            DeviceIMSI[j++] = ((pUimContent->content[i+1] & 0xF0) >> 0x04) + '0';
        }
        DeviceIMSI[j] = '\0';

        dbg_time("%s DeviceIMSI: %s", __func__, DeviceIMSI);
    }

    free(pResponse);
    return 0;
}
#endif
#endif

#if 1
static void meig_convert_cdma_mcc_2_ascii_mcc( USHORT *p_mcc, USHORT mcc )
{
    unsigned int d1, d2, d3, buf = mcc + 111;

    if ( mcc == 0x3FF ) { // wildcard
        *p_mcc = 3;
    } else {
        d3 = buf % 10;
        buf = ( d3 == 0 ) ? (buf-10)/10 : buf/10;

        d2 = buf % 10;
        buf = ( d2 == 0 ) ? (buf-10)/10 : buf/10;

        d1 = ( buf == 10 ) ? 0 : buf;

//dbg_time("d1:%d, d2:%d,d3:%d",d1,d2,d3);
        if ( d1<10 && d2<10 && d3<10 ) {
            *p_mcc = d1*100+d2*10+d3;
#if 0
            *(p_mcc+0) = '0' + d1;
            *(p_mcc+1) = '0' + d2;
            *(p_mcc+2) = '0' + d3;
#endif
        } else {
            //dbg_time( "invalid digits %d %d %d", d1, d2, d3 );
            *p_mcc = 0;
        }
    }
}

static void meig_convert_cdma_mnc_2_ascii_mnc( USHORT *p_mnc, USHORT imsi_11_12)
{
    unsigned int d1, d2, buf = imsi_11_12 + 11;

    if ( imsi_11_12 == 0x7F ) { // wildcard
        *p_mnc = 7;
    } else {
        d2 = buf % 10;
        buf = ( d2 == 0 ) ? (buf-10)/10 : buf/10;

        d1 = ( buf == 10 ) ? 0 : buf;

        if ( d1<10 && d2<10 ) {
            *p_mnc = d1*10 + d2;
        } else {
            //dbg_time( "invalid digits %d %d", d1, d2, 0 );
            *p_mnc = 0;
        }
    }
}

int requestGetHomeNetwork(USHORT *p_mcc, USHORT *p_mnc, USHORT *p_sid, USHORT *p_nid)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    PHOME_NETWORK pHomeNetwork;
    PHOME_NETWORK_SYSTEMID pHomeNetworkSystemID;

    pRequest = ComposeQMUXMsg(QMUX_TYPE_NAS, QMINAS_GET_HOME_NETWORK_REQ, NULL, NULL);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    pHomeNetwork = (PHOME_NETWORK)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x01);
    if (pHomeNetwork && p_mcc && p_mnc ) {
        *p_mcc = le16_to_cpu(pHomeNetwork->MobileCountryCode);
        *p_mnc = le16_to_cpu(pHomeNetwork->MobileNetworkCode);
        //dbg_time("%s MobileCountryCode: %d, MobileNetworkCode: %d", __func__, *pMobileCountryCode, *pMobileNetworkCode);
    }

    pHomeNetworkSystemID = (PHOME_NETWORK_SYSTEMID)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x10);
    if (pHomeNetworkSystemID && p_sid && p_nid) {
        *p_sid = le16_to_cpu(pHomeNetworkSystemID->SystemID); //china-hefei: sid 14451
        *p_nid = le16_to_cpu(pHomeNetworkSystemID->NetworkID);
        //dbg_time("%s SystemID: %d, NetworkID: %d", __func__, *pSystemID, *pNetworkID);
    }

    free(pResponse);

    return 0;
}
#endif

#if 0
// Lookup table for carriers known to produce SIMs which incorrectly indicate MNC length.
static const char * MCCMNC_CODES_HAVING_3DIGITS_MNC[] = {
    "302370", "302720", "310260",
    "405025", "405026", "405027", "405028", "405029", "405030", "405031", "405032",
    "405033", "405034", "405035", "405036", "405037", "405038", "405039", "405040",
    "405041", "405042", "405043", "405044", "405045", "405046", "405047", "405750",
    "405751", "405752", "405753", "405754", "405755", "405756", "405799", "405800",
    "405801", "405802", "405803", "405804", "405805", "405806", "405807", "405808",
    "405809", "405810", "405811", "405812", "405813", "405814", "405815", "405816",
    "405817", "405818", "405819", "405820", "405821", "405822", "405823", "405824",
    "405825", "405826", "405827", "405828", "405829", "405830", "405831", "405832",
    "405833", "405834", "405835", "405836", "405837", "405838", "405839", "405840",
    "405841", "405842", "405843", "405844", "405845", "405846", "405847", "405848",
    "405849", "405850", "405851", "405852", "405853", "405875", "405876", "405877",
    "405878", "405879", "405880", "405881", "405882", "405883", "405884", "405885",
    "405886", "405908", "405909", "405910", "405911", "405912", "405913", "405914",
    "405915", "405916", "405917", "405918", "405919", "405920", "405921", "405922",
    "405923", "405924", "405925", "405926", "405927", "405928", "405929", "405930",
    "405931", "405932", "502142", "502143", "502145", "502146", "502147", "502148"
};

static const char * MCC_CODES_HAVING_3DIGITS_MNC[] = {
    "302",    //Canada
    "310",    //United States of America
    "311",    //United States of America
    "312",    //United States of America
    "313",    //United States of America
    "314",    //United States of America
    "315",    //United States of America
    "316",    //United States of America
    "334",    //Mexico
    "338",    //Jamaica
    "342", //Barbados
    "344",    //Antigua and Barbuda
    "346",    //Cayman Islands
    "348",    //British Virgin Islands
    "365",    //Anguilla
    "708",    //Honduras (Republic of)
    "722",    //Argentine Republic
    "732"    //Colombia (Republic of)
};

int requestGetIMSI(const char **pp_imsi, USHORT *pMobileCountryCode, USHORT *pMobileNetworkCode)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;

    if (pp_imsi) *pp_imsi = NULL;
    if (pMobileCountryCode) *pMobileCountryCode = 0;
    if (pMobileNetworkCode) *pMobileNetworkCode = 0;

    pRequest = ComposeQMUXMsg(QMUX_TYPE_DMS, QMIDMS_UIM_GET_IMSI_REQ, NULL, NULL);
    err = QmiThreadSendQMI(pRequest, &pResponse);
    qmi_rsp_check_and_return();

    if (pMUXMsg->UIMGetIMSIResp.TLV2Type == 0x01 &&  le16_to_cpu(pMUXMsg->UIMGetIMSIResp.TLV2Length) >= 5) {
        int mnc_len = 2;
        unsigned i;
        char tmp[4];

        if (pp_imsi) *pp_imsi = strndup((const char *)(&pMUXMsg->UIMGetIMSIResp.IMSI), le16_to_cpu(pMUXMsg->UIMGetIMSIResp.TLV2Length));

        for (i = 0; i < sizeof(MCCMNC_CODES_HAVING_3DIGITS_MNC)/sizeof(MCCMNC_CODES_HAVING_3DIGITS_MNC[0]); i++) {
            if (!strncmp((const char *)(&pMUXMsg->UIMGetIMSIResp.IMSI), MCCMNC_CODES_HAVING_3DIGITS_MNC[i], 6)) {
                mnc_len = 3;
                break;
            }
        }
        if (mnc_len == 2) {
            for (i = 0; i < sizeof(MCC_CODES_HAVING_3DIGITS_MNC)/sizeof(MCC_CODES_HAVING_3DIGITS_MNC[0]); i++) {
                if (!strncmp((const char *)(&pMUXMsg->UIMGetIMSIResp.IMSI), MCC_CODES_HAVING_3DIGITS_MNC[i], 3)) {
                    mnc_len = 3;
                    break;
                }
            }
        }

        tmp[0] = (&pMUXMsg->UIMGetIMSIResp.IMSI)[0];
        tmp[1] = (&pMUXMsg->UIMGetIMSIResp.IMSI)[1];
        tmp[2] = (&pMUXMsg->UIMGetIMSIResp.IMSI)[2];
        tmp[3] = 0;
        if (pMobileCountryCode) *pMobileCountryCode = atoi(tmp);
        tmp[0] = (&pMUXMsg->UIMGetIMSIResp.IMSI)[3];
        tmp[1] = (&pMUXMsg->UIMGetIMSIResp.IMSI)[4];
        tmp[2] = 0;
        if (mnc_len == 3) {
            tmp[2] = (&pMUXMsg->UIMGetIMSIResp.IMSI)[6];
        }
        if (pMobileNetworkCode) *pMobileNetworkCode = atoi(tmp);
    }

    free(pResponse);

    return 0;
}
#endif

struct wwan_data_class_str class2str[] = {
    {WWAN_DATA_CLASS_NONE, "UNKNOWN"},
    {WWAN_DATA_CLASS_GPRS, "GPRS"},
    {WWAN_DATA_CLASS_EDGE, "EDGE"},
    {WWAN_DATA_CLASS_UMTS, "UMTS"},
    {WWAN_DATA_CLASS_HSDPA, "HSDPA"},
    {WWAN_DATA_CLASS_HSUPA, "HSUPA"},
    {WWAN_DATA_CLASS_LTE, "LTE"},
    {WWAN_DATA_CLASS_1XRTT, "1XRTT"},
    {WWAN_DATA_CLASS_1XEVDO, "1XEVDO"},
    {WWAN_DATA_CLASS_1XEVDO_REVA, "1XEVDO_REVA"},
    {WWAN_DATA_CLASS_1XEVDV, "1XEVDV"},
    {WWAN_DATA_CLASS_3XRTT, "3XRTT"},
    {WWAN_DATA_CLASS_1XEVDO_REVB, "1XEVDO_REVB"},
    {WWAN_DATA_CLASS_UMB, "UMB"},
    /*[zhaopf@meigsmart-2020-1029]add for NR5G { */
    {WWAN_DATA_CLASS_NR5G, "NR5G"},
    /*[zhaopf@meigsmart-2020-1029]add for NR5G } */
    {WWAN_DATA_CLASS_CUSTOM, "CUSTOM"},
};

CHAR *wwan_data_class2str(ULONG class)
{
    unsigned int i = 0;
    for (i = 0; i < sizeof(class2str)/sizeof(class2str[0]); i++) {
        if (class2str[i].class == class) {
            return class2str[i].str;
        }
    }
    return "UNKNOWN";
}

int requestRegistrationState2(UCHAR *pPSAttachedState)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    USHORT MobileCountryCode = 0;
    USHORT MobileNetworkCode = 0;
    const char *pDataCapStr = "UNKNOW";
    LONG remainingLen;
    PSERVICE_STATUS_INFO pServiceStatusInfo;
    int is_lte = 0;
    PCDMA_SYSTEM_INFO pCdmaSystemInfo;
    PHDR_SYSTEM_INFO pHdrSystemInfo;
    PGSM_SYSTEM_INFO pGsmSystemInfo;
    PWCDMA_SYSTEM_INFO pWcdmaSystemInfo;
    PLTE_SYSTEM_INFO pLteSystemInfo;
    PTDSCDMA_SYSTEM_INFO pTdscdmaSystemInfo;
    /*[zhaopf@meigsmart-2020-1029]add for NR5G { */
    PNR5G_SYSTEM_INFO pNr5gSystemInfo;
    PNR5G_SERVICE_STATUS pNr5gServiceStatus;
    UCHAR fiveGPSAttachedState = 0;
    /*[zhaopf@meigsmart-2020-1029]add for NR5G } */

    UCHAR DeviceClass = 0;
    ULONG DataCapList = 0;

    *pPSAttachedState = 0;
    pRequest = ComposeQMUXMsg(QMUX_TYPE_NAS, QMINAS_GET_SYS_INFO_REQ, NULL, NULL);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    pServiceStatusInfo = (PSERVICE_STATUS_INFO)(((PCHAR)&pMUXMsg->GetSysInfoResp) + QCQMUX_MSG_HDR_SIZE);
    remainingLen = le16_to_cpu(pMUXMsg->GetSysInfoResp.Length);

    s_is_cdma = 0;
    s_hdr_personality = 0;
    while (remainingLen > 0) {
        switch (pServiceStatusInfo->TLVType) {
        case 0x10: // CDMA
            if (pServiceStatusInfo->SrvStatus == 0x02) {
                DataCapList = WWAN_DATA_CLASS_1XRTT|
                              WWAN_DATA_CLASS_1XEVDO|
                              WWAN_DATA_CLASS_1XEVDO_REVA|
                              WWAN_DATA_CLASS_1XEVDV|
                              WWAN_DATA_CLASS_1XEVDO_REVB;
                DeviceClass = DEVICE_CLASS_CDMA;
                s_is_cdma = (0 == is_lte);
            }
            break;
        case 0x11: // HDR
            if (pServiceStatusInfo->SrvStatus == 0x02) {
                DataCapList = WWAN_DATA_CLASS_3XRTT|
                              WWAN_DATA_CLASS_UMB;
                DeviceClass = DEVICE_CLASS_CDMA;
                s_is_cdma = (0 == is_lte);
            }
            break;
        case 0x12: // GSM
            if (pServiceStatusInfo->SrvStatus == 0x02) {
                DataCapList = WWAN_DATA_CLASS_GPRS|
                              WWAN_DATA_CLASS_EDGE;
                DeviceClass = DEVICE_CLASS_GSM;
            }
            break;
        case 0x13: // WCDMA
            if (pServiceStatusInfo->SrvStatus == 0x02) {
                DataCapList = WWAN_DATA_CLASS_UMTS;
                DeviceClass = DEVICE_CLASS_GSM;
            }
            break;
        case 0x14: // LTE
            if (pServiceStatusInfo->SrvStatus == 0x02) {
                DataCapList = WWAN_DATA_CLASS_LTE;
                DeviceClass = DEVICE_CLASS_GSM;
                is_lte = 1;
                s_is_cdma = 0;
            }
            break;
        case 0x24: // TDSCDMA
            if (pServiceStatusInfo->SrvStatus == 0x02) {
                pDataCapStr = "TD-SCDMA";
            }
            break;
        case 0x15: // CDMA
            // CDMA_SYSTEM_INFO
            pCdmaSystemInfo = (PCDMA_SYSTEM_INFO)pServiceStatusInfo;
            if (pCdmaSystemInfo->SrvDomainValid == 0x01) {
                *pPSAttachedState = 0;
                if (pCdmaSystemInfo->SrvDomain & 0x02) {
                    *pPSAttachedState = 1;
                    s_is_cdma = (0 == is_lte);
                }
            }
#if 0
            if (pCdmaSystemInfo->SrvCapabilityValid == 0x01) {
                *pPSAttachedState = 0;
                if (pCdmaSystemInfo->SrvCapability & 0x02) {
                    *pPSAttachedState = 1;
                    s_is_cdma = (0 == is_lte);
                }
            }
#endif
            if (pCdmaSystemInfo->NetworkIdValid == 0x01) {
                int i;
                CHAR temp[10];
                strncpy(temp, (CHAR *)pCdmaSystemInfo->MCC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileCountryCode = (USHORT)atoi(temp);

                strncpy(temp, (CHAR *)pCdmaSystemInfo->MNC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileNetworkCode = (USHORT)atoi(temp);
            }
            break;
        case 0x16: // HDR
            // HDR_SYSTEM_INFO
            pHdrSystemInfo = (PHDR_SYSTEM_INFO)pServiceStatusInfo;
            if (pHdrSystemInfo->SrvDomainValid == 0x01) {
                *pPSAttachedState = 0;
                if (pHdrSystemInfo->SrvDomain & 0x02) {
                    *pPSAttachedState = 1;
                    s_is_cdma = (0 == is_lte);
                }
            }
#if 0
            if (pHdrSystemInfo->SrvCapabilityValid == 0x01) {
                *pPSAttachedState = 0;
                if (pHdrSystemInfo->SrvCapability & 0x02) {
                    *pPSAttachedState = 1;
                    s_is_cdma = (0 == is_lte);
                }
            }
#endif
            if (*pPSAttachedState && pHdrSystemInfo->HdrPersonalityValid == 0x01) {
                if (pHdrSystemInfo->HdrPersonality == 0x03)
                    s_hdr_personality = 0x02;
                //else if (pHdrSystemInfo->HdrPersonality == 0x02)
                //    s_hdr_personality = 0x01;
            }
            USHORT cmda_mcc = 0, cdma_mnc = 0;
            if(!requestGetHomeNetwork(&cmda_mcc, &cdma_mnc,NULL, NULL) && cmda_mcc) {
                meig_convert_cdma_mcc_2_ascii_mcc(&MobileCountryCode, cmda_mcc);
                meig_convert_cdma_mnc_2_ascii_mnc(&MobileNetworkCode, cdma_mnc);
            }
            break;
        case 0x17: // GSM
            // GSM_SYSTEM_INFO
            pGsmSystemInfo = (PGSM_SYSTEM_INFO)pServiceStatusInfo;
            if (pGsmSystemInfo->SrvDomainValid == 0x01) {
                *pPSAttachedState = 0;
                if (pGsmSystemInfo->SrvDomain & 0x02) {
                    *pPSAttachedState = 1;
                }
            }
#if 0
            if (pGsmSystemInfo->SrvCapabilityValid == 0x01) {
                *pPSAttachedState = 0;
                if (pGsmSystemInfo->SrvCapability & 0x02) {
                    *pPSAttachedState = 1;
                }
            }
#endif
            if (pGsmSystemInfo->NetworkIdValid == 0x01) {
                int i;
                CHAR temp[10];
                strncpy(temp, (CHAR *)pGsmSystemInfo->MCC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileCountryCode = (USHORT)atoi(temp);

                strncpy(temp, (CHAR *)pGsmSystemInfo->MNC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileNetworkCode = (USHORT)atoi(temp);
            }
            break;
        case 0x18: // WCDMA
            // WCDMA_SYSTEM_INFO
            pWcdmaSystemInfo = (PWCDMA_SYSTEM_INFO)pServiceStatusInfo;
            if (pWcdmaSystemInfo->SrvDomainValid == 0x01) {
                *pPSAttachedState = 0;
                if (pWcdmaSystemInfo->SrvDomain & 0x02) {
                    *pPSAttachedState = 1;
                }
            }
#if 0
            if (pWcdmaSystemInfo->SrvCapabilityValid == 0x01) {
                *pPSAttachedState = 0;
                if (pWcdmaSystemInfo->SrvCapability & 0x02) {
                    *pPSAttachedState = 1;
                }
            }
#endif
            if (pWcdmaSystemInfo->NetworkIdValid == 0x01) {
                int i;
                CHAR temp[10];
                strncpy(temp, (CHAR *)pWcdmaSystemInfo->MCC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileCountryCode = (USHORT)atoi(temp);

                strncpy(temp, (CHAR *)pWcdmaSystemInfo->MNC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileNetworkCode = (USHORT)atoi(temp);
            }
            break;
        case 0x19: // LTE_SYSTEM_INFO
            // LTE_SYSTEM_INFO
            pLteSystemInfo = (PLTE_SYSTEM_INFO)pServiceStatusInfo;
            if (pLteSystemInfo->SrvDomainValid == 0x01) {
                *pPSAttachedState = 0;
                if (pLteSystemInfo->SrvDomain & 0x02) {
                    *pPSAttachedState = 1;
                    is_lte = 1;
                    s_is_cdma = 0;
                }
            }
#if 0
            if (pLteSystemInfo->SrvCapabilityValid == 0x01) {
                *pPSAttachedState = 0;
                if (pLteSystemInfo->SrvCapability & 0x02) {
                    *pPSAttachedState = 1;
                    is_lte = 1;
                    s_is_cdma = 0;
                }
            }
#endif
            if (pLteSystemInfo->NetworkIdValid == 0x01) {
                int i;
                CHAR temp[10];
                strncpy(temp, (CHAR *)pLteSystemInfo->MCC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileCountryCode = (USHORT)atoi(temp);

                strncpy(temp, (CHAR *)pLteSystemInfo->MNC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileNetworkCode = (USHORT)atoi(temp);
            }
            break;
        case 0x25: // TDSCDMA
            // TDSCDMA_SYSTEM_INFO
            pTdscdmaSystemInfo = (PTDSCDMA_SYSTEM_INFO)pServiceStatusInfo;
            if (pTdscdmaSystemInfo->SrvDomainValid == 0x01) {
                *pPSAttachedState = 0;
                if (pTdscdmaSystemInfo->SrvDomain & 0x02) {
                    *pPSAttachedState = 1;
                }
            }
#if 0
            if (pTdscdmaSystemInfo->SrvCapabilityValid == 0x01) {
                *pPSAttachedState = 0;
                if (pTdscdmaSystemInfo->SrvCapability & 0x02) {
                    *pPSAttachedState = 1;
                }
            }
#endif
            if (pTdscdmaSystemInfo->NetworkIdValid == 0x01) {
                int i;
                CHAR temp[10];
                strncpy(temp, (CHAR *)pTdscdmaSystemInfo->MCC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileCountryCode = (USHORT)atoi(temp);

                strncpy(temp, (CHAR *)pTdscdmaSystemInfo->MNC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileNetworkCode = (USHORT)atoi(temp);
            }
            break;
        /*[zhaopf@megismart-2020-1029] add for 5GNR { */
        case 0x4a: //NR5G service status
            pNr5gServiceStatus = (PNR5G_SERVICE_STATUS)pServiceStatusInfo;
            if(pNr5gServiceStatus->SrvStatus & 0x2) {
                fiveGPSAttachedState = 1;
            } else {
                fiveGPSAttachedState = 0;
            }
            if(pNr5gServiceStatus->TrueSrvsStatus & 0x2) {
                fiveGPSAttachedState = 1;
            } else {
                fiveGPSAttachedState = 0;
            }


            dbg_time("%s SrvStatus = %d, TrueSrvsStatus = %d", __func__, pNr5gServiceStatus->SrvStatus, pNr5gServiceStatus->TrueSrvsStatus);
            break;
        case 0x4b: //NR5G System info
            pNr5gSystemInfo = (PNR5G_SYSTEM_INFO)pServiceStatusInfo;
            if (pNr5gSystemInfo->SrvDomainValid == 0x01) {
                fiveGPSAttachedState = 0;
                if (pNr5gSystemInfo->SrvDomain & 0x02) {
                    fiveGPSAttachedState = 1;
                }
            }
            if (pNr5gSystemInfo->SrvCapabilityValid == 0x01) {
                fiveGPSAttachedState = 0;
                if (pNr5gSystemInfo->SrvCapability & 0x02) {
                    fiveGPSAttachedState = 1;
                }
            }


            dbg_time("%s SrvDomainValid = %d, SrvDomain = %d", __func__, pNr5gSystemInfo->SrvDomainValid, pNr5gSystemInfo->SrvDomain);
            dbg_time("%s SrvCapabilityValid = %d, SrvCapability = %d", __func__, pNr5gSystemInfo->SrvCapabilityValid, pNr5gSystemInfo->SrvCapability);


            if (pNr5gSystemInfo->NetworkIdValid == 0x01) {
                int i;
                CHAR temp[10];
                strncpy(temp, (CHAR *)pNr5gSystemInfo->MCC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileCountryCode = (USHORT)atoi(temp);

                strncpy(temp, (CHAR *)pNr5gSystemInfo->MNC, 3);
                temp[3] = '\0';
                for (i = 0; i < 4; i++) {
                    if ((UCHAR)temp[i] == 0xFF) {
                        temp[i] = '\0';
                    }
                }
                MobileNetworkCode = (USHORT)atoi(temp);
            }
            break;
        /*[zhaopf@megismart-2020-1029] add for 5GNR } */
        default:
            break;
        } /* switch (pServiceStatusInfo->TLYType) */
        remainingLen -= (le16_to_cpu(pServiceStatusInfo->TLVLength) + 3);
        pServiceStatusInfo = (PSERVICE_STATUS_INFO)((PCHAR)&pServiceStatusInfo->TLVLength + le16_to_cpu(pServiceStatusInfo->TLVLength) + sizeof(USHORT));
    } /* while (remainingLen > 0) */
    /*[zhaopf@megismart-2020-1029] add for 5GNR { */
    if(fiveGPSAttachedState) {
        DataCapList = WWAN_DATA_CLASS_NR5G;
        DeviceClass = DEVICE_CLASS_NR5G;
    }
    /*[zhaopf@megismart-2020-1029] add for 5GNR } */
    if (DeviceClass == DEVICE_CLASS_CDMA) {
        if (s_hdr_personality == 2) {
            pDataCapStr = s_hdr_personality == 2 ? "eHRPD" : "HRPD";
        } else if (DataCapList & WWAN_DATA_CLASS_1XEVDO_REVB) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_1XEVDO_REVB);
        } else if (DataCapList & WWAN_DATA_CLASS_1XEVDO_REVA) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_1XEVDO_REVA);
        } else if (DataCapList & WWAN_DATA_CLASS_1XEVDO) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_1XEVDO);
        } else if (DataCapList & WWAN_DATA_CLASS_1XRTT) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_1XRTT);
        } else if (DataCapList & WWAN_DATA_CLASS_3XRTT) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_3XRTT);
        } else if (DataCapList & WWAN_DATA_CLASS_UMB) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_UMB);
        }
    } else {
        if (DataCapList & WWAN_DATA_CLASS_LTE) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_LTE);
        } else if ((DataCapList & WWAN_DATA_CLASS_HSDPA) && (DataCapList & WWAN_DATA_CLASS_HSUPA)) {
            pDataCapStr = "HSDPA_HSUPA";
        } else if (DataCapList & WWAN_DATA_CLASS_HSDPA) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_HSDPA);
        } else if (DataCapList & WWAN_DATA_CLASS_HSUPA) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_HSUPA);
        } else if (DataCapList & WWAN_DATA_CLASS_UMTS) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_UMTS);
        } else if (DataCapList & WWAN_DATA_CLASS_EDGE) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_EDGE);
        } else if (DataCapList & WWAN_DATA_CLASS_GPRS) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_GPRS);
            /*[zhaopf@meigsmart-2020-1029]add for 5G { */
        } else if(DataCapList & WWAN_DATA_CLASS_NR5G) {
            pDataCapStr = wwan_data_class2str(WWAN_DATA_CLASS_NR5G);
        }
        /*[zhaopf@meigsmart-2020-1029]add for 5G } */
    }
    /*[zhaopf@meigsmart-2020-1029]add for 5G { */
    if(fiveGPSAttachedState) {
        *pPSAttachedState = 1;
    }
    /*[zhaopf@meigsmart-2020-1029]add for 5G } */
    dbg_time("%s MCC: %d, MNC: %d, PS: %s, DataCap: %s", __func__,
             MobileCountryCode, MobileNetworkCode, (*pPSAttachedState == 1) ? "Attached" : "Detached", pDataCapStr);

    free(pResponse);

    return 0;
}

int requestRegistrationState(UCHAR *pPSAttachedState)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    PQMINAS_CURRENT_PLMN_MSG pCurrentPlmn;
    PSERVING_SYSTEM pServingSystem;
    PQMINAS_DATA_CAP pDataCap;
    USHORT MobileCountryCode = 0;
    USHORT MobileNetworkCode = 0;
    const char *pDataCapStr = "UNKNOW";

    if (s_9x07) {
        return requestRegistrationState2(pPSAttachedState);
    }

    pRequest = ComposeQMUXMsg(QMUX_TYPE_NAS, QMINAS_GET_SERVING_SYSTEM_REQ, NULL, NULL);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    pCurrentPlmn = (PQMINAS_CURRENT_PLMN_MSG)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x12);
    if (pCurrentPlmn) {
        MobileCountryCode = le16_to_cpu(pCurrentPlmn->MobileCountryCode);
        MobileNetworkCode = le16_to_cpu(pCurrentPlmn->MobileNetworkCode);
    }

    *pPSAttachedState = 0;
    pServingSystem = (PSERVING_SYSTEM)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x01);
    if (pServingSystem) {
        //Packet-switched domain attach state of the mobile.
        //0x00    PS_UNKNOWN ?Unknown or not applicable
        //0x01    PS_ATTACHED ?Attached
        //0x02    PS_DETACHED ?Detached
        *pPSAttachedState = pServingSystem->RegistrationState;
        if (pServingSystem->RegistrationState == 0x01) //0x01 ?C REGISTERED ?C Registered with a network
            *pPSAttachedState  = pServingSystem->PSAttachedState;
        else {
            //MobileCountryCode = MobileNetworkCode = 0;
            *pPSAttachedState  = 0x02;
        }
    }

    pDataCap = (PQMINAS_DATA_CAP)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x11);
    if (pDataCap && pDataCap->DataCapListLen) {
        UCHAR *DataCap = &pDataCap->DataCap;
        if (pDataCap->DataCapListLen == 2) {
            if ((DataCap[0] == 0x06) && ((DataCap[1] == 0x08) || (DataCap[1] == 0x0A)))
                DataCap[0] = DataCap[1];
        }
        switch (DataCap[0]) {
        case 0x01:
            pDataCapStr = "GPRS";
            break;
        case 0x02:
            pDataCapStr = "EDGE";
            break;
        case 0x03:
            pDataCapStr = "HSDPA";
            break;
        case 0x04:
            pDataCapStr = "HSUPA";
            break;
        case 0x05:
            pDataCapStr = "UMTS";
            break;
        case 0x06:
            pDataCapStr = "1XRTT";
            break;
        case 0x07:
            pDataCapStr = "1XEVDO";
            break;
        case 0x08:
            pDataCapStr = "1XEVDO_REVA";
            break;
        case 0x09:
            pDataCapStr = "GPRS";
            break;
        case 0x0A:
            pDataCapStr = "1XEVDO_REVB";
            break;
        case 0x0B:
            pDataCapStr = "LTE";
            break;
        case 0x0C:
            pDataCapStr = "HSDPA";
            break;
        case 0x0D:
            pDataCapStr = "HSDPA";
            break;
        default:
            pDataCapStr = "UNKNOW";
            break;
        }
    }

    if (pServingSystem && pServingSystem->RegistrationState == 0x01 && pServingSystem->InUseRadioIF && pServingSystem->RadioIF == 0x09) {
        pDataCapStr = "TD-SCDMA";
    }

    s_is_cdma = 0;
    if (pServingSystem && pServingSystem->RegistrationState == 0x01 && pServingSystem->InUseRadioIF && (pServingSystem->RadioIF == 0x01 || pServingSystem->RadioIF == 0x02)) {
        USHORT cmda_mcc = 0, cdma_mnc = 0;
        s_is_cdma = 1;
        if(!requestGetHomeNetwork(&cmda_mcc, &cdma_mnc,NULL, NULL) && cmda_mcc) {
            meig_convert_cdma_mcc_2_ascii_mcc(&MobileCountryCode, cmda_mcc);
            meig_convert_cdma_mnc_2_ascii_mnc(&MobileNetworkCode, cdma_mnc);
        }
        if (1) {
            PQCQMUX_TLV pTLV = (PQCQMUX_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x23);
            if (pTLV)
                s_hdr_personality = pTLV->Value;
            else
                s_hdr_personality = 0;
            if (s_hdr_personality == 2)
                pDataCapStr = "eHRPD";
        }
    }

    dbg_time("%s MCC: %d, MNC: %d, PS: %s, DataCap: %s", __func__,
             MobileCountryCode, MobileNetworkCode, (*pPSAttachedState == 1) ? "Attached" : "Detached", pDataCapStr);

    free(pResponse);

    return 0;
}

int requestQueryDataCall(int pdpIndex, unsigned char  *pConnectionStatus, int curIpFamily)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    PQMIWDS_PKT_SRVC_TLV pPktSrvc;
    UCHAR oldConnectionStatus = *pConnectionStatus;
    UCHAR QMIType = (curIpFamily == IpFamilyV4) ? QMUX_TYPE_WDS : QMUX_TYPE_WDS_IPV6;
    pRequest = ComposeQMUXMsg(QMIType, QMIWDS_GET_PKT_SRVC_STATUS_REQ, NULL, NULL);
    err = QmiThreadSendQMI(&gCMDevContext.profileList[pdpIndex], pRequest, &pResponse);
    qmi_rsp_check_and_return();

    *pConnectionStatus = QWDS_PKT_DATA_DISCONNECTED;
    pPktSrvc = (PQMIWDS_PKT_SRVC_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x01);
    if (pPktSrvc) {
        *pConnectionStatus = pPktSrvc->ConnectionStatus;
        if ((le16_to_cpu(pPktSrvc->TLVLength) == 2) && (pPktSrvc->ReconfigReqd == 0x01))
            *pConnectionStatus = QWDS_PKT_DATA_DISCONNECTED;
    }

    if (*pConnectionStatus == QWDS_PKT_DATA_DISCONNECTED) {
        if (curIpFamily == IpFamilyV4)
            gCMDevContext.wdsConnV4HandleList[pdpIndex] = 0;
        else
            gCMDevContext.wdsConnV6HandleList[pdpIndex]  = 0;
    }

    if (oldConnectionStatus != *pConnectionStatus || debug_qmi) {
        dbg_time("%s %sConnectionStatus: %s", __func__, (curIpFamily == IpFamilyV4) ? "IPv4" : "IPv6",
                 (*pConnectionStatus == QWDS_PKT_DATA_CONNECTED) ? "CONNECTED" : "DISCONNECTED");
    }

    free(pResponse);
    return 0;
}
/*zhangqingyun add for support esim 2023-7-20 start*/
#if 0
int requestSimOpenChannel(int p2, unsigned char* buffer, unsigned short length,int* result,int* select_response_length){
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;
	int i = 0;
	PQMIUIM_OPEN_CHANNEL_RESPONSE_TLV    pOpenChannelResponse;
	PQMIUIM_OPEN_CHANNEL_RESPONSE_SW_TLV pOpenChannel_Sw_Response;
	PQMIUIM_OPEN_CHANNEL_SELECT_RESPONSE_TLV pOpenChannel_select_Response;
	QMI_UIM_DATA_TYPE qmi_uim_channel_data;
	qmi_uim_channel_data.data_len = length; // uint16 to uin8?
	qmi_uim_channel_data.data_ptr = buffer;
    qmi_uim_channel_data.fci_value = p2 == -1? p2 : p2ToFciValue(p2);
	UCHAR QMIType = QMUX_TYPE_UIM;//qualcom 80-nv304-12.pdf
	dbg_time("%s buffer[0] is: 0x%x, length = %d, p2 = %d, fci = %d\n", __FUNCTION__, buffer[0], length, p2, qmi_uim_channel_data.fci_value);
	pRequest = ComposeQMUXMsg(QMIType,QMIUIM_UIM_LOGICAL_CHANNEL,SimOpenChannelSetAidValue,(void*)&qmi_uim_channel_data);
	err = QmiThreadSendQMI(NULL,pRequest,&pResponse);
	qmi_rsp_check_and_return();
	pOpenChannelResponse = (PQMIUIM_OPEN_CHANNEL_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x10);
	result[0] = pOpenChannelResponse->session_id;
	pOpenChannel_Sw_Response = (PQMIUIM_OPEN_CHANNEL_RESPONSE_SW_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x11);
	pOpenChannel_select_Response = (PQMIUIM_OPEN_CHANNEL_SELECT_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x12);
	if(pOpenChannel_select_Response != NULL){
	    for(i = 0 ; i < pOpenChannel_select_Response->select_reponse_length; i++){
		    result[i+1] = pOpenChannel_select_Response->select_reponse_value[i];
			*select_response_length = pOpenChannel_select_Response->select_reponse_length;
			dbg_time("%s select reponse is:%d, select_response_lenght is:%d\n", __func__,result[i+1],*select_response_length);
	    }
	}
	result[i+1] = pOpenChannel_Sw_Response->sw1;
	result[i+2] = pOpenChannel_Sw_Response->sw2;
	dbg_time("%s session id is:%d,sw1 is:%d,sw2 is:%d\n", __func__,result[0],result[i+1],result[i+2]);
	free(pResponse);
	return 0;
}
#else
int requestSimOpenChannel(int p2, unsigned char* buffer, unsigned short length,int* result,int* select_response_length){
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;
	int i = 0;
	PQMIUIM_OPEN_CHANNEL_RESPONSE_TLV    pOpenChannelResponse;
	PQMIUIM_OPEN_CHANNEL_RESPONSE_SW_TLV pOpenChannel_Sw_Response;
	PQMIUIM_OPEN_CHANNEL_SELECT_RESPONSE_TLV pOpenChannel_select_Response;
	QMI_UIM_DATA_TYPE qmi_uim_channel_data;
	qmi_uim_channel_data.data_len = length; // uint16 to uin8?
	qmi_uim_channel_data.data_ptr = buffer;
    qmi_uim_channel_data.fci_value = p2 == -1? p2 : p2ToFciValue(p2);
	UCHAR QMIType = QMUX_TYPE_UIM;//qualcom 80-nv304-12.pdf
	dbg_time("%s buffer[0] is: 0x%x, length = %d, p2 = %d, fci = %d\n", __FUNCTION__, buffer[0], length, p2, qmi_uim_channel_data.fci_value);
	pRequest = ComposeQMUXMsg(QMIType, QMIUIM_UIM_OPEN_LOGICAL_CHANNEL, SimOpenChannelSetAidValue,(void*)&qmi_uim_channel_data);
	err = QmiThreadSendQMI(NULL,pRequest,&pResponse);
	qmi_rsp_check_and_return();
	pOpenChannelResponse = (PQMIUIM_OPEN_CHANNEL_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x10);
	result[0] = pOpenChannelResponse->session_id;
	pOpenChannel_Sw_Response = (PQMIUIM_OPEN_CHANNEL_RESPONSE_SW_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x11);
	pOpenChannel_select_Response = (PQMIUIM_OPEN_CHANNEL_SELECT_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x12);
	if(pOpenChannel_select_Response != NULL) {
	    for(i = 0 ; i < pOpenChannel_select_Response->select_reponse_length; i++){
		    result[i+1] = pOpenChannel_select_Response->select_reponse_value[i];
			*select_response_length = pOpenChannel_select_Response->select_reponse_length;
			dbg_time("%s select reponse is:%d, select_response_lenght is:%d\n", __func__,result[i+1],*select_response_length);
	    }
	}
	result[i+1] = pOpenChannel_Sw_Response->sw1;
	result[i+2] = pOpenChannel_Sw_Response->sw2;
	dbg_time("%s sessionId = %d, i = %d, sw1 = %d,sw2 = %d\n", __func__, result[0], i, result[i+1], result[i+2]);
	free(pResponse);
	return 0;
}

#endif
int requestSimCloseChannel(int channel_id){
	PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;
	UCHAR   qmi_channel_id = channel_id; 
	dbg_time("from android framework channel_id is %d, send to qmi channel_id is %d \n", channel_id, qmi_channel_id);
	PQMIUIM_CLOSE_CHANNEL_RESPONSE_TLV    pCloseChannelResponse;
	UCHAR QMIType = QMUX_TYPE_UIM;//qualcom 80-nv304-12.pdf
	pRequest = ComposeQMUXMsg(QMIType,QMIUIM_UIM_LOGICAL_CHANNEL,SimCloseChannelSetChannelId,(void*)&qmi_channel_id);
	err = QmiThreadSendQMI(NULL,pRequest,&pResponse);
	qmi_rsp_check_and_return();
	pCloseChannelResponse = (PQMIUIM_CLOSE_CHANNEL_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x02);//type is 02 not 12
	if(pCloseChannelResponse != NULL){
	    dbg_time("%s qmiresult is:%d qmierror is: %d\n", __func__, pCloseChannelResponse->qmiResult, pCloseChannelResponse->qmierror);
	    free(pResponse);
	    return 0 ;
	}else {
	    dbg_time("some error happen in close channel return -1");
	    free(pResponse);
	    return -1;
	}
}
int requestTransmitApduLogicChannel(int channel_id,unsigned char* apdu, unsigned short apdu_length,unsigned char* apdu_response,int* apdu_response_len){
	PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
	QMI_UIM_APDU_TYPE apdu_params;
    int err = 0;
	int j = 0 ;
	*apdu_response_len = 0;
	dbg_time("send to slm750 apdu_lenght  is %d ,channel id is:%d\n", apdu_length,channel_id);
	apdu_params.channel_id = channel_id;
	apdu_params.data_ptr = apdu;
	apdu_params.data_len = apdu_length;
	PQMIUIM_TRANSMIT_APUD_LOGIC_CHANNEL_RESPONSE_TLV    pTransmitApduBasicChannelResponse;
	UCHAR QMIType = QMUX_TYPE_UIM;//qualcom 80-nv304-12.pdf
	for(j = 0; j < apdu_params.data_len;j++){
		dbg_time("from android framework apdu is:%d ",apdu_params.data_ptr[j]);
	}
	pRequest = ComposeQMUXMsg(QMIType,QMIUIM_UIM_SEND_APDU_LOGICAL_CHANNEL,SimSendApduLogicChannel,(void*)&apdu_params);
	err = QmiThreadSendQMI(NULL,pRequest,&pResponse);
	qmi_rsp_check_and_return();
	pTransmitApduBasicChannelResponse = (PQMIUIM_TRANSMIT_APUD_LOGIC_CHANNEL_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x10);
    if(pTransmitApduBasicChannelResponse){
		*apdu_response_len = pTransmitApduBasicChannelResponse->apdu_len;
		memcpy(apdu_response,pTransmitApduBasicChannelResponse->apdu,*apdu_response_len);
	}
	for(j = 0; j < *apdu_response_len; j++){
		dbg_time("%02x",apdu_response[j]);
	}
	//dbg_time("%s Sw1 is:%d Sw2 is: %d\n", __func__, pCloseChannelResponse->Sw1, pCloseChannelResponse->Sw2);
	free(pResponse);
	return 0;
}
#ifdef MEIG_NEW_FEATURE
int requestSimAuthentication(uim_authentication_data_type *auth_info, SIM_IO_rsp *rsp) {
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;

    int content_len = 0;

    PQMIUIM_AUTH_CONTENT_RESPONSE_TLV    pAuthContentResponse;
    PQMIUIM_OPEN_CHANNEL_RESPONSE_SW_TLV pOpenChannel_Sw_Response;

    UCHAR QMIType = QMUX_TYPE_UIM; // qualcom 80-nv304-12.pdf
    dbg_time("%s aid_len = %d, auth_len = %d\n", __FUNCTION__, auth_info->aid_len, auth_info->auth_data_len);
    pRequest = ComposeQMUXMsg(QMIType, QMIUIM_UIM_AUTHENTICATION_REQ, SimAuthenticationSetValue,(void*)auth_info);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    pOpenChannel_Sw_Response = (PQMIUIM_OPEN_CHANNEL_RESPONSE_SW_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x10);
    pAuthContentResponse = (PQMIUIM_AUTH_CONTENT_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x11);
    rsp->sw1 = pOpenChannel_Sw_Response->sw1;
    rsp->sw2 = pOpenChannel_Sw_Response->sw2;
    content_len = pAuthContentResponse->contentLen;
    if (rsp->simResponse) {
        memcpy(rsp->simResponse, &(pAuthContentResponse->content), content_len);
        for(int j = 0; j < content_len; j++){
            dbg_time("%02x ",(rsp->simResponse)[j]);
        }
    }

    dbg_time("%s Sw1 is:%d Sw2 is: %d\n", __FUNCTION__, rsp->sw1, rsp->sw2);
    free(pResponse);
    return 0;
}
#endif

#ifdef START_KEEP_ALIVE
int requestStartKeepAlive(wds_modem_assisted_ka_start_req_msg_type *ka_info, KeepaliveStatus *rsp) {
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;

    PQMIWDS_START_KEEP_ALIVE_RESPONSE_TLV pStartKeepAliveResponse;

    UCHAR QMIType = QMUX_TYPE_WDS;
    dbg_time("%s entry, timerValue = %d", __FUNCTION__, ka_info->timer_value);

    pRequest = ComposeQMUXMsg(QMIType, QMI_WDS_MODEM_ASSISTED_KA_START_REQ, StartKeepAliveSetValue,(void*)ka_info);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    pStartKeepAliveResponse = (PQMIWDS_START_KEEP_ALIVE_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x10);
    rsp->sessionHandle = pStartKeepAliveResponse->keepAliveHandle;
    rsp->code = 2;
    dbg_time("%s Sw1 is:%d Sw2 is: %d\n", __FUNCTION__, rsp->sessionHandle);
    free(pResponse);
    return 0;
}
#endif

int requestGetSimAtr(int slotid,unsigned char* sim_atr,int* atr_len){
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;
    int j = 0; 
    *atr_len = 0;
    PQMIUIM_GET_ATR_RESPONSE_TLV  pUimAtrValue;
    dbg_time("get slotid is: %d \n", slotid);
    UCHAR QMIType = QMUX_TYPE_UIM;//qualcom 80-nv304-12.pdf
    pRequest = ComposeQMUXMsg(QMIType,QMIUIM_GET_SIM_ATR,SimGetSimAtr,(void*)&slotid);
    err = QmiThreadSendQMI(NULL,pRequest,&pResponse);
    qmi_rsp_check_and_return();
    pUimAtrValue = (PQMIUIM_GET_ATR_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x10);
    if(pUimAtrValue){
        *atr_len = pUimAtrValue->atr_len;
        memcpy(sim_atr, pUimAtrValue->atr_value, *atr_len);
    }
    dbg_time("%s atr len is:%d \n", __func__,*atr_len );
    for (j = 0; j < *atr_len; j++) {
        dbg_time("%02x ", sim_atr[j]);
    }
    free(pResponse);
    return 0;
}

int requestGetSimEid(int slotid,unsigned char* sim_eid){
	PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;
    int j = 0; 
    UCHAR eid_len = 0;
    PQMIUIM_GET_EID_RESPONSE_TLV  pUimEidValue;
    dbg_time("get slotid is: %d \n", slotid);
    UCHAR QMIType = QMUX_TYPE_UIM;//qualcom 80-nv305-12.pdf
    pRequest = ComposeQMUXMsg(QMIType,QMIUIM_GET_SIM_EID,SimGetSimEid,(void*)&slotid);
    err = QmiThreadSendQMI(NULL,pRequest,&pResponse);
    qmi_rsp_check_and_return();
    pUimEidValue = (PQMIUIM_GET_EID_RESPONSE_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x10);
    if(pUimEidValue){
        eid_len = pUimEidValue->eid_len;
        memcpy(sim_eid, pUimEidValue->eid_value, eid_len);
    }
    dbg_time("%s eid len is:%d \n", __func__,eid_len );
    for (j = 0; j < eid_len; j++) {
        dbg_time("%02x ", sim_eid[j]);
    }
    free(pResponse);
    return 0;
}
/*zhangqingyun add for support esim 2023-7-20 end*/
/*zhangqingyun add for support body sar 2023-3-21 start*/
int requestQueryBodySar(QMISAR_VALUE * sarValue){
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;
    QMISAR_VALUE  defaltSarValue = 0;
    PQMIBODYSAR_PKT_SRVC_TLV    pBodySarValue;
    
    UCHAR QMIType = QMUX_TYPE_WDS_IPV6;//qualcom 80-nv304-19.pdf 
    
    pRequest =  ComposeQMUXMsg(QMIType,QMI_SAR_RF_GET_STATE,NULL,NULL);
    err = QmiThreadSendQMI(NULL,pRequest,&pResponse);
    qmi_rsp_check_and_return();
    pBodySarValue = (PQMIBODYSAR_PKT_SRVC_TLV)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr,0x10);
    if(pBodySarValue){
        *sarValue = pBodySarValue->SarValue;
    }
    dbg_time("%s body sar value is: %d\n",__func__,*sarValue);
    free(pResponse);
    return 0;
}

int requestSetBodySar(QMISAR_VALUE sarValue)
{   
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;
    UCHAR QMIType = QMUX_TYPE_WDS_IPV6 ;//qualcom 80-nv304-19.pdf
    dbg_time("zqy add set sar value is:%d\n",sarValue);    
    pRequest = ComposeQMUXMsg(QMIType,QMI_SAR_RF_SET_STATE,BodySarSetSarValue,(void*)&sarValue);
    QmiThreadSendQMI(NULL,pRequest,&pResponse);
    qmi_rsp_check_and_return();
    free(pResponse);
    return 0;
}

/*zhangqingyun add for support body sar 2023-3-21 end*/
/*zhangqingyun add for supoort esim 2023-7-20 start*/
/*zhangqingyun add for support getmodemActivity info 2023-12-5 start*/

int requestGetModemActivityInfo()
{   
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;
    UCHAR QMIType = QMUX_TYPE_DMS ;//qualcom 80-16656-4.pdf
    dbg_time("enter meig_cm_core.c zqy add requestGetModemActivityInfo\n");    
    pRequest = ComposeQMUXMsg(QMIType,QMIDMS_GET_MODEM_ACTIVITY_INFO,NULL,NULL);
    QmiThreadSendQMI(NULL,pRequest,&pResponse);
    qmi_rsp_check_and_return();
    free(pResponse);
    return 0;
}

/*zhangqingyun add for support esim 2023-7-20 end*/
int requestSetupDataCall(PROFILE_T *profile, int curIpFamily)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err = 0;
    UCHAR QMIType = (curIpFamily == IpFamilyV4) ? QMUX_TYPE_WDS : QMUX_TYPE_WDS_IPV6;
//DualIPSupported means can get ipv4 & ipv6 address at the same time, one wds for ipv4, the other wds for ipv6
    profile->curIpFamily = curIpFamily;
    pRequest = ComposeQMUXMsg(QMIType, QMIWDS_START_NETWORK_INTERFACE_REQ, WdsStartNwInterfaceReq, profile);
    dbg_time("%s pdpId = %d, pdp = %d, s_is_cdma = %d, apn = %s", __FUNCTION__, profile->pdpIndex, profile->pdp, s_is_cdma, profile->apn ? profile->apn : "null");
    err = QmiThreadSendQMITimeout(profile, pRequest, &pResponse, 120 * 1000);
    qmi_rsp_check();

    if (le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXResult) || le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXError)) {
        PQMI_TLV_HDR pTLVHdr;

        pTLVHdr = GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x10);
        if (pTLVHdr) {
            uint16_t *data16 = (uint16_t *)(pTLVHdr+1);
            uint16_t call_end_reason = le16_to_cpu(data16[0]);
            dbg_time("call_end_reason is %d", call_end_reason);
        }

        pTLVHdr = GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x11);
        if (pTLVHdr) {
            uint16_t *data16 = (uint16_t *)(pTLVHdr+1);
            uint16_t call_end_reason_type = le16_to_cpu(data16[0]);
            uint16_t verbose_call_end_reason  = le16_to_cpu(data16[1]);

            dbg_time("call_end_reason_type is %d", call_end_reason_type);
            dbg_time("call_end_reason_verbose is %d", verbose_call_end_reason);
        }

        free(pResponse);
        return le16_to_cpu(pMUXMsg->QMUXMsgHdrResp.QMUXError);
    }

    if (curIpFamily == IpFamilyV4) {
        gCMDevContext.wdsConnV4HandleList[profile->pdpIndex]= le32_to_cpu(pResponse->MUXMsg.StartNwInterfaceResp.Handle);
        dbg_time("%s wdsConnV4HandleList[%d]: 0x%08x", __func__, profile->pdpIndex, gCMDevContext.wdsConnV4HandleList[profile->pdpIndex]);
    } else {
        gCMDevContext.wdsConnV6HandleList[profile->pdpIndex] = le32_to_cpu(pResponse->MUXMsg.StartNwInterfaceResp.Handle);
        dbg_time("%s wdsConnV6HandleList[%d]: 0x%08x", __func__, profile->pdpIndex, gCMDevContext.wdsConnV6HandleList[profile->pdpIndex]);
    }

    free(pResponse);

    return 0;
}

int requestDeactivateDefaultPDP(PROFILE_T *profile, int curIpFamily)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    UCHAR QMIType = (curIpFamily == 0x04) ? QMUX_TYPE_WDS : QMUX_TYPE_WDS_IPV6;
    if (curIpFamily == IpFamilyV4 && gCMDevContext.wdsConnV4HandleList[0] == 0)
        return 0;
    if (curIpFamily == IpFamilyV6 && gCMDevContext.wdsConnV6HandleList[0] == 0)
        return 0;

    pRequest = ComposeQMUXMsg(QMIType, QMIWDS_STOP_NETWORK_INTERFACE_REQ, WdsStopNwInterfaceReq, &curIpFamily);
    err = QmiThreadSendQMI(profile, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    if (curIpFamily == IpFamilyV4)
        gCMDevContext.wdsConnV4HandleList[0] = 0;
    else
        gCMDevContext.wdsConnV6HandleList[0] = 0;
    free(pResponse);
    return 0;
}



int requestDeactivatePDP(int pdpIndex, int curIpFamily)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    NW_INTERFACE_PARAM nwIntfParam = {
        .ipFamily = curIpFamily,
        .pdpIndex = pdpIndex,
    };
    int err;
    UCHAR QMIType = (curIpFamily == 0x04) ? QMUX_TYPE_WDS : QMUX_TYPE_WDS_IPV6;
    if (curIpFamily == IpFamilyV4 && gCMDevContext.wdsConnV4HandleList[pdpIndex]== 0)
        return 0;
    if (curIpFamily == IpFamilyV6 && gCMDevContext.wdsConnV6HandleList[pdpIndex] == 0)
        return 0;

    pRequest = ComposeQMUXMsg( QMIType, QMIWDS_STOP_NETWORK_INTERFACE_REQ, WdsStopNwInterfaceReq, &nwIntfParam);
    err = QmiThreadSendQMI(&gCMDevContext.profileList[pdpIndex], pRequest, &pResponse);
    qmi_rsp_check_and_return();

    if (curIpFamily == IpFamilyV4)
        gCMDevContext.wdsConnV4HandleList[pdpIndex] = 0;
    else
        gCMDevContext.wdsConnV6HandleList[pdpIndex] = 0;
    free(pResponse);
    return 0;
}

int requestGetIPAddress(int pdpIndex, int curIpFamily)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV4_ADDR pIpv4Addr;
    PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV6_ADDR pIpv6Addr = NULL;
    PQMIWDS_GET_RUNTIME_SETTINGS_TLV_MTU pMtu;

    IPV4_ADDR *pIpv4 = &gCMDevContext.profileList[pdpIndex].ipv4;
    IPV6_ADDR *pIpv6 = &gCMDevContext.profileList[pdpIndex].ipv6;
    UCHAR QMIType = (curIpFamily == 0x04) ? QMUX_TYPE_WDS : QMUX_TYPE_WDS_IPV6;
    if (curIpFamily == IpFamilyV4) {
        memset(pIpv4, 0x00, sizeof(IPV4_ADDR));
        if (gCMDevContext.wdsConnV4HandleList[pdpIndex]== 0)
            return -1;
    } else if (curIpFamily == IpFamilyV6) {
        memset(pIpv6, 0x00, sizeof(IPV6_ADDR));
        if (gCMDevContext.wdsConnV6HandleList[pdpIndex]== 0)
            return -1;
    }

    pRequest = ComposeQMUXMsg(QMIType, QMIWDS_GET_RUNTIME_SETTINGS_REQ, WdsGetRuntimeSettingReq, NULL);
    err = QmiThreadSendQMI(&gCMDevContext.profileList[pdpIndex], pRequest, &pResponse);
    qmi_rsp_check_and_return();
    pIpv4Addr = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV4_ADDR)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_IPV4PRIMARYDNS);
    if (pIpv4Addr) {
        pIpv4->DnsPrimary = pIpv4Addr->IPV4Address;
    }

    pIpv4Addr = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV4_ADDR)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_IPV4SECONDARYDNS);
    if (pIpv4Addr) {
        pIpv4->DnsSecondary = pIpv4Addr->IPV4Address;
    }

    pIpv4Addr = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV4_ADDR)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_IPV4GATEWAY);
    if (pIpv4Addr) {
        pIpv4->Gateway = pIpv4Addr->IPV4Address;
    }

    pIpv4Addr = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV4_ADDR)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_IPV4SUBNET);
    if (pIpv4Addr) {
        pIpv4->SubnetMask = pIpv4Addr->IPV4Address;
    }

    pIpv4Addr = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV4_ADDR)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_IPV4);
    if (pIpv4Addr) {
        pIpv4->Address = pIpv4Addr->IPV4Address;
    }

    pIpv6Addr = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV6_ADDR)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_IPV6PRIMARYDNS);
    if (pIpv6Addr) {
        memcpy(pIpv6->DnsPrimary, pIpv6Addr->IPV6Address, 16);
    }

    pIpv6Addr = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV6_ADDR)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_IPV6SECONDARYDNS);
    if (pIpv6Addr) {
        memcpy(pIpv6->DnsSecondary, pIpv6Addr->IPV6Address, 16);
    }

    pIpv6Addr = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV6_ADDR)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_IPV6GATEWAY);
    if (pIpv6Addr) {
        memcpy(pIpv6->Gateway, pIpv6Addr->IPV6Address, 16);
        pIpv6->PrefixLengthGateway = pIpv6Addr->PrefixLength;
    }

    pIpv6Addr = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_IPV6_ADDR)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_IPV6);
    if (pIpv6Addr) {
        memcpy(pIpv6->Address, pIpv6Addr->IPV6Address, 16);
        pIpv6->PrefixLengthIPAddr = pIpv6Addr->PrefixLength;
    }

    pMtu = (PQMIWDS_GET_RUNTIME_SETTINGS_TLV_MTU)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, QMIWDS_GET_RUNTIME_SETTINGS_TLV_TYPE_MTU);
    if (pMtu) {
        pIpv4->Mtu =  pIpv6->Mtu =  le32_to_cpu(pMtu->Mtu);
    }

    free(pResponse);
    return 0;
}

#ifdef CONFIG_APN
int requestSetProfile(PROFILE_T *profile)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;

    if (!profile->pdp)
        return 0;

    dbg_time("%s[%d] %s/%s/%s/%d", __func__, profile->pdp, profile->apn, profile->user, profile->password, profile->auth);
    pRequest = ComposeQMUXMsg(QMUX_TYPE_WDS, QMIWDS_MODIFY_PROFILE_SETTINGS_REQ, WdsModifyProfileSettingsReq, profile);
    err = QmiThreadSendQMI(profile,  pRequest, &pResponse);
    qmi_rsp_check_and_return();

    free(pResponse);
    return 0;
}

/*zhaopengfei@meigsmart.com-2021-0729 create new apn when modify failed Begin */
int requestCreateProfile(PROFILE_T *profile)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    PQMIWDS_PROFILE_RESP_IDENTIFIER pProfileIndex;

    if (!profile->pdp)
        return 0;

    dbg_time("%s[%d] %s/%s/%s/%d", __func__, profile->pdp, profile->apn, profile->user, profile->password, profile->auth);
    pRequest = ComposeQMUXMsg( QMUX_TYPE_WDS, QMIWDS_CREATE_PROFILE_SETTINGS_REQ, WdsCreateProfileSettingsReq, profile);
    err = QmiThreadSendQMI(profile, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    pProfileIndex = (PQMIWDS_PROFILE_RESP_IDENTIFIER)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0X01);
    dbg_time("change pdp from %d to %d, as empty pdp", profile->pdp, pProfileIndex->ProfileIndex);
    profile->pdp = pProfileIndex->ProfileIndex;

    free(pResponse);
    return 0;
}
/*zhaopengfei@meigsmart.com-2021-0729 create new apn when modify failed End */
/* Begin: modify by zhaopengfei for apn not update from modem 2022/07/06 */
int requestGetProfile(PROFILE_T *profile)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    PQMIWDS_APNNAME pApnName;
    PQMIWDS_USERNAME pUserName;
    PQMIWDS_PASSWD pPassWd;
    PQMIWDS_AUTH_PREFERENCE pAuthPref;

    if (!profile->pdp)
        return 0;

    pRequest = ComposeQMUXMsg(QMUX_TYPE_WDS, QMIWDS_GET_PROFILE_SETTINGS_REQ, WdsGetProfileSettingsReqSend, profile);
    err = QmiThreadSendQMI(profile, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    pApnName = (PQMIWDS_APNNAME)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x14);
    pUserName = (PQMIWDS_USERNAME)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x1B);
    pPassWd = (PQMIWDS_PASSWD)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x1C);
    pAuthPref = (PQMIWDS_AUTH_PREFERENCE)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x1D);

    if (pApnName/* && le16_to_cpu(pApnName->TLVLength)*/) {
        if(profile->apn != NULL) free(profile->apn);
        profile->apn = strndup((const char *)(&pApnName->ApnName), le16_to_cpu(pApnName->TLVLength));
    }
    if (pUserName/*  && pUserName->UserName*/) {
        if(profile->user != NULL) free(profile->user);
        profile->user = strndup((const char *)(&pUserName->UserName), le16_to_cpu(pUserName->TLVLength));
    }
    if (pPassWd/*  && le16_to_cpu(pPassWd->TLVLength)*/){
        if(profile->password != NULL) free(profile->password);
        profile->password = strndup((const char *)(&pPassWd->Passwd), le16_to_cpu(pPassWd->TLVLength));
    }
    if (pAuthPref/*  && le16_to_cpu(pAuthPref->TLVLength)*/) {
        profile->auth = pAuthPref->AuthPreference;
    }

    dbg_time("%s[%d] %s/%s/%s/%d", __func__, profile->pdp, profile->apn, profile->user, profile->password, profile->auth);

    free(pResponse);
    return 0;
}
/* End: modify by zhaopengfei for apn not update from modem 2022/07/06 */
#endif

#ifdef CONFIG_VERSION
int requestBaseBandVersion(const char **pp_reversion)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    PDEVICE_REV_ID revId;
    int err;

    if (pp_reversion) *pp_reversion = NULL;

    pRequest = ComposeQMUXMsg(QMUX_TYPE_DMS, QMIDMS_GET_DEVICE_REV_ID_REQ, NULL, NULL);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    revId = (PDEVICE_REV_ID)GetTLV(&pResponse->MUXMsg.QMUXMsgHdr, 0x01);

    if (revId && le16_to_cpu(revId->TLVLength)) {
        char *DeviceRevisionID = strndup((const char *)(&revId->RevisionID), le16_to_cpu(revId->TLVLength));
        dbg_time("%s %s", __func__, DeviceRevisionID);
        if (s_9x07 == -1) { //fail to get QMUX_TYPE_WDS_ADMIN
            if((0 != strcasestr(DeviceRevisionID, "SRM815")) || (0 != strcasestr(DeviceRevisionID, "SRM825"))) {
                s_9x07=0;
            } else {
                s_9x07=1;
            }
        }
        if (pp_reversion) *pp_reversion = DeviceRevisionID;
    }

    free(pResponse);
    return 0;
}
#endif

#ifdef CONFIG_RESET_RADIO
static USHORT DmsSetOperatingModeReq(PQMUX_MSG pMUXMsg, void *arg)
{
    pMUXMsg->SetOperatingModeReq.TLVType = 0x01;
    pMUXMsg->SetOperatingModeReq.TLVLength = cpu_to_le16(1);
    pMUXMsg->SetOperatingModeReq.OperatingMode = *((UCHAR *)arg);

    return sizeof(QMIDMS_SET_OPERATING_MODE_REQ_MSG);
}

int requestSetOperatingMode(UCHAR OperatingMode)
{
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;

    dbg_time("%s(%d)", __func__, OperatingMode);

    pRequest = ComposeQMUXMsg(QMUX_TYPE_DMS, QMIDMS_SET_OPERATING_MODE_REQ, DmsSetOperatingModeReq, &OperatingMode);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();

    free(pResponse);
    return 0;
}
#endif
/*zhangqingyn add for suppot cts always enable modem activity info calculation 2023-12-6 start*/
int requestTriggerModemActivityInfoCalculationReq(){
    PQCQMIMSG pRequest;
    PQCQMIMSG pResponse;
    PQMUX_MSG pMUXMsg;
    int err;
    UCHAR enable_Statis = 1; //default set 1 for cts 
    dbg_time("%s", __func__);
	
 
    pRequest = ComposeQMUXMsg(QMUX_TYPE_DMS, QMIDMS_TRIGGER_MODEM_ACTIVITY_INFO_CALCULATION_REQ, DmsSetModemActivityCalculation, &enable_Statis);
    err = QmiThreadSendQMI(NULL, pRequest, &pResponse);
    qmi_rsp_check_and_return();
    
    free(pResponse);
    return 0;
}

/*zhangqingyn add for suppot cts always enable modem activity info calculation 2023-12-6 end*/

int getAllClientIDs()
{
    int i = 0;

    if(gCMDevContext.qmichannel == NULL || gCMDevContext.qmichannel[0] == '\0' ){
        dbg_time("%s invalid qmichannel", __func__);
        return -1;
    }
    
    gCMDevContext.qmiclientId[QMUX_TYPE_WDS] = GobiNetGetClientID(gCMDevContext.qmichannel, QMUX_TYPE_WDS);
    if (gCMDevContext.qmiclientId[QMUX_TYPE_WDS] <= 0) {
        dbg_time("%s Failed get wds clientid from dev %s, errno: %d (%s)", __func__, gCMDevContext.qmichannel, errno, strerror(errno));
        return -1;
    } 
    #if 0 //now not support ipv6 zhangqingyun add 20230810 
    gCMDevContext.qmiclientId[QMUX_TYPE_DMS] = GobiNetGetClientID(gCMDevContext.qmichannel, QMUX_TYPE_DMS);
    if (gCMDevContext.qmiclientId[QMUX_TYPE_DMS] <= 0) {
        dbg_time("%s Failed get wds clientid from dev %s, errno: %d (%s)", __func__, gCMDevContext.qmichannel, errno, strerror(errno));
        return -1;
    } 
    #endif 
    gCMDevContext.qmiclientId[QMUX_TYPE_DMS] = GobiNetGetClientID(gCMDevContext.qmichannel, QMUX_TYPE_DMS);
    if (gCMDevContext.qmiclientId[QMUX_TYPE_DMS] <= 0) {
        dbg_time("%s Failed get dms clientid from dev %s, errno: %d (%s)", __func__, gCMDevContext.qmichannel, errno, strerror(errno));
        return -1;
    }

    //zqy add initialize client id qmi_type_wds_ipv6 to set sar value
    gCMDevContext.qmiclientId[QMUX_TYPE_WDS_IPV6] = GobiNetGetClientID(gCMDevContext.qmichannel, QMUX_TYPE_WDS_IPV6);
    if (gCMDevContext.qmiclientId[QMUX_TYPE_WDS_IPV6] <= 0) {
        dbg_time("%s Failed get dms clientid from dev %s, errno: %d (%s)", __func__, gCMDevContext.qmichannel, errno, strerror(errno));
        return -1;
    }
    gCMDevContext.qmiclientId[QMUX_TYPE_NAS] = GobiNetGetClientID(gCMDevContext.qmichannel, QMUX_TYPE_NAS);
    if (gCMDevContext.qmiclientId[QMUX_TYPE_NAS] <= 0) {
        dbg_time("%s Failed get nas clientid from dev %s, errno: %d (%s)", __func__, gCMDevContext.qmichannel, errno, strerror(errno));
        return -1;
    }

    gCMDevContext.qmiclientId[QMUX_TYPE_UIM] = GobiNetGetClientID(gCMDevContext.qmichannel, QMUX_TYPE_UIM);
    if (gCMDevContext.qmiclientId[QMUX_TYPE_UIM] <= 0) {
        dbg_time("%s Failed get uim clientid from dev %s, errno: %d (%s)", __func__, gCMDevContext.qmichannel, errno, strerror(errno));
        return -1;
    }


    if (gCMDevContext.qmap_mode == 0) { //when QMAP enabled, set data format in GobiNet Driver
        gCMDevContext.qmiclientId[QMUX_TYPE_WDS_ADMIN] = GobiNetGetClientID(gCMDevContext.qmichannel, QMUX_TYPE_WDS_ADMIN);
        if (gCMDevContext.qmiclientId[QMUX_TYPE_WDS_ADMIN] <= 0) {
            dbg_time("%s Failed get wds admin clientid from dev %s, errno: %d (%s)", __func__, gCMDevContext.qmichannel, errno, strerror(errno));
            return -1;
        }
    }

    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
    for(i = 0; i < gCMDevContext.qmap_mode; i++) {
        gCMDevContext.wdsClient[i].v4clientId = GobiNetGetClientID(gCMDevContext.qmichannel, QMUX_TYPE_WDS);
        if (gCMDevContext.wdsClient[i].v4clientId <= 0) {
            dbg_time("%s get v4 clientid Failed to open %s, errno: %d (%s)", __func__, gCMDevContext.qmichannel, errno, strerror(errno));
            return -1;
        }
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
        #if 0
        gCMDevContext.wdsClient[i].v6clientId = GobiNetGetClientID(gCMDevContext.qmichannel, QMUX_TYPE_WDS);
        if (gCMDevContext.wdsClient[i].v6clientId <= 0) {
            dbg_time("%s get v6 clientid Failed to open %s, bug ignore, errno: %d (%s)", __func__, gCMDevContext.qmichannel, errno, strerror(errno));
        }
        #endif
    }

    return 0;

}

/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
int CMInitInstance(const char* adapterName, int use_oldgobi)
{


    int i = 0;
    char netCard[56];
    int triger_event = 0;
    int waitQmiDeviceTimeout = 40;
#ifdef CONFIG_KEEP_CONNECTION

#ifdef CONFIG_SIM
    CMSIM_Status SIMStatus;
#endif
    UCHAR PSAttachedState;
    UCHAR  IPv4ConnectionStatus = 0xff; //unknow state
    UCHAR  IPV6ConnectionStatus = 0xff; //unknow state
    int signo;
    char * save_usbnet_adapter = NULL;
    int qmierr = 0;
    dbg_time("%s entry", __FUNCTION__);

#endif
    pthread_attr_t cm_thread_attr;
    pthread_attr_init(&cm_thread_attr);
    pthread_attr_setdetachstate(&cm_thread_attr, PTHREAD_CREATE_DETACHED);

    memset(&gCMDevContext, 0x00, sizeof(gCMDevContext));
    gCMDevContext.usbnet_adapter = strdup(adapterName);
    gCMDevContext.read_quit = 0;
    dbg_time("%s entry", __FUNCTION__);
    if(use_oldgobi) {
        gCMDevContext.qmap_mode = 1;  //change with pdp
    } else {
        gCMDevContext.qmap_mode = PDP_SUPPORT_MAX;  //change with pdp
    }
    gCMDevContext.qmap_mode = 0;
    /* Begin: modify by zhaopengfei for the scene that apn released by users 2022/07/06 */
    for( i = 0; i < gCMDevContext.qmap_mode; i++) {

        memset(netCard, 0x0, MAX_INTERFACE_NAME);
        snprintf(netCard, MAX_INTERFACE_NAME, "bmwan%d", i);
        gCMDevContext.wdsConnV4HandleList[i] = 0;
        gCMDevContext.wdsConnV6HandleList[i] = 0;
        gCMDevContext.profileList[i].apn = strdup("3gnet");
        gCMDevContext.profileList[i].user = strdup("card");
        gCMDevContext.profileList[i].password = strdup("card");
        gCMDevContext.profileList[i].auth = 2;
        gCMDevContext.profileList[i].muxid = (0x81 + i);
        gCMDevContext.profileList[i].pincode="";
        gCMDevContext.profileList[i].pdp = (i+1);
        gCMDevContext.profileList[i].qmapnet_adapter = strdup(netCard);
        gCMDevContext.profileList[i].ipv4_flag = 1;
        gCMDevContext.profileList[i].ipv6_flag = 1;
        gCMDevContext.profileList[i].curIpFamily = IpFamilyV4;
        gCMDevContext.profileList[i].IsDualIPSupported |= (1 << IpFamilyV6);
        gCMDevContext.profileList[i].enable_ipv6 = 1;
        gCMDevContext.profileList[i].pdpIndex = i;
        if( 0 == i ) {
            gCMDevContext.profileList[i].pdp = CONFIG_DEFAULT_PDP;
        } else {
            gCMDevContext.profileList[i].pdp = (MULTI_PDP_START_OFFSET + i);

        }
    }
    /* End: modify by zhaopengfei for the scene that apn released by users 2022/07/06 */ 
    //gCMDevContext.qmichannel = "/dev/qcqmi0";
    gCMDevContext.qmichannel = NULL;
    gCMDevContext.dataCallListChanged = NULL;
    gCMDevContext.registerStateChanged = NULL;
    gCMDevContext.qmi_ops = &gobi_qmidev_ops;
    qmidev_send = gCMDevContext.qmi_ops->send;

    if (socketpair( AF_LOCAL, SOCK_STREAM, 0, signal_control_fd) < 0 ) {
        dbg_time("%s Faild to create main_control_fd: %d (%s)", __func__, errno, strerror(errno));
        return -1;
    }

    if ( socketpair( AF_LOCAL, SOCK_STREAM, 0, qmidevice_control_fd ) < 0 ) {
        dbg_time("%s Failed to create thread control socket pair: %d (%s)", __func__, errno, strerror(errno));
        return -1;
    }


//__main_loop:
    while (!gCMDevContext.qmichannel) {
        char qmichannel[32+1] = {'\0'};
        char usbnet_adapter[32+1] = {'\0'};
        strncpy(usbnet_adapter, gCMDevContext.usbnet_adapter, 32);

        if (!qmidevice_detect(qmichannel, usbnet_adapter, sizeof(qmichannel))) {
            dbg_time("wait qmi device");
            if(gCMDevContext.read_quit ==1 || waitQmiDeviceTimeout-- < 0){
                dbg_time("Cannot find valid qmichannel for Meig modules");
                return -1;
            }
            sleep(1);
            continue;
        } else if(qmichannel[0] != '\0' && (!(gCMDevContext.qmichannel))){
            strset(gCMDevContext.qmichannel, qmichannel);
            dbg_time("Found Qmi Channel");
            break;
        }

        dbg_time("Cannot find valid qmichannel for Meig modules");
        return -1;
    }


    if(use_oldgobi) {
        for( i = 0; i < gCMDevContext.qmap_mode; i++) {
            gCMDevContext.profileList[i].qmapnet_adapter = strdup(gCMDevContext.usbnet_adapter);
            dbg_time("old gobi adapter:%s, muxadapter[%d]:%s", gCMDevContext.usbnet_adapter,i,  gCMDevContext.profileList[i].qmapnet_adapter);
        }
    }

    dbg_time("qmap_mode=%d", gCMDevContext.qmap_mode);
    if(getAllClientIDs() < 0){
        dbg_time("%s Failed getAllClientIDs", __func__);
        return -1;
    }

    s_pUnsolInd = NULL;
    if (pthread_create( &gQmiThreadID, &cm_thread_attr, gCMDevContext.qmi_ops->read, (void *)(&gCMDevContext)) != 0) {
        dbg_time("%s Failed to create meig_cm: %d (%s)", __func__, errno, strerror(errno));
        return -1;
    }

    if ((read(qmidevice_control_fd[0], &triger_event, sizeof(triger_event)) != sizeof(triger_event))
        || (triger_event != RIL_INDICATE_DEVICE_CONNECTED)) {
        dbg_time("%s Failed to init meig_cm: %d (%s)", __func__, errno, strerror(errno));
        return -1;
    }

    if (gCMDevContext.qmi_ops->init && gCMDevContext.qmi_ops->init(&gCMDevContext)) {
        dbg_time("%s Failed to qmi init: %d (%s)", __func__, errno, strerror(errno));
        return -1;
    }


    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
    for(i = 0; i < gCMDevContext.qmap_mode; i++) {
        if(0 != requestSetEthMode(&gCMDevContext, i)){
            dbg_time("%s Failed requestSetEthMode", __func__);
             return -1;
         }
    }
    /* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
	/*zhangqingyun add for support cts 2023-12-6 start*/
	requestTriggerModemActivityInfoCalculationReq();
	/*zhangqingyun add for support cts 2023-12-6 end*/
    gCMInited = 1;
    dbg_time("%s finished leave", __FUNCTION__);
    return 0;


#ifdef CONFIG_PID_FILE_FORMAT
    {
        char cmd[255];
        sprintf(cmd, "echo %d > " CONFIG_PID_FILE_FORMAT, getpid(), profile.usbnet_adapter);
        system(cmd);
    }
#endif


#ifdef CONFIG_KEEP_CONNECTION
    while (1) {
        struct pollfd pollfds[] = {{signal_control_fd[1], POLLIN, 0}, {qmidevice_control_fd[0], POLLIN, 0}};
        int ne, ret, nevents = sizeof(pollfds)/sizeof(pollfds[0]);
        UCHAR *pConnectionStatus = (profile.enable_ipv6) ? &IPV6ConnectionStatus : &IPv4ConnectionStatus;
        int curIpFamily = (profile.enable_ipv6) ? IpFamilyV6 : IpFamilyV4;

        do {
            ret = poll(pollfds, nevents,  15*1000);
        } while ((ret < 0) && (errno == EINTR));

        if (ret == 0) {
            //send_signo_to_main(SIGUSR2);
            continue;
        }

        if (ret <= 0) {
            dbg_time("%s poll=%d, errno: %d (%s)", __func__, ret, errno, strerror(errno));
            goto __main_quit;
        }

        for (ne = 0; ne < nevents; ne++) {
            int fd = pollfds[ne].fd;
            short revents = pollfds[ne].revents;

            if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
                dbg_time("%s poll err/hup", __func__);
                dbg_time("epoll fd = %d, events = 0x%04x", fd, revents);
                main_send_event_to_qmidevice(RIL_REQUEST_QUIT);
                if (revents & POLLHUP)
                    goto __main_quit;
            }

            if ((revents & POLLIN) == 0)
                continue;

            if (fd == signal_control_fd[1]) {
                if (read(fd, &signo, sizeof(signo)) == sizeof(signo)) {
                    alarm(0);
                    switch (signo) {
                    case SIGUSR1:
                        CMRequestQueryDataCall(pConnectionStatus, curIpFamily);
                        if (QWDS_PKT_DATA_CONNECTED != *pConnectionStatus) {
                            usbnet_link_change(0, &profile);
                            requestRegistrationState(&PSAttachedState);

                            if (PSAttachedState == 1) {
                                qmierr = requestSetupDataCall(&profile, curIpFamily);

                                if ((qmierr > 0) && profile.user && profile.user[0] && profile.password && profile.password[0]) {
                                    int old_auto =  profile.auth;

                                    //may be fail because wrong auth mode, try pap->chap, or chap->pap
                                    profile.auth = (profile.auth == 1) ? 2 : 1;
                                    qmierr = requestSetupDataCall(&profile, curIpFamily);

                                    if (qmierr)
                                        profile.auth = old_auto; //still fail, restore old auth moe
                                }

                                //succssful setup data call
                                if (!qmierr && profile.IsDualIPSupported) {
                                    requestSetupDataCall(&profile, IpFamilyV6);
                                }

                                if (!qmierr)
                                    continue;
                            }

#ifdef CONFIG_EXIT_WHEN_DIAL_FAILED
                            kill(getpid(), SIGTERM);
#endif
                            alarm(5); //try to setup data call 5 seconds later
                        }
                        break;

                    case SIGUSR2:
                        if (QWDS_PKT_DATA_CONNECTED == *pConnectionStatus)
                            CMRequestQueryDataCall(pConnectionStatus, curIpFamily);

                        //local ip is different with remote ip
                        if (QWDS_PKT_DATA_CONNECTED == IPv4ConnectionStatus && check_ipv4_address(&profile) == 0) {
                            requestDeactivateDefaultPDP(&profile, curIpFamily);
                            *pConnectionStatus = QWDS_PKT_DATA_DISCONNECTED;
                        }

                        if (QWDS_PKT_DATA_CONNECTED != *pConnectionStatus)
                            send_signo_to_main(SIGUSR1);
                        break;

                    case SIGTERM:
                    case SIGHUP:
                    case SIGINT:
                        if (QWDS_PKT_DATA_CONNECTED == *pConnectionStatus) {
                            requestDeactivateDefaultPDP(&profile, curIpFamily);
                            if (profile.IsDualIPSupported)
                                requestDeactivateDefaultPDP(&profile, IpFamilyV6);
                        }
                        usbnet_link_change(0, profile);
                        if (profile.qmi_ops->deinit)
                            profile.qmi_ops->deinit();
                        main_send_event_to_qmidevice(RIL_REQUEST_QUIT);
                        goto __main_quit;
                        break;

                    default:
                        break;
                    }
                }
            }

            if (fd == qmidevice_control_fd[0]) {
                if (read(fd, &triger_event, sizeof(triger_event)) == sizeof(triger_event)) {
                    switch (triger_event) {
                    case RIL_INDICATE_DEVICE_DISCONNECTED:
                        usbnet_link_change(0, &profile);
                        if (main_loop) {
                            if (pthread_join(gQmiThreadID, NULL)) {
                                dbg_time("%s Error joining to listener thread (%s)", __func__, strerror(errno));
                            }
                            profile.qmichannel = NULL;
                            profile.usbnet_adapter = save_usbnet_adapter;
                            goto __main_loop;
                        }
                        goto __main_quit;
                        break;

                    case RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED:
                        requestRegistrationState(&PSAttachedState);
                        if (PSAttachedState == 1 && QWDS_PKT_DATA_DISCONNECTED == *pConnectionStatus)
                            send_signo_to_main(SIGUSR1);
                        break;

                    case RIL_UNSOL_DATA_CALL_LIST_CHANGED: {
                        UCHAR oldConnectionStatus = *pConnectionStatus;
                        CMRequestQueryDataCall(pConnectionStatus, curIpFamily);
                        if (profile.IsDualIPSupported)
                            CMRequestQueryDataCall(&IPV6ConnectionStatus, IpFamilyV6);
                        if (QWDS_PKT_DATA_CONNECTED != *pConnectionStatus) {
                            usbnet_link_change(0, &profile);
                            //connected change to disconnect
                            if (oldConnectionStatus == QWDS_PKT_DATA_CONNECTED)
                                send_signo_to_main(SIGUSR1);
                        } else if (QWDS_PKT_DATA_CONNECTED == *pConnectionStatus) {
                            usbnet_link_change(1, &profile);
                            if (oldConnectionStatus == QWDS_PKT_DATA_CONNECTED) { //receive two CONNECT IND?
                                send_signo_to_main(SIGUSR2);
                            }
                        }
                    }
                    break;

                    default:
                        break;
                    }
                }
            }
        }
    }

__main_quit:
    usbnet_link_change(0, &profile);
    if (pthread_join(gQmiThreadID, NULL)) {
        dbg_time("%s Error joining to listener thread (%s)", __func__, strerror(errno));
    }
    close(signal_control_fd[0]);
    close(signal_control_fd[1]);
    close(qmidevice_control_fd[0]);
    close(qmidevice_control_fd[1]);
    dbg_time("%s exit", __func__);


#ifdef CONFIG_PID_FILE_FORMAT
    {
        char cmd[255];
        sprintf(cmd, "rm  " CONFIG_PID_FILE_FORMAT, profile.usbnet_adapter);
        system(cmd);
    }
#endif

#endif //CONFIG_KEEP_CONNECTION
    return 0;
}
/* Modify by zhaopengfei for gobi < v1.4.3 support 2022/10/14 End */
int CMDeinitInstance()
{


    /* Begin: modify by zhaopengfei for the scene that apn released by users 2022/07/06 */
    int i = 0;
    dbg_time("%s entry", __FUNCTION__);
    gCMInited = 0;
    gCMDevContext.read_quit = 1;
    close(signal_control_fd[0]);
    close(signal_control_fd[1]);
    close(qmidevice_control_fd[0]);
    close(qmidevice_control_fd[1]);
    if(s_pUnsolInd) {
        free(s_pUnsolInd);
        s_pUnsolInd = NULL;
    }

    gCMDevContext.dataCallListChanged = NULL;
    gCMDevContext.hardwareRemoved = NULL;
    gCMDevContext.registerStateChanged = NULL;

    for( i = 0; i < PDP_SUPPORT_MAX; i++) {

        if(gCMDevContext.profileList[i].apn != NULL) {
            free(gCMDevContext.profileList[i].apn);
            gCMDevContext.profileList[i].apn = NULL;
        }
        if(gCMDevContext.profileList[i].user != NULL) {
            free(gCMDevContext.profileList[i].user);
            gCMDevContext.profileList[i].user = NULL;
        }
        if(gCMDevContext.profileList[i].password != NULL){
            free(gCMDevContext.profileList[i].password);
            gCMDevContext.profileList[i].password = NULL;
        }
        if(gCMDevContext.profileList[i].qmapnet_adapter != NULL){
            free(gCMDevContext.profileList[i].qmapnet_adapter);
            gCMDevContext.profileList[i].qmapnet_adapter = NULL;
        }

    }
    /* Add by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
    if(gCMDevContext.usbnet_adapter && gCMDevContext.usbnet_adapter[0] != '\0'){
        free(gCMDevContext.usbnet_adapter);
        gCMDevContext.usbnet_adapter = NULL;
    }
    /* Add by zhaopengfei for gobi < v1.4.3 support 2022/10/14 Begin */
    /* End: modify by zhaopengfei for the scene that apn released by users 2022/07/06 */
    dbg_time("%s leave", __FUNCTION__);
    return 0;
    //release res
}
