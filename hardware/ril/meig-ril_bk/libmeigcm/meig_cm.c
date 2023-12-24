#include "common.h"
#include "meig_cm.h"


#define CM_VERSION    (0x010000)
extern int gCMInited;
extern int debug_qmi;
char CM_VERSION_STR[CM_VERSON_STRING_LEN_MAX] = { 0x0};
static pthread_mutex_t CMDevMutex = PTHREAD_MUTEX_INITIALIZER;


void CMEnableQMIDebug(int enable)
{

    debug_qmi = 1;

}

const char* WDS_CONN_STATE_STR(CM_CONN_STATE state){
    switch(state)
    {
        case WDS_CONNECTION_STATUS_UNDEF:
            return "UNDEF";
        case WDS_CONNECTION_STATUS_DISCONNECTED:
            return "DISCONNECTED";
        case WDS_CONNECTION_STATUS_CONNECTED:
            return "CONNECTED";
        case WDS_CONNECTION_STATUS_SUSPEND:
            return "SUSPEND";
        case WDS_CONNECTION_STATUS_AUTHENTICATING:
            return "AUTHENTICATING";
        default:
            break;
    }
    return "UNDEF";

}
ULONG CMVersion(void)
{
    return (ULONG)CM_VERSION;
}


CM_IP_PROT PROT_STR2TYPE(const char* protStr){
     CM_IP_PROT prot = CM_IPV4;
    if(strcasecmp(protStr, "IPV4") == 0) {
        prot = CM_IPV4;
    } else if(strcasecmp(protStr, "IPV4V6") == 0) {
        prot = CM_IPV4V6;
    } else if(strcasecmp(protStr, "IPV6") == 0) {
        prot = CM_IPV4V6;
    }
    return prot;
}

const char* PROT_TYPE2STR(CM_IP_PROT prot){
    switch(prot){
       case CM_IPV4:
           return "IPV4";
       case CM_IPV6:
               return "IPV6";
       case CM_IPV4V6:
               return "IPV4V6";
        default:
            break;
    }
    return "IPV4";
}

void CMShowVersionString()
{

    memset(CM_VERSION_STR, 0x0, sizeof(CM_VERSION_STR));
    snprintf(CM_VERSION_STR, 28, "v%d.%d.%d", (CM_VERSION>>16)&0xf, (CM_VERSION>>8)&0xf, CM_VERSION&0xf);
    dbg_time("MEIG CM Lib Version: %s", CM_VERSION_STR);
}



int CMRequestSetProfile(int pdpIndex, const char* apn, const char* user, const char* password, CM_IP_PROT ipProto,  int auth)
{

    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    dbg_time("%s, pdpIndex = %d, apn = %s, user = %s, passw = %s, ipP = %d, auth = %d",
    __FUNCTION__, pdpIndex, apn ? apn : "null", user ? user : "null", password ? password : "null", ipProto, auth);
    if (apn != NULL || user != NULL  || password != NULL) {
        pthread_mutex_lock(&CMDevMutex);
        /* Begin: modify by zhaopengfei for the scene that apn released by users 2022/07/06 */
        if(gCMDevContext.profileList[pdpIndex].apn != NULL) free(gCMDevContext.profileList[pdpIndex].apn);
        if(gCMDevContext.profileList[pdpIndex].user != NULL) free(gCMDevContext.profileList[pdpIndex].user);
        if(gCMDevContext.profileList[pdpIndex].password != NULL) free(gCMDevContext.profileList[pdpIndex].password);
        gCMDevContext.profileList[pdpIndex].apn = (apn != NULL)?strdup(apn):NULL;
        gCMDevContext.profileList[pdpIndex].user = (user != NULL)?strdup(user):NULL;
        gCMDevContext.profileList[pdpIndex].password = (password != NULL)?strdup(password):NULL;
       /* End: modify by zhaopengfei for the scene that apn released by users 2022/07/06 */
        gCMDevContext.profileList[pdpIndex].auth = auth;
    switch(ipProto){
          case CM_IPV4:
            gCMDevContext.profileList[pdpIndex].IsDualIPSupported = 0;
            gCMDevContext.profileList[pdpIndex].enable_ipv6 = 0;
            break;
        case CM_IPV6:
            gCMDevContext.profileList[pdpIndex].IsDualIPSupported = 0;
            gCMDevContext.profileList[pdpIndex].enable_ipv6 = 1;
            break;
        case CM_IPV4V6:
            gCMDevContext.profileList[pdpIndex].IsDualIPSupported |= (1 << IpFamilyV6);;
            gCMDevContext.profileList[pdpIndex].enable_ipv6 = 0;
            break;
    }

        if(QMI_ERR_EXTENDED_INTERNAL == requestSetProfile(&gCMDevContext.profileList[pdpIndex])) {
            requestCreateProfile(&gCMDevContext.profileList[pdpIndex]);
        }
        requestGetProfile(&gCMDevContext.profileList[pdpIndex]);
        pthread_mutex_unlock(&CMDevMutex);
        return 0;
    }


    return -1;
}

int CMRequestGetIPV4Address(int pdpIndex, IPV4_ADDR* addr)
{
    int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);
    if(requestGetIPAddress(pdpIndex, IpFamilyV4) == 0 && addr != NULL) {
        if(addr != NULL)  memcpy(addr, &gCMDevContext.profileList[pdpIndex].ipv4, sizeof(gCMDevContext.profileList[pdpIndex].ipv4));
        ret = 0;
    }
    pthread_mutex_unlock(&CMDevMutex);
    return ret;
}

int CMRequestGetIPV6Address(int pdpIndex, IPV6_ADDR* addr)
{
    int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);
    if(requestGetIPAddress(pdpIndex, IpFamilyV6) == 0) {
        if(addr != NULL) memcpy(addr, &gCMDevContext.profileList[pdpIndex].ipv6, sizeof(gCMDevContext.profileList[pdpIndex].ipv6));
        ret = 0;
    }
    pthread_mutex_unlock(&CMDevMutex);
    return ret;
}

/*zhangqingyun add for support requetBodySar 2023-3-21 start*/
int CMRequestGetBodySar(int* sarValue)
{
    int ret = -1;
    QMISAR_VALUE sar_value;
        if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);
    ret =  requestQueryBodySar(&sar_value);
    *sarValue = sar_value;
    dbg_time("zqy cm get sar value is:%d\n",*sarValue);
    pthread_mutex_unlock(&CMDevMutex);
    return ret;
}

int CMRequestSetBodySar(int sarValue)
{
    int ret = -1;
        if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);
    ret =  requestSetBodySar(sarValue);
    dbg_time("zqy cm set sar value is:%d\n",sarValue);
    pthread_mutex_unlock(&CMDevMutex);
    return ret;
}
int CMRequestGetSimAtr(int slotid ,unsigned char* sim_atr,int* atr_len){
    int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);
    ret = requestGetSimAtr(slotid,sim_atr,atr_len);
    pthread_mutex_unlock(&CMDevMutex);
    return ret;
}

int CMRequestGetSimEid(int slotid,unsigned char* sim_eid){
    int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);
    ret = requestGetSimEid(slotid,sim_eid);
    pthread_mutex_unlock(&CMDevMutex);
    return ret;
}


/*zhangqingyun add for support requestBodySar2023-3-21 end*/
/*zhangqingyun add for support sim apdu 2023-7-21 start*/
int CMRequestOpenChannel(int p2, unsigned char* buffer, unsigned short length,int* result,int* select_reponse_length){
    //dbg_time("zqy [meig_cm.c] aid value buffer is:%0x,length is:%d ", );
    int ret = -1;
    int i = 0; 
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    for (i=0; i < length ; i++){
        dbg_time("zqy [meig_cm.c] aid value qmi buffer is:%0x , length is :%d \n",buffer[i],length);
    }
    pthread_mutex_lock(&CMDevMutex);
    dbg_time("%s buffer is: 0x%x, length is :%d\n", __FUNCTION__, buffer[0], length);
    ret = requestSimOpenChannel(p2, buffer, length,result,select_reponse_length);
    dbg_time("zqy [meig_cm.c] CMRequestOpenchannel result is:%d\n",ret);
    pthread_mutex_unlock(&CMDevMutex);
    return ret;       
}
int CMRequestCloseChannel(int session_id){
    int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
	pthread_mutex_lock(&CMDevMutex);
	ret = requestSimCloseChannel(session_id);
	pthread_mutex_unlock(&CMDevMutex);
	return ret;
}
int CMRequestTransmitApduLogicChannel(int channel_id,unsigned char* apdu, unsigned short apdu_length,unsigned char* apdu_response,int* apdu_response_len){
	int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
	pthread_mutex_lock(&CMDevMutex);
	ret = requestTransmitApduLogicChannel(channel_id,apdu,apdu_length,apdu_response,apdu_response_len);
	pthread_mutex_unlock(&CMDevMutex);
	return ret;
}
/*zhangqingyun add for support sim spdu 2023-7-21 end*/
#ifdef MEIG_NEW_FEATURE
int CMRequestSimAuthentication(uim_authentication_data_type *auth_info, SIM_IO_rsp *rsp) {
    int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);
    ret = requestSimAuthentication(auth_info, rsp);
    pthread_mutex_unlock(&CMDevMutex);
    dbg_time("%s leave", __FUNCTION__);
    return ret;
}
#endif

#ifdef START_KEEP_ALIVE
int CMRequestStartKeepAlive(wds_modem_assisted_ka_start_req_msg_type *ka_info, KeepaliveStatus *rsp) {
    int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);
    ret = requestStartKeepAlive(ka_info, rsp);
    pthread_mutex_unlock(&CMDevMutex);
    dbg_time("%s leave", __FUNCTION__);
    return ret;
}
#endif
/*zhangqingyun add for support getmodemactivity through qmi 2023-12-5 start*/
int CMRequestGetModemActivityInfo(){
	int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
	pthread_mutex_lock(&CMDevMutex);
	ret = requestGetModemActivityInfo();
	pthread_mutex_unlock(&CMDevMutex);
	return ret;
}
int CMRequestSetupDataCall(int pdpIndex){

    int ret = -1;
    UCHAR PSAttachedState;
    CM_IP_PROT ip_protocol;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);
/*yufeilong add for modified cdma qmi dial fail 20221205 begin*/
    requestRegistrationState(&PSAttachedState);
    if (PSAttachedState != 1) {
        pthread_mutex_unlock(&CMDevMutex);
        return -1;
    }
/*yufeilong add for modified cdma qmi dial fail 20221205 end*/
    if(gCMDevContext.profileList[pdpIndex].IsDualIPSupported) {
        ip_protocol = CM_IPV4V6;
    } else if(gCMDevContext.profileList[pdpIndex].enable_ipv6){
        ip_protocol = CM_IPV6;
    } else {
        ip_protocol = CM_IPV4;
    }

    switch(ip_protocol) {
    case CM_IPV4:
        ret = (requestSetupDataCall(&gCMDevContext.profileList[pdpIndex], IpFamilyV4) |requestGetIPAddress(pdpIndex, IpFamilyV4));
        break;
    case CM_IPV6:
        ret = (requestSetupDataCall(&gCMDevContext.profileList[pdpIndex], IpFamilyV6) |requestGetIPAddress(pdpIndex, IpFamilyV6));
        break;
    case CM_IPV4V6:
        requestSetupDataCall(&gCMDevContext.profileList[pdpIndex], IpFamilyV6) ;
        requestGetIPAddress(pdpIndex, IpFamilyV6);
        ret = (requestSetupDataCall(&gCMDevContext.profileList[pdpIndex], IpFamilyV4)|requestGetIPAddress(pdpIndex, IpFamilyV4));
        break;
    }
    pthread_mutex_unlock(&CMDevMutex);
    return ret;
}


int CMRequestTurnDownDataCall(int pdpIndex)
{
    int ret = -1;
    unsigned char v4connectionStatus = WDS_CONNECTION_STATUS_DISCONNECTED, v6connectionStatus = WDS_CONNECTION_STATUS_DISCONNECTED;
    CM_IP_PROT ip_protocol;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);

    requestQueryDataCall(pdpIndex, &v4connectionStatus, IpFamilyV4);
    requestQueryDataCall(pdpIndex, &v6connectionStatus, IpFamilyV6);

    dbg_time("v4Conn:0x%x, v6Conn:0x%x", v4connectionStatus, v6connectionStatus);
    if (WDS_CONNECTION_STATUS_CONNECTED == v4connectionStatus)
    {
      ret = requestDeactivatePDP(pdpIndex, IpFamilyV4);

    }
    if (WDS_CONNECTION_STATUS_CONNECTED == v6connectionStatus)
    {
      ret = requestDeactivatePDP(pdpIndex, IpFamilyV6);

    }
    pthread_mutex_unlock(&CMDevMutex);
    return ret;
}


int CMRequestQueryDataCall(int pdpIndex, CM_CONN_STATE *pConnectionStatus)
{
    int ret = -1;
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    pthread_mutex_lock(&CMDevMutex);

    ret =  requestQueryDataCall(pdpIndex, pConnectionStatus, IpFamilyV4);
    if (WDS_CONNECTION_STATUS_CONNECTED == *pConnectionStatus)
    {
        pthread_mutex_unlock(&CMDevMutex);
        return ret;
    }

    ret =  requestQueryDataCall(pdpIndex, pConnectionStatus, IpFamilyV6);
    pthread_mutex_unlock(&CMDevMutex);
    return ret;


}

int CMDhcpStart(int pdpIndex)
{
    pthread_mutex_lock(&CMDevMutex);
    udhcpc_start(&gCMDevContext,  pdpIndex);
    pthread_mutex_unlock(&CMDevMutex);
    return 0;

}

int CMDhcpStop(int pdpIndex)
{
    pthread_mutex_lock(&CMDevMutex);
    udhcpc_stop(&gCMDevContext,  pdpIndex);
    pthread_mutex_unlock(&CMDevMutex);
    return 0;
}

int CMRequestRegistrationState(unsigned char *pPSAttachedState)
{
    int ret = -1;
    pthread_mutex_lock(&CMDevMutex);
    ret = requestRegistrationState(pPSAttachedState);
    pthread_mutex_unlock(&CMDevMutex);
    return ret;
}
int CMRegisterDataCallListChangeListener(void (*OnCMDataCallListChanged)(int pdpIndex, CM_IP_PROT ip_protocol, unsigned char state))
{
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    gCMDevContext.dataCallListChanged = OnCMDataCallListChanged;
    return 0;
}
int CMRegisterRegisterStateChangedListener(void (*OnRegisterStateChangedd)(CM_NAS_REG_STATE reg_state, CM_CS_ATTACH_STATE cs_state, CM_PS_ATTACH_STATE ps_state))
{
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    gCMDevContext.registerStateChanged = OnRegisterStateChangedd;
    return 0;
}

int CMRegisterRegisterHardwareRemovedListener(void (*OnHardwareRemoved)()){
    if(!gCMInited) {
        dbg_time("CM not init yet");
        return -1;
    }
    gCMDevContext.hardwareRemoved = OnHardwareRemoved;
    return 0;

}


int CMUnregisterDataCallListChangeListener(void)
{
    gCMDevContext.dataCallListChanged = NULL;
    return 0;
}
int CMUnregisterRegisterStateChangedListener(void)
{
    gCMDevContext.registerStateChanged = NULL;
    return 0;

}

int CMUnregisterRegisterHardwareRemovedListener(void)
{
    gCMDevContext.hardwareRemoved = NULL;
    return 0;

}


