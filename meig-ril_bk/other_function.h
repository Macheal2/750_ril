/*other_function.h*/

/*when who why modified*/
#ifndef __OTHER_FUNCTION_H__
#define __OTHER_FUNCTION_H__ 1
void  requestSendUSSD(void *data, size_t datalen, RIL_Token t);

void requestCancelUSSD(void *data, size_t datalen, RIL_Token t);

void requestOemHookStrings(void *data, size_t datalen, RIL_Token t);

void requestBasebandVersion(void *data, size_t datalen, RIL_Token t);

void requestGetIMEI(void *data, size_t datalen, RIL_Token t);

void requestGetIMEISV(void *data, size_t datalen, RIL_Token t);

void requestGetIMSI(void *data, size_t datalen, RIL_Token t);

/* added by zte-yuyang begin */
void requestQueryClip(void *data, size_t datalen, RIL_Token t);
/* added by zte-yuyang end */
/* begin: modified by dongmeirong for CIMI retry in case of ERROR 20210130 */
ATResponse *cimiAtCmd();
/* end: modified by dongmeirong for CIMI retry in case of ERROR 20210130 */
#endif
