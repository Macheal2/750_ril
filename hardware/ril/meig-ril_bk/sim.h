/*sim.h*/
/*when who why modified*/
#ifndef __SIM_H__
#define __SIM_H__ 1

#include "ril_common.h"
typedef enum {
    SIM_ABSENT = 0,
    SIM_NOT_READY = 1,
    SIM_READY = 2,        /* SIM_READY means the radio state is RADIO_STATE_SIM_READY */
    SIM_PIN = 3,
    SIM_PUK = 4,
    SIM_NETWORK_PERSONALIZATION = 5,
    RUIM_ABSENT = 6,
    RUIM_NOT_READY = 7,
    RUIM_READY = 8,
    RUIM_PIN = 9,
    RUIM_PUK = 10,
    RUIM_NETWORK_PERSONALIZATION = 11,
    RUIM_BUSY = 12
} SIM_Status;
void  requestSIM_IO(void *data, size_t datalen, RIL_Token t);

void  requestQueryFacilityLock(void*  data, size_t  datalen, RIL_Token  t);

void  requestSetFacilityLock(void*  data, size_t  datalen, RIL_Token  t);

void  requestEnterSimPin(void*  data, size_t  datalen, RIL_Token  t);

/* deleted by dongmeirong for PIN enter adaption 20210125 */

void  requestChangeSimPin(void*  data, size_t  datalen, RIL_Token  t);

/* begin: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/
#ifdef POLL_SIM_ABSENT_RESET_MODULE
void detectSimAbsent(void *param __unused);
#endif
/* end: add by dongmeirong for poll sim and reset module when sim is absent for SHUYUAN customer 20210707*/

#endif

