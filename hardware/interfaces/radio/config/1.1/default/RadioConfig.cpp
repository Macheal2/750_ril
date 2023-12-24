/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cutils/log.h>

#include "RadioConfig.h"
//zqy add
#include <android/hardware/radio/1.0/types.h>
using ::android::hardware::radio::V1_0::RadioError;
using ::android::hardware::radio::V1_0::RadioResponseType;
using ::android::hardware::radio::V1_0::CardState;
using ::android::hardware::radio::config::V1_0::SlotState;
using ::android::hardware::radio::V1_0::RadioResponseInfo;


//using ::android::hardware::radio::V1_0;


#include <android/hardware/radio/config/1.1/IRadioConfigResponse.h>
#include <android/hardware/radio/config/1.1/IRadioConfigIndication.h>
#include <android/hardware/radio/config/1.1/types.h>

#include <android/hardware/radio/config/1.0/IRadioConfigResponse.h>
#include <android/hardware/radio/config/1.0/IRadioConfigIndication.h>
#include <android/hardware/radio/config/1.0/types.h>
#include <android/hardware/radio/config/1.0/IRadioConfig.h>



namespace android {
namespace hardware {
namespace radio {
namespace config {
namespace V1_1 {
namespace implementation {

using namespace ::android::hardware::radio::config::V1_0;
using namespace ::android::hardware::radio::config::V1_1;

sp<::android::hardware::radio::config::V1_0::IRadioConfigResponse> mRadioConfigResponse;
sp<::android::hardware::radio::config::V1_0::IRadioConfigIndication> mRadioConfigIndication;

sp<::android::hardware::radio::config::V1_1::IRadioConfigResponse> mRadioConfigResponseV1_1;
sp<::android::hardware::radio::config::V1_1::IRadioConfigIndication> mRadioConfigIndicationV1_1;

// Methods from ::android::hardware::radio::config::V1_0::IRadioConfig follow.
//zqy add fuck
typedef enum {
    RIL_UIM_CARDSTATE_ABSENT     = 0,
    RIL_UIM_CARDSTATE_PRESENT    = 1,
    RIL_UIM_CARDSTATE_ERROR      = 2
} RIL_UIM_CardState;

typedef enum {
  RIL_UIM_PHYSICAL_SLOT_STATE_INACTIVE  = 0x00,
  RIL_UIM_PHYSICAL_SLOT_STATE_ACTIVE    = 0x01
} RIL_UIM_SlotState;

typedef struct {
  RIL_UIM_CardState    card_state;
  RIL_UIM_SlotState    slot_state;
/* Logical slot is valid only when the slot state is ACTIVE */
  uint8_t              logical_slot;
  char* iccid;
  char* atr;
  char* eid;
} RIL_UIM_SlotStatus;

Return<void> RadioConfig::setResponseFunctions(
    const sp<::android::hardware::radio::config::V1_0::IRadioConfigResponse>& radioConfigResponse,
    const sp<::android::hardware::radio::config::V1_0::IRadioConfigIndication>& radioConfigIndication) {
    mRadioConfigResponse = radioConfigResponse;
    mRadioConfigIndication = radioConfigIndication;

    mRadioConfigResponseV1_1 = config::V1_1::IRadioConfigResponse::castFrom(radioConfigResponse).withDefault(nullptr);
    mRadioConfigIndicationV1_1 = config::V1_1::IRadioConfigIndication::castFrom(radioConfigIndication).withDefault(nullptr);
    return Void();
}

Return<void> RadioConfig::getSimSlotsStatus(int32_t serial ) {
    hidl_vec<SimSlotStatus> slotStatus;
    RadioResponseInfo info ={RadioResponseType::SOLICITED, serial, RadioError::NONE};
	slotStatus.resize(1);
	slotStatus[0].cardState = (CardState) RIL_UIM_CARDSTATE_PRESENT;
	slotStatus[0].slotState = (SlotState)RIL_UIM_PHYSICAL_SLOT_STATE_ACTIVE;
	slotStatus[0].logicalSlotId = 0;
	slotStatus[0].atr = "";
	slotStatus[0].iccid = "";
	ALOGD("slotStatus is:%d, slot state is:%d logicalSlotId is:%d",slotStatus[0].cardState,slotStatus[0].slotState,slotStatus[0].logicalSlotId);
    //mRadioConfigResponse->getSimSlotsStatusResponse(info, slotStatus);
    mRadioConfigResponse->getSimSlotsStatusResponse(info, slotStatus);
    return Void();
}


Return<void> RadioConfig::setSimSlotsMapping(int32_t serial ,
                                             const hidl_vec<uint32_t>& slotMap ) {
    RadioResponseInfo info ={RadioResponseType::SOLICITED, serial, RadioError::NONE};
    mRadioConfigResponse->setSimSlotsMappingResponse(info);
    return Void();
}

// Methods from ::android::hardware::radio::config::V1_1::IRadioConfig follow.
Return<void> RadioConfig::getPhoneCapability(int32_t serial) {
	RadioResponseInfo info ={RadioResponseType::SOLICITED, serial, RadioError::NONE};
	V1_1::PhoneCapability phoneCapa = {};
	phoneCapa.maxActiveData = 5;
	phoneCapa.maxActiveInternetData = 2;
	ALOGD("getPhoneCapability maxActiveData is:%d",phoneCapa.maxActiveData);
    mRadioConfigResponseV1_1->getPhoneCapabilityResponse(info,phoneCapa);
    // TODO implement
    return Void();
}

Return<void> RadioConfig::setPreferredDataModem(int32_t serial, uint8_t modemId) {
    RadioResponseInfo info ={RadioResponseType::SOLICITED, serial,  RadioError::NONE};
	mRadioConfigResponseV1_1->setPreferredDataModemResponse(info);
    // TODO implement
    return Void();
}

Return<void> RadioConfig::setModemsConfig(int32_t serial, const ModemsConfig& modemsConfig) {
    RadioResponseInfo info ={RadioResponseType::SOLICITED, serial, RadioError::NONE};
	if(modemsConfig.numOfLiveModems == 0){
		info.error = RadioError::INVALID_ARGUMENTS;
	}
    mRadioConfigResponseV1_1->setModemsConfigResponse(info);
    return Void();
}

Return<void> RadioConfig::getModemsConfig(int32_t serial) {
    RadioResponseInfo info ={RadioResponseType::SOLICITED, serial, RadioError::NONE};
	V1_1:: ModemsConfig modemConfig = {};
    mRadioConfigResponseV1_1->getModemsConfigResponse(info,modemConfig);
    return Void();
}

#if 0 
// Methods from ::android::hardware::radio::config::V1_1::IRadioConfig follow.
Return<void> RadioConfig::getPhoneCapability(int32_t serial) {
    // TODO implement
    return Void();
}

Return<void> RadioConfig::setPreferredDataModem(int32_t serial, uint8_t modemId) {
    // TODO implement
    return Void();
}

Return<void> RadioConfig::setModemsConfig(int32_t serial, const ModemsConfig& modemsConfig) {
    return Void();
}

Return<void> RadioConfig::getModemsConfig(int32_t serial) {
    return Void();
}
#endif

}  // namespace implementation
}  // namespace V1_1
}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
