# Copyright 2006 The Android Open Source Project

# XXX using libutils for simulator build only...
#
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
#support meig key read&write on modem
#depends on modify in libril&ril.h

BUILD_CUSTOMER := COMMON
#BUILD_CUSTOMER := MC551
#BUILD_CUSTOMER := JINGYI
#BUILD_CUSTOMER := RUIXUN
#BUILD_CUSTOMER := HANGSHENG
#BUILD_CUSTOMER := SHIYUAN_LIUHUAN
#BUILD_CUSTOMER := YIDAO
#BUILD_CUSTOMER := HUABEIGONGKONG
#BUILD_CUSTOMER := SHUYUAN
#BUILD_CUSTOMER := SKYWORTH
#BUILD_CUSTOMER := MT578
BUILD_VERSION := 5.0.7.4
#LOCAL_CFLAGS += -DUNSOLICITED_SIM_REFRESH
LOCAL_CFLAGS += -DUNSOLICITED_SIGNAL_STRENGTH
LOCAL_CFLAGS += -DRIL_ENABLE_MEIG_MMS 
#LOCAL_CFLAGS += -DAUTO_UPGRADE_MODEM_SUPPORT
#ECMDUP enable
#LOCAL_CFLAGS += -DECMDUP_ENABLE
LOCAL_CFLAGS += -DSEND_MMS_USE_PPP
LOCAL_CFLAGS += -DMEIG_CTS_ENABLE
LOCAL_CFLAGS += -DMEIG_NEW_FEATURE
LOCAL_CFLAGS += -DSTART_KEEP_ALIVE
ifeq ($(BUILD_CUSTOMER), MC551)
LOCAL_CFLAGS += -DRIL_ENABLE_MEIG_MMS
LOCAL_CFLAGS += -DUNSOLICITED_SIGNAL_STRENGTH
DEFAULT_ENABLE_GPS := true
endif

ifeq ($(BUILD_CUSTOMER), HUABEIGONGKONG)
LOCAL_CFLAGS += -DUNSOLICITED_SIM_REFRESH
endif

ifeq ($(BUILD_CUSTOMER), SHUYUAN)
LOCAL_CFLAGS += -DPOLL_SIM_ABSENT_RESET_MODULE
endif

ifeq ($(BUILD_CUSTOMER), YIDAO)
LOCAL_CFLAGS += -DUNSOLICITED_SIGNAL_STRENGTH
LOCAL_CFLAGS += -DDONT_REPORT_LTE_SIGNAL_STRENGTH
endif

ifeq ($(BUILD_CUSTOMER), SHIYUAN_LIUHUAN)
LOCAL_CFLAGS += -DLOCAL_IP_PROPERTY_KEY_FORMAT="\"atc.net.%s.local-ip\""
endif

ifeq ($(BUILD_CUSTOMER),RUIXUN)
DEFAULT_ENABLE_GPS := true
LOCAL_CFLAGS += -DSETUP_DATA_CALL_OPTIMIZATION
LOCAL_CFLAGS += -DDONT_REPORT_LTE_SIGNAL_STRENGTH
endif

ifeq ($(BUILD_CUSTOMER),JINGYI)
BUILD_WITI_MEIG_EXT_KEY_SUPPORT := true
DEFAULT_ENABLE_GPS := true
#BUILD_ECM_USE_STATIC_IP_ADDRESS := true
#BUILD_KEEP_ALIVE_WHEN_MODEM_LOST := true
endif

ifeq ($(BUILD_CUSTOMER),SKYWORTH)
LOCAL_CFLAGS += -DSEND_MMS_USE_PPP
LOCAL_CFLAGS += -DSUPPORT_USSD_PARTIAL
endif

ifeq ($(BUILD_CUSTOMER),MT578)
#LOCAL_CFLAGS += -DSUPPORT_BODY_SAR
LOCAL_CFLAGS += -DUNSOLICITED_SIGNAL_STRENGTH
DEFAULT_ENABLE_GPS := true
endif

ifeq ($(BUILD_KEEP_ALIVE_WHEN_MODEM_LOST),true)
LOCAL_CFLAGS += -DKEEP_ALIVE_WHEN_MODEM_LOST
endif

ifeq ($(BUILD_WITI_MEIG_EXT_KEY_SUPPORT),true)
LOCAL_CFLAGS += -DBUILD_WITI_MEIG_EXT_KEY_SUPPORT
endif

ifeq ($(BUILD_ECM_USE_STATIC_IP_ADDRESS),true)
LOCAL_CFLAGS += -DECM_USE_STATIC_IP_ADDRESS
endif

#default enable gps
ifeq ($(DEFAULT_ENABLE_GPS),true)
LOCAL_CFLAGS += -DDEFAULT_ENABLE_GPS
endif

LOCAL_SRC_FILES:= \
    meig-ril.c \
    resetep.c \
    atchannel.c \
    other_function.c \
    sim.c \
    sms.c \
    voice.c \
    misc.c \
    at_tok.c \
    usb_monitor.c \
    getdevinfo.c \
    meig-pppd.c \
    meig-gps.c
USE_NDIS := 1
ifeq ($(USE_NDIS),1)
LOCAL_CFLAGS += -DANDROID -DUSE_NDIS
$(shell touch $(LOCAL_PATH)/libmeigcm/*)
#LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/libmeigcm/src/*.c)
LOCAL_SRC_FILES += \
    libmeigcm/device.c \
    libmeigcm/gobinet_cm.c \
    libmeigcm/meig_cm_core.c \
    libmeigcm/udhcpc.c \
    libmeigcm/dhcpclient.c \
    libmeigcm/meig_cm.c \
    libmeigcm/mpqmux.c \
    libmeigcm/util.c
endif




#[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support {
LOCAL_SHARED_LIBRARIES := \
    liblog libcutils libutils libril librilutils libnetutils libdl

 $(warning  "sdk version is $(PLATFORM_SDK_VERSION)")
ifneq (,$(filter 24 25 26 27 28 29 30, $(PLATFORM_SDK_VERSION)))
ifeq ($(BUILD_CUSTOMER),JINGYI)
REFERENCE_RIL_VERSION := "\"MEIG_RIL_Android7.x-later-JY_V$(BUILD_VERSION)\""
else
REFERENCE_RIL_VERSION := "\"MEIG_RIL_Android7.x-later-V$(BUILD_VERSION)\""
endif

endif

ifneq (,$(filter 23, $(PLATFORM_SDK_VERSION)))
REFERENCE_RIL_VERSION := "\"MEIG_RIL_Android6.0_V$(BUILD_VERSION)\""
endif

ifneq (,$(filter 21 22, $(PLATFORM_SDK_VERSION)))
REFERENCE_RIL_VERSION := "\"MEIG_RIL_Android5.x_V$(BUILD_VERSION)\""
endif

ifneq (,$(filter 18 19, $(PLATFORM_SDK_VERSION)))
ifeq ($(BUILD_CUSTOMER),HANGSHENG)
LOCAL_CFLAGS += -DRIL_REQUEST_ADCREADEX=114
REFERENCE_RIL_VERSION := "\"MEIG_RIL_Android4.x-HS_V$(BUILD_VERSION)\""
else
REFERENCE_RIL_VERSION := "\"MEIG_RIL_Android4.x_V$(BUILD_VERSION)\""
endif
endif

#[zhaopf@meigsmart.com-2020-0619]modify for Android5.0, Android6.0 support }
BUILD_TIME="\"$(shell date  "+%Y/%m/%d-%T")\""
BUILD_AUTHOR="\"Dongmeirong\""
#CM_DEBUG
LOCAL_CFLAGS += -DANDROID -DUSE_NDIS -DBUILD_TIME=${BUILD_TIME} -DBUILD_AUTHOR=${BUILD_AUTHOR} -DREFERENCE_RIL_VERSION=${REFERENCE_RIL_VERSION} -DBUILD_CUSTOMER="\"${BUILD_CUSTOMER}\""


# for asprinf
LOCAL_CFLAGS += -D_GNU_SOURCE

LOCAL_PROPRIETARY_MODULE := true

#LOCAL_C_INCLUDES :=

ifeq ($(TARGET_DEVICE),sooner)
  LOCAL_CFLAGS += -DUSE_TI_COMMANDS
endif

ifeq ($(TARGET_DEVICE),surf)
  LOCAL_CFLAGS += -DPOLL_CALL_STATE -DUSE_QMI
endif

ifeq ($(TARGET_DEVICE),dream)
  LOCAL_CFLAGS += -DPOLL_CALL_STATE -DUSE_QMI
endif

ifeq (foo,foo)
  #build shared library
  LOCAL_SHARED_LIBRARIES += \
      libcutils libutils
  LOCAL_CFLAGS += \
	-DPLATFORM_SDK_VERSION=$(PLATFORM_SDK_VERSION) \
	-DRIL_SHLIB
ifneq (, $(filter 28 29 30 31, $(PLATFORM_SDK_VERSION)))
  LOCAL_CFLAGS += \
	-Wno-format-extra-args \
	-Wno-unused-parameter \
	-Wno-unused-variable \
	-Wno-unused-parameter \
	-Wno-unused-function \
	-Wno-unused-result \
	-Wno-implicit-function-declaration \
	-Wno-sign-compare \
	-Wno-maybe-uninitialized \
	-Wno-format \
	-Wno-pragma-pack \
	-Wno-parentheses-equality \
	-Wno-unused-function \
	-Wno-sign-compare \
	-Wno-pointer-sign \
	-Wno-implicit-function-declaration \
	-Wno-incompatible-pointer-types \
	-Wno-char-subscripts \
	-Wno-for-loop-analysis \
	-Wno-conditional-type-mismatch \
        -Wno-typedef-redefinition \
        -Wno-unused-label \
        -Wno-switch  \
        -Wno-implicit-function-declaration
endif	
  LOCAL_MODULE:= libmeig-ril
  include $(BUILD_SHARED_LIBRARY)
else
  #build executable
  LOCAL_SHARED_LIBRARIES += \
      libril
  LOCAL_MODULE:= meig-ril
  include $(BUILD_EXECUTABLE)
endif

