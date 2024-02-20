LOCAL_PATH := $(call my-dir)/..

include $(CLEAR_VARS)

LOCAL_CPPFLAGS += -fexceptions -Werror -Wpedantic -s -std=c++20 -w

LOCAL_C_INCLUDES := $(LOCAL_PATH)/Include \

LOCAL_MODULE           := Attestation
LOCAL_SRC_FILES        := Main.cpp KeyAttestation/KeyAttestation.cpp
LOCAL_LDLIBS           := -llog -landroid

include $(BUILD_SHARED_LIBRARY)
