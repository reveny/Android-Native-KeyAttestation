//
// Created by reveny on 29/12/2023.
//
#pragma once

#include "Asn1Utils.hpp"
#include <jni.h>
#include <android/log.h>

class RootOfTrust {
public:
    static const int VERIFIED_BOOT_KEY_INDEX = 0;
    static const int DEVICE_LOCKED_INDEX = 1;
    static const int VERIFIED_BOOT_STATE_INDEX = 2;

    enum VerifiedBootState {
        KM_VERIFIED_BOOT_VERIFIED = 0,
        KM_VERIFIED_BOOT_SELF_SIGNED = 1,
        KM_VERIFIED_BOOT_UNVERIFIED = 2,
        KM_VERIFIED_BOOT_FAILED = 3,
    };

    jbyteArray verifiedBootKey;
    bool deviceLocked = true;
    VerifiedBootState verifiedBootState;

    RootOfTrust(JNIEnv *env, jobject asn1Encodable) {
        jclass sequenceClass = env->FindClass("org/bouncycastle/asn1/ASN1Sequence");
        if (!env->IsInstanceOf(asn1Encodable, sequenceClass)) {
            SAFE_THROW(env, "java/lang/IllegalArgumentException", "Expected sequence for authorization list")
        }

        jmethodID getObjectAtMethod = env->GetMethodID(sequenceClass, "getObjectAt", "(I)Lorg/bouncycastle/asn1/ASN1Encodable;");
        verifiedBootKey = Asn1Utils::GetByteArrayFromAsn1(env, env->CallObjectMethod(asn1Encodable, getObjectAtMethod, VERIFIED_BOOT_KEY_INDEX));
        deviceLocked = Asn1Utils::GetBooleanFromAsn1(env, env->CallObjectMethod(asn1Encodable, getObjectAtMethod, DEVICE_LOCKED_INDEX));
        verifiedBootState = (VerifiedBootState) Asn1Utils::GetIntegerFromAsn1(env, env->CallObjectMethod(asn1Encodable, getObjectAtMethod, VERIFIED_BOOT_STATE_INDEX));
    }

    bool isDeviceLocked() {
        return deviceLocked;
    }

    int getVerifiedBootState() {
        return verifiedBootState;
    }

    std::string getVerifiedBootStateString() {
        switch (verifiedBootState) {
            case VerifiedBootState::KM_VERIFIED_BOOT_VERIFIED: return "Verified";
            case VerifiedBootState::KM_VERIFIED_BOOT_SELF_SIGNED: return "Self Signed";
            case VerifiedBootState::KM_VERIFIED_BOOT_UNVERIFIED: return "Unverified";
            case VerifiedBootState::KM_VERIFIED_BOOT_FAILED: return "Failed";
        }
    }
};