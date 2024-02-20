//
// Created by reveny on 19/02/2024.
//

#include <jni.h>
#include "KeyAttestation/KeyAttestation.hpp"

extern "C" {
    JNIEXPORT jstring JNICALL
    Java_com_reveny_nativekeyattestation_MainActivity_getAttestationResult(JNIEnv *env, jobject thiz)
    {
        KeyAttestation::AttestationResult result = KeyAttestation::StartAttestation(env, false, false, false);

        if (result == KeyAttestation::AttestationResult::Error || result == KeyAttestation::AttestationResult::CriticalError) {
            return env->NewStringUTF("Could not run Attestation. See Log for reason.");
        }

        return env->NewStringUTF(KeyAttestation::outData.c_str());
    }
}