//
// Created by reveny on 29/12/2023.
//
#pragma once

#include <jni.h>
#include <set>

#include "RootOfTrust.hpp"

namespace KeyAttestation {
    constexpr const int KM_BYTES = 9 << 28;
    constexpr const int KM_ENUM_REP = 2 << 28;
    constexpr const int KM_TAG_ROOT_OF_TRUST = KM_BYTES | 704;
    constexpr const int KM_TAG_PURPOSE = KM_ENUM_REP | 1;
    constexpr const int KEYMASTER_TAG_TYPE_MASK = 0x0FFFFFFF;
    constexpr const int ATTESTATION_CHALLENGE_INDEX = 4;
    constexpr const int SW_ENFORCED_INDEX = 6;
    constexpr const int TEE_ENFORCED_INDEX = 7;

    const std::string EAT_OID = "1.3.6.1.4.1.11129.2.1.25";
    const std::string ASN1_OID = "1.3.6.1.4.1.11129.2.1.17";
    const std::string CRL_DP_OID = "2.5.29.31";

    extern jbyteArray attestationChallenge;

    enum AttestationResult {
        Error = -1,
        CriticalError = -2,
        Locked = 1,
        Unlocked = 0,
    };
    extern AttestationResult attestationResult;
    extern std::string outData;

    jobject ParseAsn1Encodable(JNIEnv* env, jobject parser);
    jobject ParseAsn1TaggedObject(JNIEnv* env, jobject parser);
    jobject GetAttestationSequence(JNIEnv* env, jobject x509Cert);

    class Attest {
    public:
        std::set<int> purposes;
        RootOfTrust* rootOfTrust;

        Attest(JNIEnv* env, jobject sequence) : rootOfTrust(nullptr) {
            jclass sequenceClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1Sequence");
            SAFE_FAILIURE_RETURN_VOID(env, sequenceClass);

            if (!env->IsInstanceOf(sequence, sequenceClass)) {
                SAFE_THROW(env, "java/lang/IllegalArgumentException", "Expected sequence for authorization list");
                return;
            }

            jmethodID parserMethod = SAFE_GET_METHOD_ID(env, sequenceClass, "parser", "()Lorg/bouncycastle/asn1/ASN1SequenceParser;");
            SAFE_FAILIURE_RETURN_VOID(env, parserMethod);

            jobject parser = env->CallObjectMethod(sequence, parserMethod);
            SAFE_FAILIURE_RETURN_VOID(env, parser);

            jobject entry = ParseAsn1TaggedObject(env, parser);
            while (entry != nullptr) {
                jclass taggedObjectClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1TaggedObject");
                SAFE_FAILIURE_RETURN_VOID(env, taggedObjectClass);

                jmethodID getTagNoMethod = SAFE_GET_METHOD_ID(env, taggedObjectClass, "getTagNo", "()I");
                SAFE_FAILIURE_RETURN_VOID(env, getTagNoMethod);

                jmethodID getBaseObjectMethod = SAFE_GET_METHOD_ID(env, taggedObjectClass, "getBaseObject", "()Lorg/bouncycastle/asn1/ASN1Object;");
                SAFE_FAILIURE_RETURN_VOID(env, getBaseObjectMethod);

                int tag = env->CallIntMethod(entry, getTagNoMethod);
                SAFE_JNI_CHECK(env);

                jobject value = env->CallObjectMethod(entry, getBaseObjectMethod);
                SAFE_FAILIURE_RETURN_VOID(env, value);

                switch (tag) {
                    case KM_TAG_PURPOSE & KEYMASTER_TAG_TYPE_MASK:
                        purposes = Asn1Utils::GetIntegersFromAsn1Set(env, value);
                        break;
                    case KM_TAG_ROOT_OF_TRUST & KEYMASTER_TAG_TYPE_MASK:
                        rootOfTrust = new RootOfTrust(env, value);
                        break;
                }

                entry = ParseAsn1TaggedObject(env, parser); // Move to the next entry
            }
        }

        ~Attest() {
            delete rootOfTrust; // Ensure proper cleanup
        }
    };

    extern std::unique_ptr<Attest> softwareEnforced;
    extern std::unique_ptr<Attest> teeEnforced;

    void Asn1Attestation(JNIEnv* env, jobject cert);
    void LoadFromCert(JNIEnv* env, jobject cert);
    std::string VerifiedBootStateToString(int verifiedBootState);

    void CheckStatus(JNIEnv* env, jobject cert, jobject parentKey);
    bool CheckAttestation(JNIEnv* env, jobject certificate);
    void GenerateKey(JNIEnv* env, jstring alias, jboolean useStrongBox, jboolean includeProps, jstring attestKeyAlias);

    AttestationResult ParseCertificateChain(JNIEnv* env, jobjectArray certs);
    AttestationResult StartAttestation(JNIEnv* env, jboolean useStrongBox, jboolean includeProps, jboolean useAttestKey);
}
