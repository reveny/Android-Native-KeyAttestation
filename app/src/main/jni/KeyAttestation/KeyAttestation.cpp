//
// Created by reveny on 02/01/2024.
//
#include "KeyAttestation.hpp"
#include "Include/Logger.hpp"
#include <set>

namespace KeyAttestation {
    jbyteArray attestationChallenge = nullptr;
    std::string outData = {};
    AttestationResult attestationResult = AttestationResult::CriticalError;

    std::unique_ptr<Attest> softwareEnforced = nullptr;
    std::unique_ptr<Attest> teeEnforced = nullptr;
}

jobject KeyAttestation::ParseAsn1Encodable(JNIEnv* env, jobject parser) {
    jclass parserClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1SequenceParser");
    jmethodID readObjectMethod = SAFE_GET_METHOD_ID(env, parserClass, "readObject", "()Lorg/bouncycastle/asn1/ASN1Encodable;");
    SAFE_FAILIURE_RETURN_VALUE(env, readObjectMethod, nullptr);

    return env->CallObjectMethod(parser, readObjectMethod);
}

std::string KeyAttestation::VerifiedBootStateToString(int verifiedBootState) {
    switch (verifiedBootState) {
        case RootOfTrust::KM_VERIFIED_BOOT_VERIFIED: return "Verified";
        case RootOfTrust::KM_VERIFIED_BOOT_SELF_SIGNED: return "Self-signed";
        case RootOfTrust::KM_VERIFIED_BOOT_UNVERIFIED: return "Unverified";
        case RootOfTrust::KM_VERIFIED_BOOT_FAILED: return "Failed";
        default: return "Unknown (" + std::to_string(verifiedBootState) + ")";
    }
}

jobject KeyAttestation::ParseAsn1TaggedObject(JNIEnv* env, jobject parser) {
    jobject asn1Encodable = ParseAsn1Encodable(env, parser);
    SAFE_FAILIURE_RETURN_VALUE(env, asn1Encodable, nullptr);

    jclass taggedObjectClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1TaggedObject");
    if (env->IsInstanceOf(asn1Encodable, taggedObjectClass)) {
        return asn1Encodable;
    } else {
        SAFE_THROW(env, "java/lang/IllegalArgumentException", "Expected ASN1TaggedObject");
        return nullptr;
    }
}

jobject KeyAttestation::GetAttestationSequence(JNIEnv* env, jobject x509Cert) {
    jclass x509CertClass = SAFE_FIND_CLASS(env, "java/security/cert/X509Certificate");
    jmethodID getExtensionValueMethod = SAFE_GET_METHOD_ID(env, x509CertClass, "getExtensionValue", "(Ljava/lang/String;)[B");
    jstring asn1Oid = env->NewStringUTF(ASN1_OID.c_str());

    jbyteArray attestationExtensionBytes = static_cast<jbyteArray>(env->CallObjectMethod(x509Cert, getExtensionValueMethod, asn1Oid));
    SAFE_FAILIURE_RETURN_VALUE(env, attestationExtensionBytes, nullptr);

    jsize length = env->GetArrayLength(attestationExtensionBytes);
    if (length == 0) {
        SAFE_THROW(env, "java/lang/IllegalArgumentException", "Expected ASN1TaggedObject");
        return nullptr;
    }

    return Asn1Utils::GetAsn1SequenceFromBytes(env, attestationExtensionBytes);
}

void KeyAttestation::Asn1Attestation(JNIEnv* env, jobject cert) {
    auto GetObjectAt = [env](jobject sequence, int index) -> jobject {
        jclass sequenceClass = env->FindClass("org/bouncycastle/asn1/ASN1Sequence");
        jmethodID getObjectAtMethod = env->GetMethodID(sequenceClass, "getObjectAt", "(I)Lorg/bouncycastle/asn1/ASN1Encodable;");
        return env->CallObjectMethod(sequence, getObjectAtMethod, index);
    };

    jobject seq = GetAttestationSequence(env, cert);
    SAFE_FAILIURE_RETURN_VOID(env, seq);

    jobject challengeObj = GetObjectAt(seq, ATTESTATION_CHALLENGE_INDEX);
    SAFE_FAILIURE_RETURN_VOID(env, challengeObj);
    attestationChallenge = Asn1Utils::GetByteArrayFromAsn1(env, challengeObj);

    jobject softwareObj = GetObjectAt(seq, SW_ENFORCED_INDEX);
    SAFE_FAILIURE_RETURN_VOID(env, softwareObj);
    softwareEnforced = std::make_unique<Attest>(env, softwareObj);

    jobject teeObj = GetObjectAt(seq, TEE_ENFORCED_INDEX);
    SAFE_FAILIURE_RETURN_VOID(env, teeObj);
    teeEnforced = std::make_unique<Attest>(env, teeObj);
}

void KeyAttestation::LoadFromCert(JNIEnv* env, jobject cert) {
    jclass x509CertClass = SAFE_FIND_CLASS(env, "java/security/cert/X509Certificate");
    SAFE_FAILIURE_RETURN_VOID(env, x509CertClass);

    jmethodID getExtensionValueMethod = SAFE_GET_METHOD_ID(env, x509CertClass, "getExtensionValue", "(Ljava/lang/String;)[B");
    SAFE_FAILIURE_RETURN_VOID(env, getExtensionValueMethod);

    jstring asn1Oid = env->NewStringUTF(ASN1_OID.c_str());
    jstring eatOid = env->NewStringUTF(EAT_OID.c_str());
    jstring crlDpOid = env->NewStringUTF(CRL_DP_OID.c_str());

    if (env->CallObjectMethod(cert, getExtensionValueMethod, asn1Oid) == NULL) {
        jmethodID getIssuerDNMethod = env->GetMethodID(x509CertClass, "getIssuerDN", "()Ljava/security/Principal;");
        jobject issuerDN = env->CallObjectMethod(cert, getIssuerDNMethod);
        SAFE_FAILIURE_RETURN_VOID(env, issuerDN);

        jmethodID getNameMethod = env->GetMethodID(env->GetObjectClass(issuerDN), "getName", "()Ljava/lang/String;");
        jstring name = (jstring)env->CallObjectMethod(issuerDN, getNameMethod);

        // Do not throw exception here because this is actually expected.
        // SAFE_THROW(env, "java/lang/IllegalArgumentException", "Invalid issuer");
        throw std::runtime_error("Invalid issuer");
    }

    if (env->CallObjectMethod(cert, getExtensionValueMethod, eatOid) != nullptr) {
        if (env->CallObjectMethod(cert, getExtensionValueMethod, asn1Oid) != nullptr) {
            SAFE_THROW(env, "java/lang/IllegalArgumentException", "Multiple attestation extensions found");
        }
    }

    if (env->CallObjectMethod(cert, getExtensionValueMethod, crlDpOid) != nullptr) {
        LOGE("CRL Distribution Points extension found in leaf certificate.");
    }

    Asn1Attestation(env, cert);
}

bool KeyAttestation::CheckAttestation(JNIEnv* env, jobject certificate) {
    try {
        LoadFromCert(env, certificate);

        if (!softwareEnforced || !teeEnforced) {
            LOGE("CheckAttestation -> Tee or Software is null %p %p", softwareEnforced.get(), teeEnforced.get());
            return false;
        }

        std::set<int> purposes = !teeEnforced->purposes.empty() ? teeEnforced->purposes : softwareEnforced->purposes;
        return !(purposes.empty() || purposes.find(7) == purposes.end());
    } catch (...) {
        return false;
    }
}

KeyAttestation::AttestationResult KeyAttestation::ParseCertificateChain(JNIEnv* env, jobjectArray certs) {
    SAFE_FAILIURE_RETURN_VALUE(env, certs, AttestationResult::Error);

    int size = env->GetArrayLength(certs);
    jobject parent = env->GetObjectArrayElement(certs, size - 1);
    for (int i = size - 1; i >= 0; i--) {
        jobject current = env->GetObjectArrayElement(certs, i);
        SAFE_FAILIURE_RETURN_VALUE(env, current, AttestationResult::Error);

        if (CheckAttestation(env, current)) {
            break;
        }
    }

    // Software and Tee broken, return error.
    if (softwareEnforced.get() == nullptr && teeEnforced.get() == nullptr) {
        return AttestationResult::Error;
    }

    if (teeEnforced.get() != nullptr && teeEnforced->rootOfTrust != nullptr) {
        attestationResult = (!teeEnforced->rootOfTrust->isDeviceLocked() || teeEnforced->rootOfTrust->getVerifiedBootState() != RootOfTrust::KM_VERIFIED_BOOT_VERIFIED) ? AttestationResult::Unlocked : AttestationResult::Locked;
        outData = "Verified Boot State: " + teeEnforced->rootOfTrust->getVerifiedBootStateString() + "\n"
                + "Is Device Locked: " + std::string(teeEnforced->rootOfTrust->isDeviceLocked() ? "true" : "false");
    }

    // I assume that Software isn't as reliable as Tee so we only check that if tee returned locked.
    if (softwareEnforced.get() != nullptr && softwareEnforced->rootOfTrust != nullptr && attestationResult != AttestationResult::Unlocked) {
        attestationResult = (!softwareEnforced->rootOfTrust->isDeviceLocked() || softwareEnforced->rootOfTrust->getVerifiedBootState() != RootOfTrust::KM_VERIFIED_BOOT_VERIFIED) ? AttestationResult::Unlocked : AttestationResult::Locked;
        outData = "Verified Boot State: " + softwareEnforced->rootOfTrust->getVerifiedBootStateString() + "\n"
                + "Is Device Unlocked: " + std::string(softwareEnforced->rootOfTrust->isDeviceLocked() ? "true" : "false");
    }

    // LOGI("ParseCertificateChain -> Result: %d", attestationResult);
    return attestationResult;
}

void KeyAttestation::GenerateKey(JNIEnv* env, jstring alias, jboolean useStrongBox, jboolean includeProps, jstring attestKeyAlias) {
    jclass dateClass = SAFE_FIND_CLASS(env, "java/util/Date");
    jmethodID dateConstructor = SAFE_GET_METHOD_ID(env, dateClass, "<init>", "()V");
    jobject now = env->NewObject(dateClass, dateConstructor);
    SAFE_FAILIURE_RETURN_VOID(env, now);

    jmethodID attestKeyID = SAFE_GET_METHOD_ID(env, env->GetObjectClass(alias), "equals", "(Ljava/lang/Object;)Z")
    jboolean attestKey = env->CallBooleanMethod(alias, attestKeyID, attestKeyAlias);
    SAFE_JNI_CHECK(env);

    jint purposes = (android_get_device_api_level() >= 31 && attestKey) ? 128 : (4 | 8);

    jclass builderClass = SAFE_FIND_CLASS(env, "android/security/keystore/KeyGenParameterSpec$Builder");
    jmethodID builderConstructor = SAFE_GET_METHOD_ID(env, builderClass, "<init>", "(Ljava/lang/String;I)V");
    jobject builder = env->NewObject(builderClass, builderConstructor, alias, purposes);
    SAFE_FAILIURE_RETURN_VOID(env, builder);

    jmethodID setAlgorithmParameterSpecMethod = SAFE_GET_METHOD_ID(env, builderClass, "setAlgorithmParameterSpec", "(Ljava/security/spec/AlgorithmParameterSpec;)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
    jclass ecGenParameterSpecClass = SAFE_FIND_CLASS(env, "java/security/spec/ECGenParameterSpec");
    jmethodID ecGenParameterSpecConstructor = SAFE_GET_METHOD_ID(env, ecGenParameterSpecClass, "<init>", "(Ljava/lang/String;)V");
    jobject ecGenParameterSpec = env->NewObject(ecGenParameterSpecClass, ecGenParameterSpecConstructor, env->NewStringUTF("secp256r1"));
    SAFE_FAILIURE_RETURN_VOID(env, ecGenParameterSpec);

    env->CallObjectMethod(builder, setAlgorithmParameterSpecMethod, ecGenParameterSpec);

    jclass stringClass = SAFE_FIND_CLASS(env, "java/lang/String");
    jobjectArray digests = env->NewObjectArray(1, stringClass, nullptr);
    SAFE_FAILIURE_RETURN_VOID(env, digests);
    env->SetObjectArrayElement(digests, 0, env->NewStringUTF("SHA-256"));

    jmethodID setDigestsMethod = env->GetMethodID(builderClass, "setDigests", "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
    env->CallObjectMethod(builder, setDigestsMethod, digests);

    jmethodID setKeyValidityStartMethod = env->GetMethodID(builderClass, "setKeyValidityStart", "(Ljava/util/Date;)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
    env->CallObjectMethod(builder, setKeyValidityStartMethod, now);

    jmethodID setAttestationChallengeMethod = env->GetMethodID(builderClass, "setAttestationChallenge", "([B)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
    jmethodID getBytesMethod = env->GetMethodID(env->FindClass("java/lang/String"), "getBytes", "()[B");
    jmethodID toStringID = SAFE_GET_METHOD_ID(env, dateClass, "toString", "()Ljava/lang/String;");
    jbyteArray challenge = (jbyteArray)env->CallObjectMethod(env->CallObjectMethod(now, toStringID), getBytesMethod);
    SAFE_FAILIURE_RETURN_VOID(env, challenge);
    env->CallObjectMethod(builder, setAttestationChallengeMethod, challenge);

    if (android_get_device_api_level() >= 28 && useStrongBox) {
        jmethodID setIsStrongBoxBackedMethod = SAFE_GET_METHOD_ID(env, builderClass, "setIsStrongBoxBacked", "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
        env->CallObjectMethod(builder, setIsStrongBoxBackedMethod, JNI_TRUE);
    }

    if (android_get_device_api_level() >= 31) {
        if (includeProps) {
            jmethodID setDevicePropertiesAttestationIncludedMethod = env->GetMethodID(builderClass, "setDevicePropertiesAttestationIncluded", "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
            env->CallObjectMethod(builder, setDevicePropertiesAttestationIncludedMethod, JNI_TRUE);
        }

        if (attestKeyAlias != NULL && !attestKey) {
            jmethodID setAttestKeyAliasMethod = env->GetMethodID(builderClass, "setAttestKeyAlias", "(Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
            env->CallObjectMethod(builder, setAttestKeyAliasMethod, attestKeyAlias);
        }

        if (attestKey) {
            jmethodID setCertificateSubjectMethod = env->GetMethodID(builderClass, "setCertificateSubject", "(Ljavax/security/auth/x500/X500Principal;)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
            jclass x500PrincipalClass = env->FindClass("javax/security/auth/x500/X500Principal");
            jmethodID x500PrincipalConstructor = env->GetMethodID(x500PrincipalClass, "<init>", "(Ljava/lang/String;)V");
            jobject x500Principal = env->NewObject(x500PrincipalClass, x500PrincipalConstructor, env->NewStringUTF("CN=App Attest Key"));
            SAFE_FAILIURE_RETURN_VOID(env, x500Principal);
            env->CallObjectMethod(builder, setCertificateSubjectMethod, x500Principal);
        }
    }

    jclass keyPairGeneratorClass = SAFE_FIND_CLASS(env, "java/security/KeyPairGenerator");
    jmethodID getInstanceMethod = SAFE_GET_STATIC_METHOD_ID(env, keyPairGeneratorClass, "getInstance", "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;");
    jobject keyPairGenerator = env->CallStaticObjectMethod(keyPairGeneratorClass, getInstanceMethod, env->NewStringUTF("EC"), env->NewStringUTF("AndroidKeyStore"));
    SAFE_FAILIURE_RETURN_VOID(env, keyPairGenerator);

    jmethodID initializeMethod = SAFE_GET_METHOD_ID(env, keyPairGeneratorClass, "initialize", "(Ljava/security/spec/AlgorithmParameterSpec;)V");
    jmethodID buildMethod = SAFE_GET_METHOD_ID(env, builderClass, "build", "()Landroid/security/keystore/KeyGenParameterSpec;");
    env->CallVoidMethod(keyPairGenerator, initializeMethod, env->CallObjectMethod(builder, buildMethod));

    jmethodID generateKeyPairMethod = SAFE_GET_METHOD_ID(env, keyPairGeneratorClass, "generateKeyPair", "()Ljava/security/KeyPair;");
    env->CallObjectMethod(keyPairGenerator, generateKeyPairMethod);
}

KeyAttestation::AttestationResult KeyAttestation::StartAttestation(JNIEnv* env, jboolean useStrongBox, jboolean includeProps, jboolean useAttestKey) {
    auto AddToArray = [env](jobjectArray array, jobject element) -> jobjectArray {
        jsize length = env->GetArrayLength(array);
        jobjectArray newArray = env->NewObjectArray(length + 1, env->GetObjectClass(element), NULL);

        for (jsize i = 0; i < length; i++) {
            env->SetObjectArrayElement(newArray, i, env->GetObjectArrayElement(array, i));
        }

        env->SetObjectArrayElement(newArray, length, element);
        return newArray;
    };

    jclass certClass = SAFE_FIND_CLASS(env, "java/security/cert/Certificate");
    jobjectArray certs = env->NewObjectArray(0, certClass, nullptr);
    jstring alias = env->NewStringUTF("reveny");
    jstring attestKeyAlias = useAttestKey ? env->NewStringUTF("reveny_persistent") : nullptr;

    jclass keyStoreClass = SAFE_FIND_CLASS(env, "java/security/KeyStore");
    jmethodID getInstanceMethod = SAFE_GET_STATIC_METHOD_ID(env, keyStoreClass, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;");
    jobject keyStore = env->CallStaticObjectMethod(keyStoreClass, getInstanceMethod, env->NewStringUTF("AndroidKeyStore"));
    SAFE_FAILIURE_RETURN_VALUE(env, keyStore, AttestationResult::Error);

    jmethodID loadMethod = SAFE_GET_METHOD_ID(env, keyStoreClass, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V");
    env->CallVoidMethod(keyStore, loadMethod, nullptr);
    SAFE_JNI_CHECK_VALUE(env, AttestationResult::Error);

    if (useAttestKey) {
        jmethodID containsAliasMethod = SAFE_GET_METHOD_ID(env, keyStoreClass, "containsAlias", "(Ljava/lang/String;)Z");
        jboolean hasAttestKey = env->CallBooleanMethod(keyStore, containsAliasMethod, attestKeyAlias);
        SAFE_JNI_CHECK_VALUE(env, AttestationResult::Error);

        if (!hasAttestKey) {
            GenerateKey(env, attestKeyAlias, useStrongBox, includeProps, attestKeyAlias);
        }
    }
    GenerateKey(env, alias, useStrongBox, includeProps, attestKeyAlias);

    jmethodID getCertificateChainMethod = SAFE_GET_METHOD_ID(env, keyStoreClass, "getCertificateChain", "(Ljava/lang/String;)[Ljava/security/cert/Certificate;");
    jobjectArray certificateChain = static_cast<jobjectArray>(env->CallObjectMethod(keyStore, getCertificateChainMethod, useAttestKey ? attestKeyAlias : alias));
    SAFE_FAILIURE_RETURN_VALUE(env, certificateChain, AttestationResult::Error);

    jclass certificateFactoryClass = SAFE_FIND_CLASS(env, "java/security/cert/CertificateFactory");
    jmethodID getInstanceCFMethod = SAFE_GET_STATIC_METHOD_ID(env, certificateFactoryClass, "getInstance", "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jobject cf = env->CallStaticObjectMethod(certificateFactoryClass, getInstanceCFMethod, env->NewStringUTF("X.509"));
    SAFE_FAILIURE_RETURN_VALUE(env, cf, AttestationResult::Error);

    jclass byteArrayInputStreamClass = SAFE_FIND_CLASS(env, "java/io/ByteArrayInputStream");
    jmethodID byteArrayInputStreamConstructor = SAFE_GET_METHOD_ID(env, byteArrayInputStreamClass, "<init>", "([B)V");
    jmethodID generateCertificateMethod = SAFE_GET_METHOD_ID(env, certificateFactoryClass, "generateCertificate", "(Ljava/io/InputStream;)Ljava/security/cert/Certificate;");

    jsize chainLength = env->GetArrayLength(certificateChain);
    for (jsize i = 0; i < chainLength; i++) {
        jobject cert = env->GetObjectArrayElement(certificateChain, i);
        jmethodID getEncodedMethod = SAFE_GET_METHOD_ID(env, certClass, "getEncoded", "()[B");
        jbyteArray encodedCert = static_cast<jbyteArray>(env->CallObjectMethod(cert, getEncodedMethod));
        SAFE_FAILIURE_RETURN_VALUE(env, encodedCert, AttestationResult::Error);

        jobject inputStream = env->NewObject(byteArrayInputStreamClass, byteArrayInputStreamConstructor, encodedCert);
        SAFE_FAILIURE_RETURN_VALUE(env, inputStream, AttestationResult::Error);

        jobject x509Cert = env->CallObjectMethod(cf, generateCertificateMethod, inputStream);
        SAFE_FAILIURE_RETURN_VALUE(env, x509Cert, AttestationResult::Error);

        certs = AddToArray(certs, x509Cert);
    }

    jobjectArray x509Certs = env->NewObjectArray(0, env->FindClass("java/security/cert/X509Certificate"), NULL);
    jsize length = env->GetArrayLength(certs);
    for (jsize i = 0; i < length; i++) {
        jobject cert = env->GetObjectArrayElement(certs, i);

        if (env->IsInstanceOf(cert, env->FindClass("java/security/cert/X509Certificate"))) {
            // Add the certificate to the x509Certs array.
            x509Certs = AddToArray(x509Certs, cert);
        }
    }

    // LOGI("StartAttestation -> Size: %d", env->GetArrayLength(x509Certs));
    return ParseCertificateChain(env, x509Certs);
}