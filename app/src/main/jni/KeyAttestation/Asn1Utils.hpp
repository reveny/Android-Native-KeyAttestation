//
// Created by reveny on 29/12/2023.
//
#pragma once

#include <jni.h>
#include <string>
#include <stdio.h>

#include "Include/SafeJNI.hpp"

namespace Asn1Utils {
    inline jbyteArray GetByteArrayFromAsn1(JNIEnv *env, jobject asn1Encodable) {
        jclass derOctetStringClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/DEROctetString");
        if (asn1Encodable == nullptr || !env->IsInstanceOf(asn1Encodable, derOctetStringClass)) {
            SAFE_THROW(env, "java/lang/IllegalArgumentException", "Expected DEROctetString");
            return nullptr;
        }
        jmethodID getOctetsMethod = SAFE_GET_METHOD_ID(env, derOctetStringClass, "getOctets", "()[B");
        SAFE_FAILIURE_RETURN_VALUE(env, getOctetsMethod, nullptr);

        return (jbyteArray)env->CallObjectMethod(asn1Encodable, getOctetsMethod);
    }

    inline jobject GetAsn1SequenceFromStream(JNIEnv* env, jobject asn1InputStream) {
        jclass asn1InputStreamClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1InputStream");
        jmethodID readObjectMethod = SAFE_GET_METHOD_ID(env, asn1InputStreamClass, "readObject", "()Lorg/bouncycastle/asn1/ASN1Primitive;");
        SAFE_FAILIURE_RETURN_VALUE(env, readObjectMethod, nullptr);

        jobject asn1Primitive = env->CallObjectMethod(asn1InputStream, readObjectMethod);
        SAFE_FAILIURE_RETURN_VALUE(env, asn1Primitive, nullptr);

        jclass octetStringClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1OctetString");
        if (!env->IsInstanceOf(asn1Primitive, octetStringClass)) {
            SAFE_THROW(env, "java/lang/IllegalArgumentException", "Expected octet stream");
            return nullptr;
        }

        jmethodID getOctetsMethod = SAFE_GET_METHOD_ID(env, octetStringClass, "getOctets", "()[B");
        SAFE_FAILIURE_RETURN_VALUE(env, getOctetsMethod, nullptr);

        jbyteArray octets = static_cast<jbyteArray>(env->CallObjectMethod(asn1Primitive, getOctetsMethod));
        jmethodID inputStreamID = SAFE_GET_METHOD_ID(env, asn1InputStreamClass, "<init>", "([B)V");
        jobject seqInputStream = env->NewObject(asn1InputStreamClass, inputStreamID, octets);
        SAFE_FAILIURE_RETURN_VALUE(env, seqInputStream, nullptr);

        asn1Primitive = env->CallObjectMethod(seqInputStream, readObjectMethod);
        SAFE_FAILIURE_RETURN_VALUE(env, asn1Primitive, nullptr);

        jclass sequenceClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1Sequence");
        if (!env->IsInstanceOf(asn1Primitive, sequenceClass)) {
            SAFE_THROW(env, "java/lang/IllegalArgumentException", "Expected sequence");
            return nullptr;
        }

        return asn1Primitive;
    }

    inline jobject GetAsn1SequenceFromBytes(JNIEnv* env, jbyteArray bytes) {
        jclass asn1InputStreamClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1InputStream");
        SAFE_FAILIURE_RETURN_VALUE(env, asn1InputStreamClass, nullptr);

        jmethodID asn1InputStreamConstructor = SAFE_GET_METHOD_ID(env, asn1InputStreamClass, "<init>", "([B)V");
        SAFE_FAILIURE_RETURN_VALUE(env, asn1InputStreamConstructor, nullptr);

        jobject asn1InputStream = env->NewObject(asn1InputStreamClass, asn1InputStreamConstructor, bytes);
        SAFE_FAILIURE_RETURN_VALUE(env, asn1InputStream, nullptr);

        return GetAsn1SequenceFromStream(env, asn1InputStream);
    }

    inline jboolean GetBooleanFromAsn1(JNIEnv *env, jobject value) {
        jclass booleanClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1Boolean");
        if (!env->IsInstanceOf(value, booleanClass)) {
            SAFE_THROW(env, "java/lang/IllegalArgumentException", "Expected boolean");
            return JNI_FALSE;
        }

        jmethodID equalsMethod = SAFE_GET_METHOD_ID(env, booleanClass, "equals", "(Ljava/lang/Object;)Z");
        jobject trueValue = env->GetStaticObjectField(booleanClass, env->GetStaticFieldID(booleanClass, "TRUE", "Lorg/bouncycastle/asn1/ASN1Boolean;"));
        jobject falseValue = env->GetStaticObjectField(booleanClass, env->GetStaticFieldID(booleanClass, "FALSE", "Lorg/bouncycastle/asn1/ASN1Boolean;"));

        if (env->CallBooleanMethod(value, equalsMethod, trueValue)) {
            return JNI_TRUE;
        }
        else if (env->CallBooleanMethod(value, equalsMethod, falseValue)) {
            return JNI_FALSE;
        } else {
            SAFE_THROW(env, "java/lang/IllegalArgumentException", "Invalid boolean value");
            return JNI_FALSE;
        }
    }

    inline jint BigIntegerToInt(JNIEnv *env, jobject bigInt) {
        jclass bigIntegerClass = SAFE_FIND_CLASS(env, "java/math/BigInteger");
        SAFE_FAILIURE_RETURN_VALUE(env, bigIntegerClass, 0);

        jmethodID intValueMethod = SAFE_GET_METHOD_ID(env, bigIntegerClass, "intValue", "()I");
        SAFE_FAILIURE_RETURN_VALUE(env, intValueMethod, 0);

        return env->CallIntMethod(bigInt, intValueMethod);
    }

    inline jint GetIntegerFromAsn1(JNIEnv *env, jobject asn1Value) {
        jclass integerClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1Integer");
        jclass enumeratedClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1Enumerated");
        SAFE_FAILIURE_RETURN_VALUE(env, enumeratedClass, 0);

        if (env->IsInstanceOf(asn1Value, integerClass)) {
            return BigIntegerToInt(env, env->CallObjectMethod(asn1Value, env->GetMethodID(integerClass, "getValue", "()Ljava/math/BigInteger;")));
        } else if (env->IsInstanceOf(asn1Value, enumeratedClass)) {
            return BigIntegerToInt(env, env->CallObjectMethod(asn1Value, env->GetMethodID(enumeratedClass, "getValue", "()Ljava/math/BigInteger;")));
        } else {
            SAFE_THROW(env, "java/lang/IllegalArgumentException", "Integer value expected");
            return 0;
        }
    }

    inline std::set<int> GetIntegersFromAsn1Set(JNIEnv* env, jobject set) {
        jclass setClass = SAFE_FIND_CLASS(env, "org/bouncycastle/asn1/ASN1Set");
        if (!env->IsInstanceOf(set, setClass)) {
            SAFE_THROW(env, "java/lang/IllegalArgumentException", "Expected set");
            return std::set<int>(); // Return empty set to avoid further processing
        }

        std::set<int> resultSet;
        jmethodID getObjectsMethod = SAFE_GET_METHOD_ID(env, setClass, "getObjects", "()Ljava/util/Enumeration;");
        jobject enumeration = env->CallObjectMethod(set, getObjectsMethod);
        SAFE_FAILIURE_RETURN_VALUE(env, enumeration, std::set<int>());

        jclass enumerationClass = SAFE_FIND_CLASS(env, "java/util/Enumeration");
        jmethodID hasMoreElementsMethod = SAFE_GET_METHOD_ID(env, enumerationClass, "hasMoreElements", "()Z");
        jmethodID nextElementMethod = SAFE_GET_METHOD_ID(env, enumerationClass, "nextElement", "()Ljava/lang/Object;");
        while (env->CallBooleanMethod(enumeration, hasMoreElementsMethod)) {
            jobject asn1Integer = env->CallObjectMethod(enumeration, nextElementMethod);
            if (env->ExceptionCheck()) break;

            resultSet.insert(GetIntegerFromAsn1(env, asn1Integer));
        }

        return resultSet;
    }
}
