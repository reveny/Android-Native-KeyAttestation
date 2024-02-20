//
// Created by reveny on 04/02/2024.
//
#pragma once

#define THROW_JNI_EXCEPTIONS 1

#define SAFE_FIND_CLASS(env, name) SafeJNI::FindClass(env, name);
#define SAFE_GET_METHOD_ID(env, clazz, name, sig) SafeJNI::GetMethodID(env, clazz, name, sig);
#define SAFE_GET_STATIC_METHOD_ID(env, clazz, name, sig) SafeJNI::GetStaticMethodID(env, clazz, name, sig);

#define SAFE_THROW(env, clazz, info) SafeJNI::ThrowException(env, clazz, info);
#define SAFE_FAILIURE_RETURN_VALUE(env, obj, ret) if (obj == nullptr || env->ExceptionCheck()) { env->ExceptionClear(); return ret; }
#define SAFE_FAILIURE_RETURN_VOID(env, obj) if (obj == nullptr || env->ExceptionCheck()) { env->ExceptionClear(); return; }
#define SAFE_JNI_CHECK(env) if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
#define SAFE_JNI_CHECK_VALUE(env, val) if (env->ExceptionCheck()) { env->ExceptionClear(); return val; }

namespace SafeJNI {
    inline jclass FindClass(JNIEnv* env, const char* name) {
        jclass clazz = env->FindClass(name);
        if (!clazz) {
            if (THROW_JNI_EXCEPTIONS) env->ThrowNew(env->FindClass("java/lang/ClassNotFoundException"), name);
            return nullptr;
        }
        return clazz;
    }

    inline jmethodID GetMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
        jmethodID mid = env->GetMethodID(clazz, name, sig);
        if (!mid) {
            if (THROW_JNI_EXCEPTIONS) env->ThrowNew(env->FindClass("java/lang/NoSuchMethodException"), name);
            return nullptr;
        }
        return mid;
    }

    inline jmethodID GetStaticMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
        jmethodID mid = env->GetStaticMethodID(clazz, name, sig);
        if (!mid) {
            if (THROW_JNI_EXCEPTIONS) env->ThrowNew(env->FindClass("java/lang/NoSuchMethodException"), name);
            return nullptr;
        }
        return mid;
    }

    inline void ThrowException(JNIEnv* env, const char* clazz, const char* info) {
        if (THROW_JNI_EXCEPTIONS == 0) return;

        env->ThrowNew(env->FindClass(clazz), info);
    }
}
