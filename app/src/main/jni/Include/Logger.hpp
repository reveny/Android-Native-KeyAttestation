//
// Created by reveny on 26/10/2023.
//
#pragma once

#include <android/log.h>

#define LOG_TAG "KeyAttestation"
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))