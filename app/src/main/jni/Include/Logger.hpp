//
// Created by reveny on 26/10/2023.
//

#ifndef ANDROID_ROOT_DETECTION_LOGGER_H
#define ANDROID_ROOT_DETECTION_LOGGER_H

#include <android/log.h>

#define LOG_TAG "KeyAttestation"
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))

#endif
