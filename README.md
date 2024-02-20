# Android-Native-KeyAttestation
A c++ (jni) implementation of KeyAttestation for Android

## Disclaimer
- This code is NOT written by me, it is simply just translated by me. Credit for KeyAttestation goes to vvb2060
- I don't suggest using this code in any commercial software as it is not really stable and really only a POC.
- To pass this app you can simply use bootloader spoofer by chiteroman. This is not intended to be used as a root detection app.
- Don't expect much from this app as it is just a small project for me to see what's possible with the use of JavaNativeInterface.

## Features
- [x] Support for Android 14
- [x] Hardware-backed key generation and attestation
- [x] Native code implementation for improved security
- [x] Error handling and reporting

## Todo
- [ ] Check whether certificate is expired
- [ ] Maybe there is a way to do everything without JNI?
- [ ] Adapt more checks from regular KeyAttestation
- [ ] Remove some unnecessary error checks

## Build and Installation
Building this project requires the Android NDK and CMake: https://developer.android.com/studio/projects/install-ndk  
Follow these steps to compile and install the application on your device:

1. Clone the repository to your local machine.
2. Open the project in Android Studio with NDK and CMake installed.
3. Build the project using the "Build" menu.
4. Connect your Android device and ensure USB debugging is enabled.
5. Install the app onto your device using Android Studio's "Run" function.

## Known Problems
- Some devices may not support hardware-backed key attestation
- Crashes may happen if TEE is broken

## Credits
This project uses resources from following sources:
- Original KeyAttestation project by vvb2060: https://github.com/vvb2060/KeyAttestation
- Key Attestation sample by Google: https://developer.android.com/training/articles/security-key-attestation

Special thanks to vvb2060 and contributors of KeyAttestation for their resources and knowledge.
Contributions to this project are very welcome.

## Contact
For questions, suggestions, or contributions, please reach out through:
- Telegram Group: https://t.me/reveny1
- Telegram Contact: https://t.me/revenyy

## Screenshots
![preview](https://github.com/reveny/Android-Native-KeyAttestation/blob/main/images/preview.png)
