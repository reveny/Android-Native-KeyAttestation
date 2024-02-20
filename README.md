# Android-Native-KeyAttestation
A c++ (jni) implementation of KeyAttestation for Android

## Features
- [x] Support for Android API levels 21 through 33
- [x] Hardware-backed key generation and attestation
- [x] Native code implementation for improved security
- [x] Error handling and reporting

## Build and Installation
Building this project requires the Android NDK and CMake: https://developer.android.com/studio/projects/install-ndk  
Follow these steps to compile and install the application on your device:

1. Clone the repository to your local machine.
2. Open the project in Android Studio with NDK and CMake installed.
3. Build the project using the "Build" menu.
4. Connect your Android device and ensure USB debugging is enabled.
5. Install the app onto your device using Android Studio's "Run" function.

## Known Problems
- Some devices may not support hardware-backed key attestation if TEE is broken.

## Credits
This project uses resources from following sources:
- Original KeyAttestation project by vvb2060: https://github.com/vvb2060/KeyAttestation
- Key Attestation sample by Google: https://developer.android.com/training/articles/security-key-attestation
- Android NDK documentation by Google: https://developer.android.com/ndk

Special thanks to vvb2060 and contributors of KeyAttestation for their valuable resources and knowledge.

## Contact
For questions, suggestions, or contributions, please reach out through:
- Telegram Group: https://t.me/reveny1
- Telegram Contact: https://t.me/revenyy

## Screenshots
