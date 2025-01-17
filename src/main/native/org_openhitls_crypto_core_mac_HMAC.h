/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_openhitls_crypto_HMAC */

#ifndef _Included_org_openhitls_crypto_HMAC
#define _Included_org_openhitls_crypto_HMAC
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     org_openhitls_crypto_HMAC
 * Method:    nativeInit
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_org_openhitls_crypto_HMAC_nativeInit
  (JNIEnv *, jobject, jint, jbyteArray);

/*
 * Class:     org_openhitls_crypto_HMAC
 * Method:    nativeUpdate
 * Signature: ([BII)V
 */
JNIEXPORT void JNICALL Java_org_openhitls_crypto_HMAC_nativeUpdate
  (JNIEnv *, jobject, jbyteArray, jint, jint);

/*
 * Class:     org_openhitls_crypto_HMAC
 * Method:    nativeDoFinal
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_HMAC_nativeDoFinal
  (JNIEnv *, jobject);

/*
 * Class:     org_openhitls_crypto_HMAC
 * Method:    nativeReinit
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_openhitls_crypto_HMAC_nativeReinit
  (JNIEnv *, jobject);

/*
 * Class:     org_openhitls_crypto_HMAC
 * Method:    nativeGetMacLength
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_openhitls_crypto_HMAC_nativeGetMacLength
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif 