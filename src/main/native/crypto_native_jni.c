#include <jni.h>
#include "org_openhitls_crypto_core_CryptoNative.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <crypto/crypt_errno.h>
#include <crypto/crypt_algid.h>
#include <crypto/crypt_eal_provider.h>
#include <crypto/crypt_eal_codecs.h>
#include <crypto/crypt_eal_pkey.h>
#include <crypto/crypt_eal_cipher.h>
#include <crypto/crypt_eal_mac.h>
#include <crypto/crypt_eal_md.h>
#include <crypto/crypt_eal_rand.h>
#include <crypto/crypt_params_key.h>
#include <bsl/bsl_sal.h>
#include <bsl/bsl_err.h>
#include <pthread.h>


// Exception type constants
static const char* INVALID_KEY_EXCEPTION = "java/security/InvalidKeyException";
static const char* INVALID_ALGORITHM_PARAMETER_EXCEPTION = "java/security/InvalidAlgorithmParameterException";
static const char* NO_SUCH_ALGORITHM_EXCEPTION = "java/security/NoSuchAlgorithmException";
static const char* ILLEGAL_STATE_EXCEPTION = "java/lang/IllegalStateException";
static const char* ILLEGAL_ARGUMENT_EXCEPTION = "java/lang/IllegalArgumentException";
static const char* SIGNATURE_EXCEPTION = "java/security/SignatureException";
static const char* OUT_OF_MEMORY_ERROR = "java/lang/OutOfMemoryError";

static void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

static void secureZeroFree(void *ptr, size_t len) {
    if (ptr != NULL) {
        memset(ptr, 0, len);
        free(ptr);
    }
}

static void throwException(JNIEnv *env, const char *exceptionClass, const char *message) {
    jclass cls = (*env)->FindClass(env, exceptionClass);
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, message);
    }
    (*env)->DeleteLocalRef(env, cls);
}

static void throwExceptionWithError(JNIEnv *env, const char *exceptionClass, const char *message, int32_t errorCode) {
    char errorMsg[256];
    snprintf(errorMsg, sizeof(errorMsg), "%s (error code: %d)", message, errorCode);
    jclass cls = (*env)->FindClass(env, exceptionClass);
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, errorMsg);
    }
    (*env)->DeleteLocalRef(env, cls);
}

static jbyteArray newByteArrayFromData(JNIEnv *env, const uint8_t *data, uint32_t dataLen) {
    if (dataLen > INT32_MAX) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Native buffer too large for Java byte array");
        return NULL;
    }

    jbyteArray array = (*env)->NewByteArray(env, (jsize)dataLen);
    if (array == NULL) {
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate Java byte array");
        return NULL;
    }
    if (dataLen != 0) {
        (*env)->SetByteArrayRegion(env, array, 0, (jsize)dataLen, (const jbyte *)data);
    }
    return array;
}

static jobjectArray newByteArrayObjectArray(JNIEnv *env, jsize length) {
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    if (byteArrayClass == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to find byte array class");
        return NULL;
    }

    jobjectArray array = (*env)->NewObjectArray(env, length, byteArrayClass, NULL);
    (*env)->DeleteLocalRef(env, byteArrayClass);
    if (array == NULL) {
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate byte array result");
    }
    return array;
}

typedef struct {
    jbyteArray array;
    jbyte *bytes;
    uint32_t len;
} JByteArrayRef;

static bool getByteArrayRef(JNIEnv *env, jbyteArray array, JByteArrayRef *ref, const char *message, bool required) {
    ref->array = array;
    ref->bytes = NULL;
    ref->len = 0;

    if (array == NULL) {
        if (required) {
            throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, message);
            return false;
        }
        return true;
    }

    ref->bytes = (*env)->GetByteArrayElements(env, array, NULL);
    if (ref->bytes == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, message);
        return false;
    }
    ref->len = (uint32_t)(*env)->GetArrayLength(env, array);
    return true;
}

static uint8_t *copyByteArrayWithTerminator(JNIEnv *env, jbyteArray array, uint32_t *len, const char *message) {
    if (array == NULL || len == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, message);
        return NULL;
    }

    jsize arrayLen = (*env)->GetArrayLength(env, array);
    uint8_t *buffer = malloc((size_t)arrayLen + 1);
    if (buffer == NULL) {
        throwException(env, OUT_OF_MEMORY_ERROR, message);
        return NULL;
    }

    if (arrayLen > 0) {
        (*env)->GetByteArrayRegion(env, array, 0, arrayLen, (jbyte *)buffer);
        if ((*env)->ExceptionCheck(env)) {
            secureZeroFree(buffer, (size_t)arrayLen + 1);
            return NULL;
        }
    }
    buffer[arrayLen] = '\0';
    *len = (uint32_t)arrayLen;
    return buffer;
}

static void releaseByteArrayRef(JNIEnv *env, JByteArrayRef *ref) {
    if (ref->array != NULL && ref->bytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, ref->array, ref->bytes, JNI_ABORT);
    }
    ref->array = NULL;
    ref->bytes = NULL;
    ref->len = 0;
}

static void deleteLocalByteArrays(JNIEnv *env, jbyteArray *arrays, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (arrays[i] != NULL) {
            (*env)->DeleteLocalRef(env, arrays[i]);
            arrays[i] = NULL;
        }
    }
}

static bool allByteArraysCreated(jbyteArray *arrays, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (arrays[i] == NULL) {
            return false;
        }
    }
    return true;
}

static bool isZeroComponent(const uint8_t *data, uint32_t dataLen) {
    if (data == NULL || dataLen == 0) {
        return true;
    }
    for (uint32_t i = 0; i < dataLen; i++) {
        if (data[i] != 0) {
            return false;
        }
    }
    return true;
}

static void freeRsaPrivateKeyBuffers(CRYPT_EAL_PkeyPrv *privKey, uint32_t allocLen) {
    free(privKey->key.rsaPrv.n);
    secureZeroFree(privKey->key.rsaPrv.d, allocLen);
    secureZeroFree(privKey->key.rsaPrv.e, allocLen);
    secureZeroFree(privKey->key.rsaPrv.p, allocLen);
    secureZeroFree(privKey->key.rsaPrv.q, allocLen);
    secureZeroFree(privKey->key.rsaPrv.dP, allocLen);
    secureZeroFree(privKey->key.rsaPrv.dQ, allocLen);
    secureZeroFree(privKey->key.rsaPrv.qInv, allocLen);
}

// Static initialization flag
static volatile int32_t g_initialized = 0;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static void bslInit() {
    BSL_ERR_Init();
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
}

static void randInit() {
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
}

// Initialize BSL and random number generator
static void initializeCrypto() {
    if (g_initialized) return;

    pthread_mutex_lock(&g_init_mutex);
    if (!g_initialized) {
        // Initialize BSL
        static BSL_SAL_OnceControl bslOnceControl = BSL_SAL_ONCE_INIT;
        BSL_SAL_ThreadRunOnce(&bslOnceControl, bslInit);

        // Initialize random number generator
        static BSL_SAL_OnceControl randOnceControl = BSL_SAL_ONCE_INIT;
        BSL_SAL_ThreadRunOnce(&randOnceControl, randInit);

        // Test random number generation
        uint8_t testBuf[32];
        int ret = CRYPT_EAL_Randbytes(testBuf, sizeof(testBuf));
        if (ret != CRYPT_SUCCESS) {
            // Log error but don't throw exception here
            fprintf(stderr, "Warning: Failed to initialize random number generator: %d\n", ret);
        }

        g_initialized = 1;
    }
    pthread_mutex_unlock(&g_init_mutex);
}

// JNI_OnLoad - called when the native library is loaded
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    // Initialize crypto when the library is loaded
    initializeCrypto();
    return JNI_VERSION_1_8;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestInit
  (JNIEnv *env, jclass cls, jstring jalgorithm) {
    const char *algorithm = (*env)->GetStringUTFChars(env, jalgorithm, NULL);
    if (algorithm == NULL) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Failed to get algorithm string");
        return 0;
    }

    int mdId;
    if (strcasecmp(algorithm, "SHA-1") == 0) {
        mdId = CRYPT_MD_SHA1;
    } else if (strcasecmp(algorithm, "SHA-224") == 0) {
        mdId = CRYPT_MD_SHA224;
    } else if (strcasecmp(algorithm, "SHA-256") == 0) {
        mdId = CRYPT_MD_SHA256;
    } else if (strcasecmp(algorithm, "SHA-384") == 0) {
        mdId = CRYPT_MD_SHA384;
    } else if (strcasecmp(algorithm, "SHA-512") == 0) {
        mdId = CRYPT_MD_SHA512;
    } else if (strcasecmp(algorithm, "SHA3-224") == 0) {
        mdId = CRYPT_MD_SHA3_224;
    } else if (strcasecmp(algorithm, "SHA3-256") == 0) {
        mdId = CRYPT_MD_SHA3_256;
    } else if (strcasecmp(algorithm, "SHA3-384") == 0) {
        mdId = CRYPT_MD_SHA3_384;
    } else if (strcasecmp(algorithm, "SHA3-512") == 0) {
        mdId = CRYPT_MD_SHA3_512;
    } else if (strcasecmp(algorithm, "SM3") == 0) {
        mdId = CRYPT_MD_SM3;
    } else {
        (*env)->ReleaseStringUTFChars(env, jalgorithm, algorithm);
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported hash algorithm");
        return 0;
    }
    (*env)->ReleaseStringUTFChars(env, jalgorithm, algorithm);

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(mdId);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create message digest context");
        return 0;
    }

    int ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to initialize message digest", ret);
        return 0;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestUpdate
  (JNIEnv *env, jobject obj, jlong contextPtr, jbyteArray data, jint offset, jint length) {
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid context");
        return;
    }

    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get byte array elements");
        return;
    }

    int result = CRYPT_EAL_MdUpdate(ctx, (unsigned char *)(bytes + offset), length);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    
    if (result != CRYPT_SUCCESS) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to update message digest");
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestFinal
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid context");
        return NULL;
    }
    
    CRYPT_MD_AlgId algoId = CRYPT_EAL_MdGetId(ctx);
    uint32_t digestLen = CRYPT_EAL_MdGetDigestSize(algoId);
    unsigned char hash[128];  // Large enough for any hash
    uint32_t outLen = digestLen;
    
    if (CRYPT_EAL_MdFinal(ctx, hash, &outLen) != CRYPT_SUCCESS) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to finalize message digest");
        return NULL;
    }
    
    jbyteArray result = (*env)->NewByteArray(env, digestLen);
    if (result == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, result, 0, digestLen, (jbyte *)hash);
    return result;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}

// Get algorithm ID from algorithm name
static int getHmacAlgorithmId(const char *algorithm) {
    if (strcmp(algorithm, "HMACSHA1") == 0) {
        return CRYPT_MAC_HMAC_SHA1;
    } else if (strcmp(algorithm, "HMACSHA224") == 0) {
        return CRYPT_MAC_HMAC_SHA224;
    } else if (strcmp(algorithm, "HMACSHA256") == 0) {
        return CRYPT_MAC_HMAC_SHA256;
    } else if (strcmp(algorithm, "HMACSHA384") == 0) {
        return CRYPT_MAC_HMAC_SHA384;
    } else if (strcmp(algorithm, "HMACSHA512") == 0) {
        return CRYPT_MAC_HMAC_SHA512;
    } else if (strcmp(algorithm, "HMACSHA3-224") == 0) {
        return CRYPT_MAC_HMAC_SHA3_224;
    } else if (strcmp(algorithm, "HMACSHA3-256") == 0) {
        return CRYPT_MAC_HMAC_SHA3_256;
    } else if (strcmp(algorithm, "HMACSHA3-384") == 0) {
        return CRYPT_MAC_HMAC_SHA3_384;
    } else if (strcmp(algorithm, "HMACSHA3-512") == 0) {
        return CRYPT_MAC_HMAC_SHA3_512;
    } else if (strcmp(algorithm, "HMACSM3") == 0) {
        return CRYPT_MAC_HMAC_SM3;
    }
    return -1;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacInit
  (JNIEnv *env, jobject obj, jstring jalgorithm, jbyteArray key) {
    // Convert Java string to C string
    const char *algorithm = (*env)->GetStringUTFChars(env, jalgorithm, NULL);
    if (algorithm == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get algorithm string");
        return 0;
    }

    // Get algorithm ID
    int algorithmId = getHmacAlgorithmId(algorithm);
    (*env)->ReleaseStringUTFChars(env, jalgorithm, algorithm);

    if (algorithmId == -1) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Unsupported HMAC algorithm");
        return 0;
    }

    // Verify algorithm is supported
    if (!CRYPT_EAL_MacIsValidAlgId(algorithmId)) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid HMAC algorithm");
        return 0;
    }
    
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algorithmId);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create HMAC context");
        return 0;
    }

    jbyte *keyBytes = NULL;
    jsize keyLen = 0;
    
    if (key != NULL) {
        keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
        if (keyBytes == NULL) {
            CRYPT_EAL_MacFreeCtx(ctx);
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get key bytes");
            return 0;
        }
        keyLen = (*env)->GetArrayLength(env, key);
    }
    
    int result = CRYPT_EAL_MacInit(ctx, (uint8_t *)keyBytes, keyLen);
    if (result != CRYPT_SUCCESS) {
        if (keyBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        }
        CRYPT_EAL_MacFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to initialize HMAC");
        return 0;
    }

    if (keyBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    }
    
    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacUpdate
  (JNIEnv *env, jobject obj, jlong contextPtr, jbyteArray data, jint offset, jint length) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "HMAC context is null");
        return;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get data bytes");
        return;
    }

    int result = CRYPT_EAL_MacUpdate(ctx, (uint8_t *)dataBytes + offset, length);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (result != CRYPT_SUCCESS) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to update HMAC");
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacFinal
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "HMAC context is null");
        return NULL;
    }

    uint32_t macLength = CRYPT_EAL_GetMacLen(ctx);
    if (macLength == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get MAC length");
        return NULL;
    }

    uint8_t *mac = malloc(macLength);
    if (mac == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for MAC");
        return NULL;
    }

    uint32_t outLen = macLength;
    int result = CRYPT_EAL_MacFinal(ctx, mac, &outLen);
    if (result != CRYPT_SUCCESS) {
        free(mac);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to finalize HMAC");
        return NULL;
    }

    jbyteArray macArray = (*env)->NewByteArray(env, outLen);
    if (macArray == NULL) {
        free(mac);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create Java byte array");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, macArray, 0, outLen, (jbyte *)mac);
    memset(mac, 0, outLen);
    free(mac);

    return macArray;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacReinit
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "HMAC context is null");
        return;
    }

    int result = CRYPT_EAL_MacReinit(ctx);
    if (result != CRYPT_SUCCESS) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to reinitialize HMAC");
    }
}

JNIEXPORT jint JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacGetMacLength
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "HMAC context is null");
        return 0;
    }

    return CRYPT_EAL_GetMacLen(ctx);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_MacFreeCtx((CRYPT_EAL_MacCtx *)contextPtr);
    }
}

// Update curve IDs to match OpenHiTLS
static int getEcCurveId(const char *curveName) {
    if (strcmp(curveName, "sm2p256v1") == 0) {
        return CRYPT_ECC_SM2;  // Use correct constant
    } else if (strcmp(curveName, "secp256r1") == 0 || 
               strcmp(curveName, "prime256v1") == 0 || 
               strcmp(curveName, "p-256") == 0) {
        return CRYPT_ECC_NISTP256;  // Use correct constant
    } else if (strcmp(curveName, "secp384r1") == 0 || 
               strcmp(curveName, "p-384") == 0) {
        return CRYPT_ECC_NISTP384;  // Use correct constant
    } else if (strcmp(curveName, "secp521r1") == 0 || 
               strcmp(curveName, "p-521") == 0) {
        return CRYPT_ECC_NISTP521;  // Use correct constant
    }
    return -1;
}

// Map Java hash algorithm constants to OpenHiTLS MD IDs
static int getMdId(int hashAlg) {
    switch (hashAlg) {
        case 1:  // HASH_ALG_SM3
            return CRYPT_MD_SM3;
        case 2:  // HASH_ALG_SHA1
            return CRYPT_MD_SHA1;
        case 3:  // HASH_ALG_SHA224
            return CRYPT_MD_SHA224;
        case 4:  // HASH_ALG_SHA256
            return CRYPT_MD_SHA256;
        case 5:  // HASH_ALG_SHA384
            return CRYPT_MD_SHA384;
        case 6:  // HASH_ALG_SHA512
            return CRYPT_MD_SHA512;
        case 7:  // HASH_ALG_SHAKE128
            return CRYPT_MD_SHAKE128;
        case 8:  // HASH_ALG_SHAKE256
            return CRYPT_MD_SHAKE256;
        default:
            return CRYPT_MD_SHA256; // Default to SHA256
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaCreateContext
  (JNIEnv *env, jclass cls, jstring jcurveName) {
    if (jcurveName == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Curve name cannot be null");
        return 0;
    }
    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
    if (curveName == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get curve name string");
        return 0;
    }
    int curveId = getEcCurveId(curveName);
    (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);

    if (curveId == -1) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported curve");
        return 0;
    }

    // Create context based on curve type
    CRYPT_EAL_PkeyCtx *pkey;
    int ret;
    if (curveId == CRYPT_ECC_SM2) {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
        if (pkey == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create context");
            return 0;
        }
        
        // No need to set curve parameters for SM2 as it's fixed to sm2p256v1
        
        // Set the default user ID for SM2
        const char *defaultUserId = "1234567812345678";
        ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SM2_USER_ID, (void *)defaultUserId, strlen(defaultUserId));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set default user ID", ret);
            return 0;
        }
    } else {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
        if (pkey == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create context");
            return 0;
        }
        
        // For ECDSA, we need to set the curve ID
        ret = CRYPT_EAL_PkeySetParaById(pkey, curveId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set curve parameters", ret);
            return 0;
        }
    }
    return (jlong)pkey;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaSetKeys
  (JNIEnv *env, jobject obj, jlong nativeRef, jstring jcurveName, jbyteArray publicKey, jbyteArray privateKey) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
    int keyType = strcmp(curveName, "sm2p256v1") == 0 ? CRYPT_PKEY_SM2 : CRYPT_PKEY_ECDSA;
    (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);

    if (publicKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = keyType;
        jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
        pubKey.key.eccPub.data = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
        pubKey.key.eccPub.len = pubKeyLen;

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
        (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)pubKey.key.eccPub.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set public key", ret);
            return;
        }
    }

    if (privateKey != NULL) {
        CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = keyType;
        jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
        privKey.key.eccPrv.data = (uint8_t *)(*env)->GetByteArrayElements(env, privateKey, NULL);
        privKey.key.eccPrv.len = privKeyLen;

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privKey.key.eccPrv.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set private key", ret);
            return;
        }
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaSetUserId
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray userId) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (userId != NULL) {
        jsize userIdLen = (*env)->GetArrayLength(env, userId);
        const unsigned char *userIdData = (const unsigned char *)(*env)->GetByteArrayElements(env, userId, NULL);
        
        if (userIdData != NULL) {
            ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SM2_USER_ID, (void *)userIdData, userIdLen);
            (*env)->ReleaseByteArrayElements(env, userId, (jbyte *)userIdData, JNI_ABORT);
            
            if (ret != CRYPT_SUCCESS) {
                throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set SM2 user ID", ret);
                return;
            }
        }
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef, jstring jcurveName) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
    int curveId = getEcCurveId(curveName);
    int keyType = (curveId == CRYPT_ECC_SM2) ? CRYPT_PKEY_SM2 : CRYPT_PKEY_ECDSA;

    // Get key sizes based on curve
    int privKeySize;
    int pubKeySize;
    switch (curveId) {
        case CRYPT_ECC_SM2:
        case CRYPT_ECC_NISTP256:
            privKeySize = 32;  // 256 bits
            pubKeySize = 65;   // 0x04 + 32 bytes X + 32 bytes Y
            break;
        case CRYPT_ECC_NISTP384:
            privKeySize = 48;  // 384 bits
            pubKeySize = 97;   // 0x04 + 48 bytes X + 48 bytes Y
            break;
        case CRYPT_ECC_NISTP521:
            privKeySize = 66;  // 521 bits
            pubKeySize = 133;   // 0x04 + 66 bytes X + 66 bytes Y
            break;
        default:
            (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);
            throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported curve");
            return NULL;
    }
    (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);

    // Generate key pair
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate key pair", ret);
        return NULL;
    }

    // Get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = keyType;
    pubKey.key.eccPub.data = malloc(pubKeySize);
    pubKey.key.eccPub.len = pubKeySize;
    if (pubKey.key.eccPub.data == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for public key");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.eccPub.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get public key", ret);
        return NULL;
    }

    // Get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = keyType;
    privKey.key.eccPrv.data = malloc(privKeySize);
    privKey.key.eccPrv.len = privKeySize;
    if (privKey.key.eccPrv.data == NULL) {
        free(pubKey.key.eccPub.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for private key");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyGetPrv(pkey, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.eccPub.data);
        secureZeroFree(privKey.key.eccPrv.data, privKey.key.eccPrv.len);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.eccPub.len);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.eccPrv.len);
    if (pubKeyArray == NULL || privKeyArray == NULL) {
        free(pubKey.key.eccPub.data);
        secureZeroFree(privKey.key.eccPrv.data, privKey.key.eccPrv.len);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create key arrays");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.eccPub.len, (jbyte *)pubKey.key.eccPub.data);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.eccPrv.len, (jbyte *)privKey.key.eccPrv.data);

    // Create array of byte arrays to return both keys
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, pubKeyArray), NULL);
    if (result == NULL) {
        free(pubKey.key.eccPub.data);
        secureZeroFree(privKey.key.eccPrv.data, privKey.key.eccPrv.len);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, pubKeyArray);
    (*env)->SetObjectArrayElement(env, result, 1, privKeyArray);

    free(pubKey.key.eccPub.data);
    secureZeroFree(privKey.key.eccPrv.data, privKey.key.eccPrv.len);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaEncrypt
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    jbyteArray result = NULL;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    uint8_t *outBuf = malloc(inputLen + 256);
    uint32_t outLen = inputLen + 256;
    if (outBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for output buffer");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyEncrypt(pkey, (uint8_t *)inputData, inputLen, outBuf, &outLen);
    if (ret != CRYPT_SUCCESS) {
        free(outBuf);
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to encrypt data", ret);
        return NULL;
    }

    result = (*env)->NewByteArray(env, outLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, outLen, (jbyte *)outBuf);
    }

    free(outBuf);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaDecrypt
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray encryptedData) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    jbyteArray result = NULL;

    jbyte *inputData = (*env)->GetByteArrayElements(env, encryptedData, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, encryptedData);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    uint8_t *decryptedData = malloc(inputLen);
    uint32_t decryptedLen = inputLen;
    if (decryptedData == NULL) {
        (*env)->ReleaseByteArrayElements(env, encryptedData, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for decrypted data");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyDecrypt(pkey, (uint8_t *)inputData, inputLen, decryptedData, &decryptedLen);
    if (ret != CRYPT_SUCCESS) {
        free(decryptedData);
        (*env)->ReleaseByteArrayElements(env, encryptedData, inputData, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to decrypt data", ret);
        return NULL;
    }

    result = (*env)->NewByteArray(env, decryptedLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, decryptedLen, (jbyte *)decryptedData);
    }

    free(decryptedData);
    (*env)->ReleaseByteArrayElements(env, encryptedData, inputData, JNI_ABORT);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaSign
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    jbyteArray result = NULL;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    uint8_t *signBuf = malloc(256);
    uint32_t signLen = 256;
    if (signBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for signature");
        return NULL;
    }

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeySign(pkey, mdId, (uint8_t *)inputData, inputLen, signBuf, &signLen);
    if (ret != CRYPT_SUCCESS) {
        free(signBuf);
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to sign data", ret);
        return NULL;
    }

    result = (*env)->NewByteArray(env, signLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, signLen, (jbyte *)signBuf);
    }

    free(signBuf);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return result;
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaVerify
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data, jbyteArray signature, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return JNI_FALSE;
    }

    jbyte *signData = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize signLen = (*env)->GetArrayLength(env, signature);
    if (signData == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get signature data");
        return JNI_FALSE;
    }

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeyVerify(pkey, mdId, (uint8_t *)inputData, inputLen, (uint8_t *)signData, signLen);

    (*env)->ReleaseByteArrayElements(env, signature, signData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return (ret == CRYPT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static CRYPT_CIPHER_AlgId getSM4ModeId(JNIEnv *env, jstring mode) {
    CRYPT_CIPHER_AlgId algId = (CRYPT_CIPHER_AlgId)0;
    const char* modeStr = (*env)->GetStringUTFChars(env, mode, NULL);
    if (modeStr == NULL) {
        return algId;
    }
    if (strcmp(modeStr, "ECB") == 0) {
        algId = BSL_CID_SM4_ECB;
    } else if (strcmp(modeStr, "CBC") == 0) {
        algId = BSL_CID_SM4_CBC;           
    } else if (strcmp(modeStr, "CTR") == 0) {
        algId = BSL_CID_SM4_CTR; 
    } else if (strcmp(modeStr, "GCM") == 0) {
        algId = BSL_CID_SM4_GCM;
    } else if (strcmp(modeStr, "CFB") == 0) {
        algId = BSL_CID_SM4_CFB;
    } else if (strcmp(modeStr, "OFB") == 0) {
        algId = BSL_CID_SM4_OFB;
    } else if (strcmp(modeStr, "XTS") == 0) {
        algId = BSL_CID_SM4_XTS;
    }

    (*env)->ReleaseStringUTFChars(env, mode, modeStr);
    return algId;
}

static CRYPT_CIPHER_AlgId getAesModeId(JNIEnv *env, jstring mode, jint keySize) {
    CRYPT_CIPHER_AlgId algId = (CRYPT_CIPHER_AlgId)0;
    const char* modeStr = (*env)->GetStringUTFChars(env, mode, NULL);
    if (modeStr == NULL) {
        return algId;
    }

    if (strcmp(modeStr, "ECB") == 0) {
        switch (keySize) {
            case 128:
                algId = CRYPT_CIPHER_AES128_ECB;
                break;
            case 192:
                algId = CRYPT_CIPHER_AES192_ECB;
                break;
            case 256:
                algId = CRYPT_CIPHER_AES256_ECB;
                break;
        }
    } else if (strcmp(modeStr, "CBC") == 0) {
        switch (keySize) {
            case 128:
                algId = CRYPT_CIPHER_AES128_CBC;
                break;
            case 192:
                algId = CRYPT_CIPHER_AES192_CBC;
                break;
            case 256:
                algId = CRYPT_CIPHER_AES256_CBC;
                break;
        }
    } else if (strcmp(modeStr, "CTR") == 0) {
        switch (keySize) {
            case 128:
                algId = CRYPT_CIPHER_AES128_CTR;
                break;
            case 192:
                algId = CRYPT_CIPHER_AES192_CTR;
                break;
            case 256:
                algId = CRYPT_CIPHER_AES256_CTR;
                break;
        }
    } else if (strcmp(modeStr, "GCM") == 0) {
        switch (keySize) {
            case 128:
                algId = CRYPT_CIPHER_AES128_GCM;
                break;
            case 192:
                algId = CRYPT_CIPHER_AES192_GCM;
                break;
            case 256:
                algId = CRYPT_CIPHER_AES256_GCM;
                break;
        }
    } else if (strcmp(modeStr, "CFB") == 0) {
        switch (keySize) {
            case 128:
                algId = CRYPT_CIPHER_AES128_CFB;
                break;
            case 192:
                algId = CRYPT_CIPHER_AES192_CFB;
                break;
            case 256:
                algId = CRYPT_CIPHER_AES256_CFB;
                break;
        }
    } else if (strcmp(modeStr, "OFB") == 0) {
        switch (keySize) {
            case 128:
                algId = CRYPT_CIPHER_AES128_OFB;
                break;
            case 192:
                algId = CRYPT_CIPHER_AES192_OFB;
                break;
            case 256:
                algId = CRYPT_CIPHER_AES256_OFB;
                break;
        }
    }

    (*env)->ReleaseStringUTFChars(env, mode, modeStr);
    return algId;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherInit
  (JNIEnv *env, jclass cls, jstring algorithm, jstring cipherMode, jbyteArray key, jbyteArray iv, jint mode) {
    CRYPT_CIPHER_AlgId algId = 0;
    const char* algoStr = (*env)->GetStringUTFChars(env, algorithm, NULL);
    if (strcmp(algoStr, "AES") == 0) {
        // Get key size in bits
        jsize keyLen = (*env)->GetArrayLength(env, key);
        jint keySize = keyLen * 8;  // Convert bytes to bits
        algId = getAesModeId(env, cipherMode, keySize);
        if (algId == (CRYPT_CIPHER_AlgId)0) {
            (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
            throwException(env, INVALID_ALGORITHM_PARAMETER_EXCEPTION, "Invalid AES mode or key size");
            return 0;
        }
    } else if (strcmp(algoStr, "SM4") == 0) {
        algId = getSM4ModeId(env, cipherMode);
        if (algId == (CRYPT_CIPHER_AlgId)0) {
            (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
            throwException(env, INVALID_ALGORITHM_PARAMETER_EXCEPTION, "Invalid SM4 mode.");
            return 0;
        }
    } else {
        (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Invalid algorithm");
        return 0;
    }
    (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create cipher context");
        return 0;
    }
    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get key bytes");
        return 0;
    }

    jbyte *ivBytes = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        if (ivBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            CRYPT_EAL_CipherFreeCtx(ctx);
            throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get IV bytes");
            return 0;
        }
        ivLen = (*env)->GetArrayLength(env, iv);
    }

    jsize keyLen = (*env)->GetArrayLength(env, key);

    int result = CRYPT_EAL_CipherInit(ctx,
                                (const uint8_t *)keyBytes,
                                (uint32_t)keyLen,
                                ivBytes != NULL ? (const uint8_t *)ivBytes : NULL,
                                (uint32_t)ivLen,
                                mode == 1);

    if (result != CRYPT_SUCCESS) {
        if (ivBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        CRYPT_EAL_CipherFreeCtx(ctx);
        throwException(env, INVALID_KEY_EXCEPTION, "Failed to initialize cipher");
        return 0;
    }

    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherSetPadding
  (JNIEnv *env, jobject obj, jlong nativeRef, jint paddingType) {
    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Symmetric cipher context is null");
        return;
    }

    int result = CRYPT_EAL_CipherSetPadding(ctx, paddingType);
    if (result != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set padding", result);
        return;
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)contextPtr;
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherUpdate
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jintArray outLen) {
    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Symmetric cipher context is null");
        return;
    }

    jbyte *inputBytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (inputBytes == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input bytes");
        return;
    }

    jbyte *outputBytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (outputBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get output bytes");
        return;
    }

    jint *outLenPtr = (*env)->GetIntArrayElements(env, outLen, NULL);
    if (outLenPtr == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get outLen array");
        return;
    }

    uint32_t actualOutLen = inputLen + 16; // Allow for padding
    int result = CRYPT_EAL_CipherUpdate(ctx,
                                       (uint8_t *)(inputBytes + inputOffset),
                                       inputLen,
                                       (uint8_t *)(outputBytes + outputOffset),
                                       &actualOutLen);

    *outLenPtr = actualOutLen;
    (*env)->ReleaseIntArrayElements(env, outLen, outLenPtr, 0);
    (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

    if (result != CRYPT_SUCCESS) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to encrypt data");
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherFinal
  (JNIEnv *env, jobject obj, jlong nativeRef) {
    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Symmetric cipher context is null");
        return NULL;
    }

    uint32_t outLen = 32; // Allow for up to 2 blocks of padding
    uint8_t *outBuf = malloc(outLen);
    if (outBuf == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for final block");
        return NULL;
    }

    int result = CRYPT_EAL_CipherFinal(ctx, outBuf, &outLen);
    if (result != CRYPT_SUCCESS) {
        free(outBuf);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to finalize encryption");
        return NULL;
    }

    jbyteArray finalBlock = NULL;
    if (outLen > 0) {
        finalBlock = (*env)->NewByteArray(env, outLen);
        if (finalBlock == NULL) {
            free(outBuf);
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create final block array");
            return NULL;
        }
        (*env)->SetByteArrayRegion(env, finalBlock, 0, outLen, (jbyte *)outBuf);
    }
    free(outBuf);
    return finalBlock;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaCreateContext
  (JNIEnv *env, jclass cls) {
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DSA);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create DSA context");
        return 0;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaSetParameters
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray p, jbyteArray q, jbyteArray g) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return;
    }

    // Get parameter bytes
    jbyte *pBytes = (*env)->GetByteArrayElements(env, p, NULL);
    jbyte *qBytes = (*env)->GetByteArrayElements(env, q, NULL);
    jbyte *gBytes = (*env)->GetByteArrayElements(env, g, NULL);
    
    if (pBytes == NULL || qBytes == NULL || gBytes == NULL) {
        if (pBytes) (*env)->ReleaseByteArrayElements(env, p, pBytes, JNI_ABORT);
        if (qBytes) (*env)->ReleaseByteArrayElements(env, q, qBytes, JNI_ABORT);
        if (gBytes) (*env)->ReleaseByteArrayElements(env, g, gBytes, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get parameter bytes");
        return;
    }

    jsize pLen = (*env)->GetArrayLength(env, p);
    jsize qLen = (*env)->GetArrayLength(env, q);
    jsize gLen = (*env)->GetArrayLength(env, g);

    // Set up DSA parameters
    CRYPT_EAL_PkeyPara para;
    memset(&para, 0, sizeof(CRYPT_EAL_PkeyPara));
    para.id = CRYPT_PKEY_DSA;
    para.para.dsaPara.p = (uint8_t *)pBytes;
    para.para.dsaPara.pLen = pLen;
    para.para.dsaPara.q = (uint8_t *)qBytes;
    para.para.dsaPara.qLen = qLen;
    para.para.dsaPara.g = (uint8_t *)gBytes;
    para.para.dsaPara.gLen = gLen;

    // Set parameters in context
    int ret = CRYPT_EAL_PkeySetPara(ctx, &para);

    // Release byte arrays
    (*env)->ReleaseByteArrayElements(env, p, pBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, q, qBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, g, gBytes, JNI_ABORT);

    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set DSA parameters", ret);
        return;
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return NULL;
    }

    // Generate key pair
    int ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate DSA key pair", ret);
        return NULL;
    }

    // Get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = CRYPT_PKEY_DSA;
    pubKey.key.dsaPub.data = malloc(128); // 1024 bits
    pubKey.key.dsaPub.len = 128;

    ret = CRYPT_EAL_PkeyGetPub(ctx, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.dsaPub.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get DSA public key", ret);
        return NULL;
    }

    // Get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = CRYPT_PKEY_DSA;
    privKey.key.dsaPrv.data = malloc(20); // 160 bits
    privKey.key.dsaPrv.len = 20;

    ret = CRYPT_EAL_PkeyGetPrv(ctx, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.dsaPub.data);
        secureZeroFree(privKey.key.dsaPrv.data, privKey.key.dsaPrv.len);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get DSA private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.dsaPub.len);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.dsaPrv.len);
    
    if (pubKeyArray == NULL || privKeyArray == NULL) {
        free(pubKey.key.dsaPub.data);
        secureZeroFree(privKey.key.dsaPrv.data, privKey.key.dsaPrv.len);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create key arrays");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.dsaPub.len, (jbyte *)pubKey.key.dsaPub.data);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.dsaPrv.len, (jbyte *)privKey.key.dsaPrv.data);

    // Create array of byte arrays to return both keys
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, pubKeyArray), NULL);
    if (result == NULL) {
        free(pubKey.key.dsaPub.data);
        secureZeroFree(privKey.key.dsaPrv.data, privKey.key.dsaPrv.len);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, pubKeyArray);
    (*env)->SetObjectArrayElement(env, result, 1, privKeyArray);

    free(pubKey.key.dsaPub.data);
    secureZeroFree(privKey.key.dsaPrv.data, privKey.key.dsaPrv.len);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaSign
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return NULL;
    }

    // Get input data
    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    // Allocate buffer for signature
    uint8_t *signBuf = malloc(256); // Large enough for DSA signature
    uint32_t signLen = 256;
    if (signBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for signature");
        return NULL;
    }

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    int ret = CRYPT_EAL_PkeySign(ctx, mdId, (uint8_t *)inputData, inputLen, signBuf, &signLen);
    
    // Release input data
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    if (ret != CRYPT_SUCCESS) {
        free(signBuf);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to sign data", ret);
        return NULL;
    }

    // Create result byte array
    jbyteArray result = (*env)->NewByteArray(env, signLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, signLen, (jbyte *)signBuf);
    }

    free(signBuf);
    return result;
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaVerify
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return JNI_FALSE;
    }

    // Get input data
    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return JNI_FALSE;
    }

    // Get signature data
    jbyte *signData = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize signLen = (*env)->GetArrayLength(env, signature);
    if (signData == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get signature data");
        return JNI_FALSE;
    }

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    int ret = CRYPT_EAL_PkeyVerify(ctx, mdId, (uint8_t *)inputData, inputLen, (uint8_t *)signData, signLen);

    // Release arrays
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, signData, JNI_ABORT);

    return (ret == CRYPT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaSetKeys
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey, jbyteArray privateKey) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return;
    }

    if (publicKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_DSA;
        jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
        pubKey.key.dsaPub.data = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
        pubKey.key.dsaPub.len = pubKeyLen;

        int ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
        (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)pubKey.key.dsaPub.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set public key", ret);
            return;
        }
    }

    if (privateKey != NULL) {
        CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_DSA;
        jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
        privKey.key.dsaPrv.data = (uint8_t *)(*env)->GetByteArrayElements(env, privateKey, NULL);
        privKey.key.dsaPrv.len = privKeyLen;

        int ret = CRYPT_EAL_PkeySetPrv(ctx, &privKey);
        (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privKey.key.dsaPrv.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set private key", ret);
            return;
        }
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaCreateContext
  (JNIEnv *env, jclass cls) {
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create RSA context");
        return 0;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaSetParameters
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray e, jint keyBits) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");
        return;
    }

    jbyte *eBytes = (*env)->GetByteArrayElements(env, e, NULL);
    if (eBytes == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get exponent bytes");
        return;
    }
    jsize eLen = (*env)->GetArrayLength(env, e);

    // Validate key size (1024-16384 bits)
    if (keyBits < 1024 || keyBits > 16384 || (keyBits % 8) != 0) {
        (*env)->ReleaseByteArrayElements(env, e, eBytes, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Invalid RSA key size");
        return;
    }

    CRYPT_EAL_PkeyPara param;
    memset(&param, 0, sizeof(CRYPT_EAL_PkeyPara));
    param.id = CRYPT_PKEY_RSA;
    param.para.rsaPara.e = (uint8_t *)eBytes;
    param.para.rsaPara.eLen = eLen;
    param.para.rsaPara.bits = keyBits;

    int ret = CRYPT_EAL_PkeySetPara(ctx, &param);
    (*env)->ReleaseByteArrayElements(env, e, eBytes, JNI_ABORT);

    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA parameters", ret);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaSetKeys
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey, jbyteArray privateKey, jbyteArray publicExponent) {
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");
        return;
    }

    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    uint8_t *eBytes = NULL;
    jsize eLen = 0;
    bool releaseExponent = false;

    if ((publicKey != NULL || privateKey != NULL)
            && (publicExponent == NULL || (*env)->GetArrayLength(env, publicExponent) == 0)) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "RSA public exponent is required");
        return;
    }

    if (publicExponent != NULL && (*env)->GetArrayLength(env, publicExponent) > 0) {
        eLen = (*env)->GetArrayLength(env, publicExponent);
        eBytes = (uint8_t *)(*env)->GetByteArrayElements(env, publicExponent, NULL);
        if (eBytes == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get public exponent bytes");
            return;
        }
        releaseExponent = true;
    }

    // Set the public key if provided
    if (publicKey != NULL) {
        CRYPT_EAL_PkeyPub pub;
        memset(&pub, 0, sizeof(CRYPT_EAL_PkeyPub));
        pub.id = CRYPT_PKEY_RSA;
        jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
        pub.key.rsaPub.n = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
        if (pub.key.rsaPub.n == NULL) {
            if (releaseExponent) {
                (*env)->ReleaseByteArrayElements(env, publicExponent, (jbyte *)eBytes, JNI_ABORT);
            }
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get public key bytes");
            return;
        }
        pub.key.rsaPub.nLen = pubKeyLen;
        pub.key.rsaPub.e = eBytes;
        pub.key.rsaPub.eLen = eLen;

        int ret = CRYPT_EAL_PkeySetPub(ctx, &pub);
        (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)pub.key.rsaPub.n, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            if (releaseExponent) {
                (*env)->ReleaseByteArrayElements(env, publicExponent, (jbyte *)eBytes, JNI_ABORT);
            }
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA public key", ret);
            return;
        }
    }

    // Set the private key if provided
    if (privateKey != NULL) {
        CRYPT_EAL_PkeyPrv prv;
        memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
        prv.id = CRYPT_PKEY_RSA;

        // Get private key bytes
        jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
        prv.key.rsaPrv.d = (uint8_t *)(*env)->GetByteArrayElements(env, privateKey, NULL);
        if (prv.key.rsaPrv.d == NULL) {
            if (releaseExponent) {
                (*env)->ReleaseByteArrayElements(env, publicExponent, (jbyte *)eBytes, JNI_ABORT);
            }
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get private key bytes");
            return;
        }
        prv.key.rsaPrv.dLen = privKeyLen;
        prv.key.rsaPrv.e = eBytes;
        prv.key.rsaPrv.eLen = eLen;

        // Get modulus from public key if available
        if (publicKey != NULL) {
            jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
            prv.key.rsaPrv.n = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
            if (prv.key.rsaPrv.n == NULL) {
                (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)prv.key.rsaPrv.d, JNI_ABORT);
                if (releaseExponent) {
                    (*env)->ReleaseByteArrayElements(env, publicExponent, (jbyte *)eBytes, JNI_ABORT);
                }
                throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get modulus bytes");
                return;
            }
            prv.key.rsaPrv.nLen = pubKeyLen;
        }

        int ret = CRYPT_EAL_PkeySetPrv(ctx, &prv);

        // Release allocated memory
        if (publicKey != NULL) {
            (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)prv.key.rsaPrv.n, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)prv.key.rsaPrv.d, JNI_ABORT);

        if (ret != CRYPT_SUCCESS) {
            if (releaseExponent) {
                (*env)->ReleaseByteArrayElements(env, publicExponent, (jbyte *)eBytes, JNI_ABORT);
            }
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA private key", ret);
            return;
        }
    }

    if (releaseExponent) {
        (*env)->ReleaseByteArrayElements(env, publicExponent, (jbyte *)eBytes, JNI_ABORT);
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");
        return NULL;
    }

    // Generate key pair
    int ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate RSA key pair", ret);
        return NULL;
    }

    // Get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = CRYPT_PKEY_RSA;
    uint32_t keyBytes = CRYPT_EAL_PkeyGetKeyLen(ctx); // Get actual key size in bytes
    if (keyBytes == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get key size");
        return NULL;
    }
    pubKey.key.rsaPub.n = malloc(keyBytes);
    pubKey.key.rsaPub.e = malloc(8);   // Large enough for public exponent
    if (pubKey.key.rsaPub.n == NULL || pubKey.key.rsaPub.e == NULL) {
        if (pubKey.key.rsaPub.n) free(pubKey.key.rsaPub.n);
        if (pubKey.key.rsaPub.e) free(pubKey.key.rsaPub.e);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for public key");
        return NULL;
    }
    pubKey.key.rsaPub.nLen = keyBytes;
    pubKey.key.rsaPub.eLen = 8;

    ret = CRYPT_EAL_PkeyGetPub(ctx, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.rsaPub.n);
        free(pubKey.key.rsaPub.e);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get RSA public key", ret);
        return NULL;
    }

    // Get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = CRYPT_PKEY_RSA;
    privKey.key.rsaPrv.d = malloc(keyBytes);    // Same size as modulus
    privKey.key.rsaPrv.n = malloc(keyBytes);    // Same size as modulus
    privKey.key.rsaPrv.e = malloc(keyBytes);
    privKey.key.rsaPrv.p = malloc(keyBytes);
    privKey.key.rsaPrv.q = malloc(keyBytes);
    privKey.key.rsaPrv.dP = malloc(keyBytes);
    privKey.key.rsaPrv.dQ = malloc(keyBytes);
    privKey.key.rsaPrv.qInv = malloc(keyBytes);
    if (privKey.key.rsaPrv.d == NULL || privKey.key.rsaPrv.n == NULL || privKey.key.rsaPrv.e == NULL ||
            privKey.key.rsaPrv.p == NULL || privKey.key.rsaPrv.q == NULL || privKey.key.rsaPrv.dP == NULL ||
            privKey.key.rsaPrv.dQ == NULL || privKey.key.rsaPrv.qInv == NULL) {
        free(pubKey.key.rsaPub.n);
        free(pubKey.key.rsaPub.e);
        if (privKey.key.rsaPrv.d) free(privKey.key.rsaPrv.d);
        if (privKey.key.rsaPrv.n) free(privKey.key.rsaPrv.n);
        if (privKey.key.rsaPrv.e) free(privKey.key.rsaPrv.e);
        if (privKey.key.rsaPrv.p) free(privKey.key.rsaPrv.p);
        if (privKey.key.rsaPrv.q) free(privKey.key.rsaPrv.q);
        if (privKey.key.rsaPrv.dP) free(privKey.key.rsaPrv.dP);
        if (privKey.key.rsaPrv.dQ) free(privKey.key.rsaPrv.dQ);
        if (privKey.key.rsaPrv.qInv) free(privKey.key.rsaPrv.qInv);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for private key");
        return NULL;
    }
    privKey.key.rsaPrv.dLen = keyBytes;
    privKey.key.rsaPrv.nLen = keyBytes;
    privKey.key.rsaPrv.eLen = keyBytes;
    privKey.key.rsaPrv.pLen = keyBytes;
    privKey.key.rsaPrv.qLen = keyBytes;
    privKey.key.rsaPrv.dPLen = keyBytes;
    privKey.key.rsaPrv.dQLen = keyBytes;
    privKey.key.rsaPrv.qInvLen = keyBytes;

    ret = CRYPT_EAL_PkeyGetPrv(ctx, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.rsaPub.n);
        free(pubKey.key.rsaPub.e);
        secureZeroFree(privKey.key.rsaPrv.d, privKey.key.rsaPrv.dLen);
        secureZeroFree(privKey.key.rsaPrv.n, privKey.key.rsaPrv.nLen);
        secureZeroFree(privKey.key.rsaPrv.e, privKey.key.rsaPrv.eLen);
        secureZeroFree(privKey.key.rsaPrv.p, privKey.key.rsaPrv.pLen);
        secureZeroFree(privKey.key.rsaPrv.q, privKey.key.rsaPrv.qLen);
        secureZeroFree(privKey.key.rsaPrv.dP, privKey.key.rsaPrv.dPLen);
        secureZeroFree(privKey.key.rsaPrv.dQ, privKey.key.rsaPrv.dQLen);
        secureZeroFree(privKey.key.rsaPrv.qInv, privKey.key.rsaPrv.qInvLen);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get RSA private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.rsaPub.nLen);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.rsaPrv.dLen);
    jbyteArray publicExponentArray = (*env)->NewByteArray(env, privKey.key.rsaPrv.eLen);
    jbyteArray primePArray = (*env)->NewByteArray(env, privKey.key.rsaPrv.pLen);
    jbyteArray primeQArray = (*env)->NewByteArray(env, privKey.key.rsaPrv.qLen);
    jbyteArray primeExponentPArray = (*env)->NewByteArray(env, privKey.key.rsaPrv.dPLen);
    jbyteArray primeExponentQArray = (*env)->NewByteArray(env, privKey.key.rsaPrv.dQLen);
    jbyteArray crtCoefficientArray = (*env)->NewByteArray(env, privKey.key.rsaPrv.qInvLen);
    if (pubKeyArray == NULL || privKeyArray == NULL || publicExponentArray == NULL ||
            primePArray == NULL || primeQArray == NULL || primeExponentPArray == NULL ||
            primeExponentQArray == NULL || crtCoefficientArray == NULL) {
        free(pubKey.key.rsaPub.n);
        free(pubKey.key.rsaPub.e);
        secureZeroFree(privKey.key.rsaPrv.d, privKey.key.rsaPrv.dLen);
        secureZeroFree(privKey.key.rsaPrv.n, privKey.key.rsaPrv.nLen);
        secureZeroFree(privKey.key.rsaPrv.e, privKey.key.rsaPrv.eLen);
        secureZeroFree(privKey.key.rsaPrv.p, privKey.key.rsaPrv.pLen);
        secureZeroFree(privKey.key.rsaPrv.q, privKey.key.rsaPrv.qLen);
        secureZeroFree(privKey.key.rsaPrv.dP, privKey.key.rsaPrv.dPLen);
        secureZeroFree(privKey.key.rsaPrv.dQ, privKey.key.rsaPrv.dQLen);
        secureZeroFree(privKey.key.rsaPrv.qInv, privKey.key.rsaPrv.qInvLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create key arrays");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.rsaPub.nLen, (jbyte *)pubKey.key.rsaPub.n);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.rsaPrv.dLen, (jbyte *)privKey.key.rsaPrv.d);
    (*env)->SetByteArrayRegion(env, publicExponentArray, 0, privKey.key.rsaPrv.eLen, (jbyte *)privKey.key.rsaPrv.e);
    (*env)->SetByteArrayRegion(env, primePArray, 0, privKey.key.rsaPrv.pLen, (jbyte *)privKey.key.rsaPrv.p);
    (*env)->SetByteArrayRegion(env, primeQArray, 0, privKey.key.rsaPrv.qLen, (jbyte *)privKey.key.rsaPrv.q);
    (*env)->SetByteArrayRegion(env, primeExponentPArray, 0, privKey.key.rsaPrv.dPLen, (jbyte *)privKey.key.rsaPrv.dP);
    (*env)->SetByteArrayRegion(env, primeExponentQArray, 0, privKey.key.rsaPrv.dQLen, (jbyte *)privKey.key.rsaPrv.dQ);
    (*env)->SetByteArrayRegion(env, crtCoefficientArray, 0, privKey.key.rsaPrv.qInvLen, (jbyte *)privKey.key.rsaPrv.qInv);

    // Create array of byte arrays to return both keys
    jobjectArray result = (*env)->NewObjectArray(env, 8, (*env)->GetObjectClass(env, pubKeyArray), NULL);
    if (result == NULL) {
        free(pubKey.key.rsaPub.n);
        free(pubKey.key.rsaPub.e);
        secureZeroFree(privKey.key.rsaPrv.d, privKey.key.rsaPrv.dLen);
        secureZeroFree(privKey.key.rsaPrv.n, privKey.key.rsaPrv.nLen);
        secureZeroFree(privKey.key.rsaPrv.e, privKey.key.rsaPrv.eLen);
        secureZeroFree(privKey.key.rsaPrv.p, privKey.key.rsaPrv.pLen);
        secureZeroFree(privKey.key.rsaPrv.q, privKey.key.rsaPrv.qLen);
        secureZeroFree(privKey.key.rsaPrv.dP, privKey.key.rsaPrv.dPLen);
        secureZeroFree(privKey.key.rsaPrv.dQ, privKey.key.rsaPrv.dQLen);
        secureZeroFree(privKey.key.rsaPrv.qInv, privKey.key.rsaPrv.qInvLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, pubKeyArray);
    (*env)->SetObjectArrayElement(env, result, 1, privKeyArray);
    (*env)->SetObjectArrayElement(env, result, 2, publicExponentArray);
    (*env)->SetObjectArrayElement(env, result, 3, primePArray);
    (*env)->SetObjectArrayElement(env, result, 4, primeQArray);
    (*env)->SetObjectArrayElement(env, result, 5, primeExponentPArray);
    (*env)->SetObjectArrayElement(env, result, 6, primeExponentQArray);
    (*env)->SetObjectArrayElement(env, result, 7, crtCoefficientArray);

    free(pubKey.key.rsaPub.n);
    free(pubKey.key.rsaPub.e);
    secureZeroFree(privKey.key.rsaPrv.d, privKey.key.rsaPrv.dLen);
    secureZeroFree(privKey.key.rsaPrv.n, privKey.key.rsaPrv.nLen);
    secureZeroFree(privKey.key.rsaPrv.e, privKey.key.rsaPrv.eLen);
    secureZeroFree(privKey.key.rsaPrv.p, privKey.key.rsaPrv.pLen);
    secureZeroFree(privKey.key.rsaPrv.q, privKey.key.rsaPrv.qLen);
    secureZeroFree(privKey.key.rsaPrv.dP, privKey.key.rsaPrv.dPLen);
    secureZeroFree(privKey.key.rsaPrv.dQ, privKey.key.rsaPrv.dQLen);
    secureZeroFree(privKey.key.rsaPrv.qInv, privKey.key.rsaPrv.qInvLen);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaEncodePublicKey
  (JNIEnv *env, jclass cls, jbyteArray jmodulus, jbyteArray jpublicExponent) {
    if (jmodulus == NULL || jpublicExponent == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "RSA public key components cannot be null");
        return NULL;
    }

    jbyte *modulus = (*env)->GetByteArrayElements(env, jmodulus, NULL);
    if (modulus == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get RSA modulus bytes");
        return NULL;
    }
    jbyte *publicExponent = (*env)->GetByteArrayElements(env, jpublicExponent, NULL);
    if (publicExponent == NULL) {
        (*env)->ReleaseByteArrayElements(env, jmodulus, modulus, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get RSA public exponent bytes");
        return NULL;
    }

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (ctx == NULL) {
        (*env)->ReleaseByteArrayElements(env, jmodulus, modulus, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, jpublicExponent, publicExponent, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create RSA context");
        return NULL;
    }

    CRYPT_EAL_PkeyPub pub;
    memset(&pub, 0, sizeof(pub));
    pub.id = CRYPT_PKEY_RSA;
    pub.key.rsaPub.n = (uint8_t *)modulus;
    pub.key.rsaPub.nLen = (uint32_t)(*env)->GetArrayLength(env, jmodulus);
    pub.key.rsaPub.e = (uint8_t *)publicExponent;
    pub.key.rsaPub.eLen = (uint32_t)(*env)->GetArrayLength(env, jpublicExponent);

    int32_t ret = CRYPT_EAL_PkeySetPub(ctx, &pub);
    (*env)->ReleaseByteArrayElements(env, jmodulus, modulus, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jpublicExponent, publicExponent, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA public key", ret);
        return NULL;
    }

    BSL_Buffer encoded = {0};
    ret = CRYPT_EAL_EncodeBuffKey(ctx, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encoded);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to encode RSA public key", ret);
        return NULL;
    }

    jbyteArray result = newByteArrayFromData(env, encoded.data, encoded.dataLen);
    BSL_SAL_FREE(encoded.data);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaEncodePrivateKey
  (JNIEnv *env, jclass cls, jbyteArray jmodulus, jbyteArray jprivateExponent, jbyteArray jpublicExponent,
      jbyteArray jprimeP, jbyteArray jprimeQ, jbyteArray jprimeExponentP, jbyteArray jprimeExponentQ,
      jbyteArray jcrtCoefficient) {
    JByteArrayRef modulus = {0};
    JByteArrayRef privateExponent = {0};
    JByteArrayRef publicExponent = {0};
    JByteArrayRef primeP = {0};
    JByteArrayRef primeQ = {0};
    JByteArrayRef primeExponentP = {0};
    JByteArrayRef primeExponentQ = {0};
    JByteArrayRef crtCoefficient = {0};

    if (!getByteArrayRef(env, jmodulus, &modulus, "Failed to get RSA modulus bytes", true) ||
            !getByteArrayRef(env, jprivateExponent, &privateExponent, "Failed to get RSA private exponent bytes", true) ||
            !getByteArrayRef(env, jpublicExponent, &publicExponent, "Failed to get RSA public exponent bytes", false) ||
            !getByteArrayRef(env, jprimeP, &primeP, "Failed to get RSA primeP bytes", false) ||
            !getByteArrayRef(env, jprimeQ, &primeQ, "Failed to get RSA primeQ bytes", false) ||
            !getByteArrayRef(env, jprimeExponentP, &primeExponentP, "Failed to get RSA primeExponentP bytes", false) ||
            !getByteArrayRef(env, jprimeExponentQ, &primeExponentQ, "Failed to get RSA primeExponentQ bytes", false) ||
            !getByteArrayRef(env, jcrtCoefficient, &crtCoefficient, "Failed to get RSA crtCoefficient bytes", false)) {
        releaseByteArrayRef(env, &modulus);
        releaseByteArrayRef(env, &privateExponent);
        releaseByteArrayRef(env, &publicExponent);
        releaseByteArrayRef(env, &primeP);
        releaseByteArrayRef(env, &primeQ);
        releaseByteArrayRef(env, &primeExponentP);
        releaseByteArrayRef(env, &primeExponentQ);
        releaseByteArrayRef(env, &crtCoefficient);
        return NULL;
    }

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (ctx == NULL) {
        releaseByteArrayRef(env, &modulus);
        releaseByteArrayRef(env, &privateExponent);
        releaseByteArrayRef(env, &publicExponent);
        releaseByteArrayRef(env, &primeP);
        releaseByteArrayRef(env, &primeQ);
        releaseByteArrayRef(env, &primeExponentP);
        releaseByteArrayRef(env, &primeExponentQ);
        releaseByteArrayRef(env, &crtCoefficient);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create RSA context");
        return NULL;
    }

    CRYPT_EAL_PkeyPub pub;
    memset(&pub, 0, sizeof(pub));
    pub.id = CRYPT_PKEY_RSA;
    pub.key.rsaPub.n = (uint8_t *)modulus.bytes;
    pub.key.rsaPub.nLen = modulus.len;
    pub.key.rsaPub.e = (uint8_t *)publicExponent.bytes;
    pub.key.rsaPub.eLen = publicExponent.len;

    CRYPT_EAL_PkeyPrv prv;
    memset(&prv, 0, sizeof(prv));
    prv.id = CRYPT_PKEY_RSA;
    prv.key.rsaPrv.n = (uint8_t *)modulus.bytes;
    prv.key.rsaPrv.nLen = modulus.len;
    prv.key.rsaPrv.d = (uint8_t *)privateExponent.bytes;
    prv.key.rsaPrv.dLen = privateExponent.len;
    prv.key.rsaPrv.e = (uint8_t *)publicExponent.bytes;
    prv.key.rsaPrv.eLen = publicExponent.len;
    prv.key.rsaPrv.p = (uint8_t *)primeP.bytes;
    prv.key.rsaPrv.pLen = primeP.len;
    prv.key.rsaPrv.q = (uint8_t *)primeQ.bytes;
    prv.key.rsaPrv.qLen = primeQ.len;
    prv.key.rsaPrv.dP = (uint8_t *)primeExponentP.bytes;
    prv.key.rsaPrv.dPLen = primeExponentP.len;
    prv.key.rsaPrv.dQ = (uint8_t *)primeExponentQ.bytes;
    prv.key.rsaPrv.dQLen = primeExponentQ.len;
    prv.key.rsaPrv.qInv = (uint8_t *)crtCoefficient.bytes;
    prv.key.rsaPrv.qInvLen = crtCoefficient.len;

    int32_t ret = CRYPT_SUCCESS;
    if (publicExponent.bytes != NULL && publicExponent.len > 0) {
        ret = CRYPT_EAL_PkeySetPub(ctx, &pub);
    }
    if (ret == CRYPT_SUCCESS) {
        ret = CRYPT_EAL_PkeySetPrv(ctx, &prv);
    }

    releaseByteArrayRef(env, &modulus);
    releaseByteArrayRef(env, &privateExponent);
    releaseByteArrayRef(env, &publicExponent);
    releaseByteArrayRef(env, &primeP);
    releaseByteArrayRef(env, &primeQ);
    releaseByteArrayRef(env, &primeExponentP);
    releaseByteArrayRef(env, &primeExponentQ);
    releaseByteArrayRef(env, &crtCoefficient);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA private key", ret);
        return NULL;
    }

    BSL_Buffer encoded = {0};
    ret = CRYPT_EAL_EncodeBuffKey(ctx, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encoded);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to encode RSA private key", ret);
        return NULL;
    }

    jbyteArray result = newByteArrayFromData(env, encoded.data, encoded.dataLen);
    BSL_SAL_ClearFree(encoded.data, encoded.dataLen);
    return result;
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaDecodePublicKey
  (JNIEnv *env, jclass cls, jbyteArray jencodedKey) {
    if (jencodedKey == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Encoded RSA public key cannot be null");
        return NULL;
    }

    uint32_t encodedLen = 0;
    uint8_t *encodedBytes = copyByteArrayWithTerminator(env, jencodedKey, &encodedLen,
        "Failed to copy encoded RSA public key bytes");
    if (encodedBytes == NULL) {
        return NULL;
    }

    BSL_Buffer encoded = {encodedBytes, encodedLen};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_UNKNOWN, CRYPT_PUBKEY_SUBKEY, &encoded, NULL, 0, &ctx);
    free(encodedBytes);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to decode RSA public key", ret);
        return NULL;
    }
    if (CRYPT_EAL_PkeyGetId(ctx) != CRYPT_PKEY_RSA) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Decoded public key is not an RSA key");
        return NULL;
    }

    uint32_t keyBytes = CRYPT_EAL_PkeyGetKeyLen(ctx);
    if (keyBytes == 0) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get RSA public key size");
        return NULL;
    }

    CRYPT_EAL_PkeyPub pub;
    memset(&pub, 0, sizeof(pub));
    pub.id = CRYPT_PKEY_RSA;
    pub.key.rsaPub.n = malloc(keyBytes);
    pub.key.rsaPub.e = malloc(keyBytes);
    if (pub.key.rsaPub.n == NULL || pub.key.rsaPub.e == NULL) {
        free(pub.key.rsaPub.n);
        free(pub.key.rsaPub.e);
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate RSA public key buffers");
        return NULL;
    }
    pub.key.rsaPub.nLen = keyBytes;
    pub.key.rsaPub.eLen = keyBytes;

    ret = CRYPT_EAL_PkeyGetPub(ctx, &pub);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        free(pub.key.rsaPub.n);
        free(pub.key.rsaPub.e);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to extract RSA public key", ret);
        return NULL;
    }

    jobjectArray result = newByteArrayObjectArray(env, 2);
    if (result == NULL) {
        free(pub.key.rsaPub.n);
        free(pub.key.rsaPub.e);
        return NULL;
    }

    jbyteArray keyParts[2] = {
        newByteArrayFromData(env, pub.key.rsaPub.n, pub.key.rsaPub.nLen),
        newByteArrayFromData(env, pub.key.rsaPub.e, pub.key.rsaPub.eLen)
    };
    if (!allByteArraysCreated(keyParts, 2)) {
        deleteLocalByteArrays(env, keyParts, 2);
        free(pub.key.rsaPub.n);
        free(pub.key.rsaPub.e);
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, result, 0, keyParts[0]);
    (*env)->SetObjectArrayElement(env, result, 1, keyParts[1]);
    deleteLocalByteArrays(env, keyParts, 2);

    free(pub.key.rsaPub.n);
    free(pub.key.rsaPub.e);
    return result;
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaDecodePrivateKey
  (JNIEnv *env, jclass cls, jbyteArray jencodedKey) {
    if (jencodedKey == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Encoded RSA private key cannot be null");
        return NULL;
    }

    uint32_t encodedLen = 0;
    uint8_t *encodedBytes = copyByteArrayWithTerminator(env, jencodedKey, &encodedLen,
        "Failed to copy encoded RSA private key bytes");
    if (encodedBytes == NULL) {
        return NULL;
    }

    BSL_Buffer encoded = {encodedBytes, encodedLen};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_UNKNOWN, CRYPT_ENCDEC_UNKNOW, &encoded, NULL, 0, &ctx);
    secureZeroFree(encodedBytes, (size_t)encodedLen + 1);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to decode RSA private key", ret);
        return NULL;
    }
    if (CRYPT_EAL_PkeyGetId(ctx) != CRYPT_PKEY_RSA) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Decoded private key is not an RSA key");
        return NULL;
    }

    uint32_t keyBytes = CRYPT_EAL_PkeyGetKeyLen(ctx);
    if (keyBytes == 0) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get RSA private key size");
        return NULL;
    }

    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(privKey));
    privKey.id = CRYPT_PKEY_RSA;
    privKey.key.rsaPrv.n = calloc(1, keyBytes);
    privKey.key.rsaPrv.d = calloc(1, keyBytes);
    privKey.key.rsaPrv.e = calloc(1, keyBytes);
    privKey.key.rsaPrv.p = calloc(1, keyBytes);
    privKey.key.rsaPrv.q = calloc(1, keyBytes);
    privKey.key.rsaPrv.dP = calloc(1, keyBytes);
    privKey.key.rsaPrv.dQ = calloc(1, keyBytes);
    privKey.key.rsaPrv.qInv = calloc(1, keyBytes);
    if (privKey.key.rsaPrv.n == NULL || privKey.key.rsaPrv.d == NULL || privKey.key.rsaPrv.e == NULL ||
            privKey.key.rsaPrv.p == NULL || privKey.key.rsaPrv.q == NULL || privKey.key.rsaPrv.dP == NULL ||
            privKey.key.rsaPrv.dQ == NULL || privKey.key.rsaPrv.qInv == NULL) {
        free(privKey.key.rsaPrv.n);
        secureZeroFree(privKey.key.rsaPrv.d, keyBytes);
        secureZeroFree(privKey.key.rsaPrv.e, keyBytes);
        secureZeroFree(privKey.key.rsaPrv.p, keyBytes);
        secureZeroFree(privKey.key.rsaPrv.q, keyBytes);
        secureZeroFree(privKey.key.rsaPrv.dP, keyBytes);
        secureZeroFree(privKey.key.rsaPrv.dQ, keyBytes);
        secureZeroFree(privKey.key.rsaPrv.qInv, keyBytes);
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate RSA private key buffers");
        return NULL;
    }
    privKey.key.rsaPrv.nLen = keyBytes;
    privKey.key.rsaPrv.dLen = keyBytes;
    privKey.key.rsaPrv.eLen = keyBytes;
    privKey.key.rsaPrv.pLen = keyBytes;
    privKey.key.rsaPrv.qLen = keyBytes;
    privKey.key.rsaPrv.dPLen = keyBytes;
    privKey.key.rsaPrv.dQLen = keyBytes;
    privKey.key.rsaPrv.qInvLen = keyBytes;

    ret = CRYPT_EAL_PkeyGetPrv(ctx, &privKey);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        freeRsaPrivateKeyBuffers(&privKey, keyBytes);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to extract RSA private key", ret);
        return NULL;
    }

    if (isZeroComponent(privKey.key.rsaPrv.e, privKey.key.rsaPrv.eLen)) {
        freeRsaPrivateKeyBuffers(&privKey, keyBytes);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Decoded RSA private key does not contain public exponent");
        return NULL;
    }

    bool pIsZero = isZeroComponent(privKey.key.rsaPrv.p, privKey.key.rsaPrv.pLen);
    bool qIsZero = isZeroComponent(privKey.key.rsaPrv.q, privKey.key.rsaPrv.qLen);
    bool dPIsZero = isZeroComponent(privKey.key.rsaPrv.dP, privKey.key.rsaPrv.dPLen);
    bool dQIsZero = isZeroComponent(privKey.key.rsaPrv.dQ, privKey.key.rsaPrv.dQLen);
    bool qInvIsZero = isZeroComponent(privKey.key.rsaPrv.qInv, privKey.key.rsaPrv.qInvLen);
    bool hasCrt = !(pIsZero && qIsZero && dPIsZero && dQIsZero && qInvIsZero);
    bool hasCompleteCrt = !(pIsZero || qIsZero || dPIsZero || dQIsZero || qInvIsZero);
    if (hasCrt && !hasCompleteCrt) {
        freeRsaPrivateKeyBuffers(&privKey, keyBytes);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Decoded RSA private key contains incomplete CRT parameters");
        return NULL;
    }

    size_t partCount = hasCrt ? 8 : 3;
    jobjectArray result = newByteArrayObjectArray(env, (jsize)partCount);
    if (result == NULL) {
        freeRsaPrivateKeyBuffers(&privKey, keyBytes);
        return NULL;
    }

    const uint8_t *partData[8] = {
        privKey.key.rsaPrv.n, privKey.key.rsaPrv.d, privKey.key.rsaPrv.e,
        privKey.key.rsaPrv.p, privKey.key.rsaPrv.q, privKey.key.rsaPrv.dP,
        privKey.key.rsaPrv.dQ, privKey.key.rsaPrv.qInv
    };
    uint32_t partLens[8] = {
        privKey.key.rsaPrv.nLen, privKey.key.rsaPrv.dLen, privKey.key.rsaPrv.eLen,
        privKey.key.rsaPrv.pLen, privKey.key.rsaPrv.qLen, privKey.key.rsaPrv.dPLen,
        privKey.key.rsaPrv.dQLen, privKey.key.rsaPrv.qInvLen
    };
    jbyteArray keyParts[8] = {0};
    for (size_t i = 0; i < partCount; i++) {
        keyParts[i] = newByteArrayFromData(env, partData[i], partLens[i]);
    }
    if (!allByteArraysCreated(keyParts, partCount)) {
        deleteLocalByteArrays(env, keyParts, partCount);
        freeRsaPrivateKeyBuffers(&privKey, keyBytes);
        return NULL;
    }

    for (size_t i = 0; i < partCount; i++) {
        (*env)->SetObjectArrayElement(env, result, (jsize)i, keyParts[i]);
    }
    deleteLocalByteArrays(env, keyParts, partCount);

    freeRsaPrivateKeyBuffers(&privKey, keyBytes);
    return result;
}

static int getHashAlgorithmId(JNIEnv *env, const char* algorithm) {
    if (algorithm == NULL) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Algorithm name cannot be null");
        return -1;
    }

    // Handle SHA1/SHA-1 first as a special case
    if (strcmp(algorithm, "SHA1") == 0 || strcmp(algorithm, "SHA-1") == 0) {
        return CRYPT_MD_SHA1;
    }

    // Handle SM3 as a special case
    if (strcmp(algorithm, "SM3") == 0) {
        return CRYPT_MD_SM3;
    }

    // For SHA-2 family, extract the number part
    const char* hashNum = NULL;
    if (strncmp(algorithm, "SHA-", 4) == 0) {
        hashNum = algorithm + 4;
    } else if (strncmp(algorithm, "SHA", 3) == 0) {
        hashNum = algorithm + 3;
    }

    if (hashNum != NULL) {
        if (strcmp(hashNum, "224") == 0) {
            return CRYPT_MD_SHA224;
        } else if (strcmp(hashNum, "256") == 0) {
            return CRYPT_MD_SHA256;
        } else if (strcmp(hashNum, "384") == 0) {
            return CRYPT_MD_SHA384;
        } else if (strcmp(hashNum, "512") == 0) {
            return CRYPT_MD_SHA512;
        }
    }

    char errMsg[256];
    snprintf(errMsg, sizeof(errMsg), "Unsupported hash algorithm: %s", algorithm);
    throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, errMsg);
    return -1;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaSign
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jstring digestAlgorithm) {
    if (nativeRef == 0 || data == NULL || digestAlgorithm == NULL) {
        throwException(env, "java/lang/IllegalArgumentException", "Invalid arguments");
        return NULL;
    }

    // Get the hash algorithm ID
    const char *algorithm = (*env)->GetStringUTFChars(env, digestAlgorithm, NULL);
    if (algorithm == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get digest algorithm");
        return NULL;
    }
    int hashAlg = getHashAlgorithmId(env, algorithm);
    (*env)->ReleaseStringUTFChars(env, digestAlgorithm, algorithm);

    // Get data bytes
    jsize dataLen = (*env)->GetArrayLength(env, data);
    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get data bytes");
        return NULL;
    }

    // Set PKCS#1 v1.5 padding for RSA signing
    int32_t pkcsv15 = hashAlg;
    int ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15));
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA padding", ret);
        return NULL;
    }

    // Get signature length
    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen((CRYPT_EAL_PkeyCtx *)nativeRef);
    if (signLen == 0) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get signature length");
        return NULL;
    }

    // Allocate memory for signature
    uint8_t *signature = (uint8_t *)malloc(signLen);
    if (signature == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for signature");
        return NULL;
    }

    // Sign the data
    ret = CRYPT_EAL_PkeySign(
        (CRYPT_EAL_PkeyCtx *)nativeRef,
        hashAlg,
        (const uint8_t *)dataBytes,
        (uint32_t)dataLen,
        signature,
        &signLen
    );

    // Release data bytes
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (ret != CRYPT_SUCCESS) {
        free(signature);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to sign data", ret);
        return NULL;
    }

    // Create result byte array
    jbyteArray result = (*env)->NewByteArray(env, signLen);
    if (result == NULL) {
        free(signature);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    // Set signature bytes to result array
    (*env)->SetByteArrayRegion(env, result, 0, signLen, (jbyte *)signature);
    free(signature);

    return result;
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaVerify
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature, jstring digestAlgorithm) {
    if (nativeRef == 0 || data == NULL || signature == NULL || digestAlgorithm == NULL) {
        throwException(env, "java/lang/IllegalArgumentException", "Invalid arguments");
        return JNI_FALSE;
    }

    const char *algorithm = (*env)->GetStringUTFChars(env, digestAlgorithm, NULL);
    if (algorithm == NULL) {
        throwException(env, "java/lang/IllegalArgumentException", "Failed to get digest algorithm string");
        return JNI_FALSE;
    }

    int hashAlg = getHashAlgorithmId(env, algorithm);
    (*env)->ReleaseStringUTFChars(env, digestAlgorithm, algorithm);

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throwException(env, "java/lang/IllegalArgumentException", "Failed to get data bytes");
        return JNI_FALSE;
    }

    jbyte *signBytes = (*env)->GetByteArrayElements(env, signature, NULL);
    if (signBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throwException(env, "java/lang/IllegalArgumentException", "Failed to get signature bytes");
        return JNI_FALSE;
    }

    // Set PKCS#1 v1.5 padding for RSA signature verification
    int32_t pkcsv15 = hashAlg;
    int ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15));
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, signature, signBytes, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA padding", ret);
        return JNI_FALSE;
    }

    jsize dataLen = (*env)->GetArrayLength(env, data);
    jsize signLen = (*env)->GetArrayLength(env, signature);

    // Verify the signature
    ret = CRYPT_EAL_PkeyVerify((CRYPT_EAL_PkeyCtx *)nativeRef, hashAlg, (uint8_t *)dataBytes, dataLen,
                                      (uint8_t *)signBytes, signLen);

    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, signBytes, JNI_ABORT);

    // Handle normal verification failures without throwing exceptions
    if (ret == CRYPT_RSA_NOR_VERIFY_FAIL || 
        ret == CRYPT_RSA_ERR_PSS_SALT_DATA ||
        ret == CRYPT_RSA_ERR_INPUT_VALUE) {
        return JNI_FALSE;
    }

    // Only throw exceptions for other errors that indicate real problems
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, "java/security/SignatureException", "Failed to verify signature", ret);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherSetAAD
  (JNIEnv *env, jclass cls, jlong contextPtr, jbyteArray aad, jint offset, jint len)
{
    if (contextPtr == 0) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Invalid context pointer");
        return;
    }

    if (aad == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "AAD data cannot be null");
        return;
    }

    if (len <= 0) {
        return; // Nothing to do for zero or negative length
    }

    jbyte* aadBytes = (*env)->GetByteArrayElements(env, aad, NULL);
    if (aadBytes == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get AAD bytes");
        return;
    }
    
    // Cast to cipher context and set AAD using CRYPT_CTRL_SET_AAD
    CRYPT_EAL_CipherCtx* ctx = (CRYPT_EAL_CipherCtx*)contextPtr;
    int ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, 
                                 (void*)(aadBytes + offset), 
                                 (uint32_t)len);
    
    (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
    
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set AAD", ret);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherSetTagLen
  (JNIEnv *env, jclass cls, jlong contextPtr, jint tagLen)
{
    if (contextPtr == 0) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Invalid context pointer");
        return;
    }

    if (tagLen < 4 || tagLen > 16) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Tag length must be between 4 and 16 bytes");
        return;
    }

    uint32_t len = (uint32_t)tagLen;
    int ret = CRYPT_EAL_CipherCtrl((CRYPT_EAL_CipherCtx*)contextPtr, 
                                 CRYPT_CTRL_SET_TAGLEN, 
                                 &len, 
                                 sizeof(uint32_t));
    
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set tag length", ret);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherGetTag
  (JNIEnv *env, jclass cls, jlong contextPtr, jbyteArray tag, jint tagLen)
{
    if (contextPtr == 0) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Invalid context pointer");
        return;
    }

    if (tag == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Tag buffer cannot be null");
        return;
    }

    jsize tagArrayLen = (*env)->GetArrayLength(env, tag);
    if (tagLen < 4 || tagLen > 16 || tagLen > tagArrayLen) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Invalid tag length");
        return;
    }

    jbyte* tagBuf = (*env)->GetByteArrayElements(env, tag, NULL);
    if (tagBuf == NULL) {
        return; // Exception already thrown
    }
    
    // Use cipher context and control command to get the tag
    CRYPT_EAL_CipherCtx* ctx = (CRYPT_EAL_CipherCtx*)contextPtr;
    
    // Call with tag length directly as the last parameter
    int ret = CRYPT_EAL_CipherCtrl(ctx, 
                                 CRYPT_CTRL_GET_TAG, 
                                 (void*)tagBuf, 
                                 (uint32_t)tagLen);  // Pass tag length directly, not a pointer
    
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, tag, tagBuf, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get tag", ret);
        return;
    }
    
    (*env)->ReleaseByteArrayElements(env, tag, tagBuf, 0);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaSetPadding
  (JNIEnv *env, jclass cls, jlong nativeRef, jint paddingMode) {
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");
        return;
    }

    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (paddingMode == 0) {
        // No padding
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_PADDING, NULL, 0);
    } else {
        // PKCS1 padding
        int32_t pkcsv15 = CRYPT_MD_SHA256;
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15, sizeof(pkcsv15));
    }

    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA padding", ret);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaEncrypt	
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data) {	
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;	
    if (ctx == NULL) {	
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");	
        return NULL;	
    }	
    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);	
    if (dataBytes == NULL) {	
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get data bytes");	
        return NULL;	
    }	
    jsize dataLen = (*env)->GetArrayLength(env, data);	
    // Set PKCS#1 v1.5 padding for RSA encryption	
    int32_t pkcsv15 = CRYPT_MD_SHA256;	
    int ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15, sizeof(pkcsv15));	
    if (ret != CRYPT_SUCCESS) {	
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);	
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA padding", ret);	
        return NULL;	
    }	
    uint32_t outLen = CRYPT_EAL_PkeyGetKeyLen(ctx);	
    uint8_t *outBuf = malloc(outLen);	
    if (outBuf == NULL) {	
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);	
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for encrypted data");	
        return NULL;	
    }	
    ret = CRYPT_EAL_PkeyEncrypt(ctx, (uint8_t *)dataBytes, dataLen, outBuf, &outLen);	
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);	
    if (ret != CRYPT_SUCCESS) {	
        free(outBuf);	
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to encrypt data", ret);	
        return NULL;	
    }	
    jbyteArray result = (*env)->NewByteArray(env, outLen);	
    if (result != NULL) {	
        (*env)->SetByteArrayRegion(env, result, 0, outLen, (jbyte *)outBuf);
    }
    free(outBuf);
    return result;
}	
JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaDecrypt	
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray encryptedData) {	
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;	
    if (ctx == NULL) {	
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");	
        return NULL;	

    }	
    jbyte *dataBytes = (*env)->GetByteArrayElements(env, encryptedData, NULL);	



    if (dataBytes == NULL) {	
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get encrypted data bytes");	
        return NULL;	
    }	
    jsize dataLen = (*env)->GetArrayLength(env, encryptedData);	
    // Set PKCS#1 v1.5 padding for RSA decryption	
    int32_t pkcsv15 = CRYPT_MD_SHA256;	
    int ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15, sizeof(pkcsv15));	
    if (ret != CRYPT_SUCCESS) {	
        (*env)->ReleaseByteArrayElements(env, encryptedData, dataBytes, JNI_ABORT);	
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA padding", ret);	
        return NULL;	
    }	
    uint32_t outLen = CRYPT_EAL_PkeyGetKeyLen(ctx);	
    uint8_t *outBuf = malloc(outLen);	
    if (outBuf == NULL) {	
        (*env)->ReleaseByteArrayElements(env, encryptedData, dataBytes, JNI_ABORT);	
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for decrypted data");	
        return NULL;	
    }	
    ret = CRYPT_EAL_PkeyDecrypt(ctx, (uint8_t *)dataBytes, dataLen, outBuf, &outLen);	
    (*env)->ReleaseByteArrayElements(env, encryptedData, dataBytes, JNI_ABORT);	
    if (ret != CRYPT_SUCCESS) {	
        free(outBuf);	
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to decrypt data", ret);	
        return NULL;	
    }	
    jbyteArray result = (*env)->NewByteArray(env, outLen);	
    if (result != NULL) {	
        (*env)->SetByteArrayRegion(env, result, 0, outLen, (jbyte *)outBuf);	
    }	
    free(outBuf);	
    return result;	
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaSignPSS
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jstring digestAlgorithm,
   jstring mgf1Algorithm, jint saltLength, jint trailerField) {
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");
        return NULL;
    }

    if (data == NULL || digestAlgorithm == NULL || mgf1Algorithm == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Input parameters cannot be null");
        return NULL;
    }

    const char* digestAlgStr = (*env)->GetStringUTFChars(env, digestAlgorithm, NULL);
    const char* mgf1AlgStr = (*env)->GetStringUTFChars(env, mgf1Algorithm, NULL);
    jbyte* dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, data);

    if (digestAlgStr == NULL || mgf1AlgStr == NULL || dataBytes == NULL) {
        if (digestAlgStr) (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        if (mgf1AlgStr) (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        if (dataBytes) (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to get native resources");
        return NULL;
    }

    int hashAlg = getHashAlgorithmId(env, digestAlgStr);
    if (hashAlg == -1) {
        (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        // Exception already thrown by getHashAlgorithmId
        return NULL;
    }

    int mgf1HashAlg = getHashAlgorithmId(env, mgf1AlgStr);
    if (mgf1HashAlg == -1) {
        (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        // Exception already thrown by getHashAlgorithmId
        return NULL;
    }

    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashAlg, sizeof(hashAlg), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mgf1HashAlg, sizeof(mgf1HashAlg), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLength, sizeof(saltLength), 0},
        BSL_PARAM_END
    };

    int ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0);
    if (ret != CRYPT_SUCCESS) {
        char errMsg[256];
        snprintf(errMsg, sizeof(errMsg), "Failed to set PSS parameters (hash: %d, mgf1: %d, salt: %d)", 
                hashAlg, mgf1HashAlg, saltLength);
        (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, errMsg, ret);
        return NULL;
    }

    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen((CRYPT_EAL_PkeyCtx *)nativeRef);
    uint8_t *signature = (uint8_t *)malloc(signLen);
    if (signature == NULL) {
        (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate memory for signature");
        return NULL;
    }

    ret = CRYPT_EAL_PkeySign((CRYPT_EAL_PkeyCtx *)nativeRef, hashAlg, (uint8_t *)dataBytes, dataLen, signature, &signLen);

    (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
    (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (ret != CRYPT_SUCCESS) {
        free(signature);
        char errMsg[256];
        snprintf(errMsg, sizeof(errMsg), "Failed to sign data (hash: %d, mgf1: %d, salt: %d, data_len: %d)", 
                hashAlg, mgf1HashAlg, saltLength, (int)dataLen);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, errMsg, ret);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, signLen);
    if (result == NULL) {
        free(signature);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to create result array");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, signLen, (jbyte *)signature);
    free(signature);
    return result;
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaVerifyPSS
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature,
   jstring digestAlgorithm, jstring mgf1Algorithm, jint saltLength, jint trailerField) {
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");
        return JNI_FALSE;
    }

    if (data == NULL || signature == NULL || digestAlgorithm == NULL || mgf1Algorithm == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Input parameters cannot be null");
        return JNI_FALSE;
    }

    const char* digestAlgStr = (*env)->GetStringUTFChars(env, digestAlgorithm, NULL);
    const char* mgf1AlgStr = (*env)->GetStringUTFChars(env, mgf1Algorithm, NULL);
    jbyte* dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    jbyte* signBytes = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, data);
    jsize signLen = (*env)->GetArrayLength(env, signature);

    if (digestAlgStr == NULL || mgf1AlgStr == NULL || dataBytes == NULL || signBytes == NULL) {
        if (digestAlgStr) (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        if (mgf1AlgStr) (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        if (dataBytes) (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        if (signBytes) (*env)->ReleaseByteArrayElements(env, signature, signBytes, JNI_ABORT);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to get native resources");
        return JNI_FALSE;
    }

    int hashAlg = getHashAlgorithmId(env, digestAlgStr);
    if (hashAlg == -1) {
        (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, signature, signBytes, JNI_ABORT);
        // Exception already thrown by getHashAlgorithmId
        return JNI_FALSE;
    }

    int mgf1HashAlg = getHashAlgorithmId(env, mgf1AlgStr);
    if (mgf1HashAlg == -1) {
        (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, signature, signBytes, JNI_ABORT);
        // Exception already thrown by getHashAlgorithmId
        return JNI_FALSE;
    }

    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashAlg, sizeof(hashAlg), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mgf1HashAlg, sizeof(mgf1HashAlg), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLength, sizeof(saltLength), 0},
        BSL_PARAM_END
    };

    int ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0);
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, signature, signBytes, JNI_ABORT);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to set PSS parameters", ret);
        return JNI_FALSE;
    }

    ret = CRYPT_EAL_PkeyVerify((CRYPT_EAL_PkeyCtx *)nativeRef, hashAlg, (uint8_t *)dataBytes, dataLen,
                               (uint8_t *)signBytes, signLen);

    (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
    (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, signBytes, JNI_ABORT);

    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to verify signature", ret);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

static int getMlDsaParamId(const char *parameterSet) {
    if (strcmp(parameterSet, "ML-DSA-44") == 0) {
        return CRYPT_MLDSA_TYPE_MLDSA_44;
    } else if (strcmp(parameterSet, "ML-DSA-65") == 0) {
        return CRYPT_MLDSA_TYPE_MLDSA_65;
    } else if (strcmp(parameterSet, "ML-DSA-87") == 0) {
        return CRYPT_MLDSA_TYPE_MLDSA_87;
    } else {
        return -1;
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef, jstring jparameterSet) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    int privateKeySize;
    int publicKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    int paramId = getMlDsaParamId(parameterSet);
    switch(paramId) {
        case CRYPT_MLDSA_TYPE_MLDSA_44:
            privateKeySize = 2560;
            publicKeySize = 1312;
            break;
        case CRYPT_MLDSA_TYPE_MLDSA_65:
            privateKeySize = 4032;
            publicKeySize = 1952;
            break;
        case CRYPT_MLDSA_TYPE_MLDSA_87:
            privateKeySize = 4896;
            publicKeySize = 2592;
            break;
        default:
            (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
            throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported parameterSet");
            return NULL;
    }
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);

    // generate keyPair
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate key pair", ret);
        return NULL;
    }

    // get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = CRYPT_PKEY_ML_DSA;
    pubKey.key.mldsaPub.data = malloc(publicKeySize);
    pubKey.key.mldsaPub.len = publicKeySize;
    if (pubKey.key.mldsaPub.data == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for public key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.mldsaPub.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get public key", ret);
        return NULL;
    }

    // get private key
    CRYPT_EAL_PkeyPrv priKey;
    memset(&priKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    priKey.id = CRYPT_PKEY_ML_DSA;
    priKey.key.mldsaPrv.data = malloc(privateKeySize);
    priKey.key.mldsaPrv.len = privateKeySize;
    if (priKey.key.mldsaPrv.data == NULL) {
        free(pubKey.key.mldsaPub.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for public key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPrv(pkey, &priKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.mldsaPub.data);
        secureZeroFree(priKey.key.mldsaPrv.data, priKey.key.mldsaPrv.len);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.mldsaPub.len);
    jbyteArray priKeyArray = (*env)->NewByteArray(env, priKey.key.mldsaPrv.len);
    if (pubKeyArray == NULL || priKeyArray == NULL) {
        free(pubKey.key.mldsaPub.data);
        secureZeroFree(priKey.key.mldsaPrv.data, priKey.key.mldsaPrv.len);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create key arrays");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.mldsaPub.len, (jbyte *)pubKey.key.mldsaPub.data);
    (*env)->SetByteArrayRegion(env, priKeyArray, 0, priKey.key.mldsaPrv.len, (jbyte *)priKey.key.mldsaPrv.data);

    // create byte arrays for keyPair
    jobjectArray keyPair = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, pubKeyArray), NULL);
    if (keyPair == NULL) {
        free(pubKey.key.mldsaPub.data);
        secureZeroFree(priKey.key.mldsaPrv.data, priKey.key.mldsaPrv.len);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, keyPair, 0, pubKeyArray);
    (*env)->SetObjectArrayElement(env, keyPair, 1, priKeyArray);

    free(pubKey.key.mldsaPub.data);
    secureZeroFree(priKey.key.mldsaPrv.data, priKey.key.mldsaPrv.len);

    return keyPair;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaCreateContext
  (JNIEnv *env, jclass cls, jstring jparameterSet) {
    if (jparameterSet == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Parameter set cannot be null");
        return 0;
    }
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get parameter set string");
        return 0;
    }
    int paramId = getMlDsaParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported parameterSet");
        return 0;
    }

    // create context
    int ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    if (pkey == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create context");
        return 0;
    }

    // set parameterSet
    ret = CRYPT_EAL_PkeySetParaById(pkey, paramId);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set curve parameters", ret);
        return 0;
    }

    return (jlong)pkey;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaSetKeys
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey, jbyteArray privateKey) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (privateKey != NULL) {
        CRYPT_EAL_PkeyPrv priKey;
        memset(&priKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        priKey.id = CRYPT_PKEY_ML_DSA;
        jsize priKeyLen = (*env)->GetArrayLength(env, privateKey);
        priKey.key.mldsaPrv.data = (uint8_t *)(*env)->GetByteArrayElements(env, privateKey, NULL);
        priKey.key.mldsaPrv.len = priKeyLen;

        ret = CRYPT_EAL_PkeySetPrv(pkey, &priKey);
        (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)priKey.key.mldsaPrv.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set private key", ret);
            return;
        }
    }

    if (publicKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_ML_DSA;
        jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
        pubKey.key.mldsaPub.data = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
        pubKey.key.mldsaPub.len = pubKeyLen;

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
        (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)pubKey.key.mldsaPub.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set public key", ret);
            return;
        }
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaSign
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    uint32_t signLen;
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SIGNLEN, &signLen, sizeof(signLen));
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get signature length", ret);
        return NULL;
    }

    uint8_t *signBuf = malloc(signLen);
    if (signBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for signature");
        return NULL;
    }

    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeySign(pkey, mdId, (uint8_t *)inputData, inputLen, signBuf, &signLen);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        free(signBuf);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to sign data", ret);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, signLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, signLen, (jbyte *)signBuf);
    }

    free(signBuf);
    return result;
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaVerify
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    // get inputData for native methods
    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return JNI_FALSE;
    }

    // get signData for native methods
    jbyte *signData = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize signLen = (*env)->GetArrayLength(env, signature);
    if (signData == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get sign data");
        return JNI_FALSE;
    }

    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeyVerify(pkey, mdId, (uint8_t *)inputData, inputLen, (uint8_t *)signData, signLen);

    (*env)->ReleaseByteArrayElements(env, signature, signData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return (ret == CRYPT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaSetCxt
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray context) {
    if (context == NULL) {
        return;
    }

    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;

    // get context for native methods
    jbyte *data = (*env)->GetByteArrayElements(env, context, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, context);
    if (data == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get context data");
        return;
    }

    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_CTX_INFO, (uint8_t *)data, dataLen);
    (*env)->ReleaseByteArrayElements(env, context, data, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set MLDSA context", ret);
    }
    return;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaSetDeterministic
  (JNIEnv *env, jclass cls, jlong nativeRef, jboolean deterministic) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    uint32_t val = deterministic ? 1 : 0;
    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set MLDSA deterministic flag", ret);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaSetExternalMuFlag
  (JNIEnv *env, jclass cls, jlong nativeRef, jboolean externalMuFlag) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    uint32_t val = externalMuFlag ? 1 : 0;
    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_MLDSA_MUMSG_FLAG, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set MLDSA external mu flag", ret);
    }
    return;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mldsaSetPreHash
  (JNIEnv *env, jclass cls, jlong nativeRef, jboolean preHash) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    uint32_t val = preHash ? 1 : 0;
    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set MLDSA prehash flag", ret);
    }
    return;
}

static int getMlKemParamId(const char *parameterSet) {
    if (strcmp(parameterSet, "ML-KEM-512") == 0) {
        return CRYPT_KEM_TYPE_MLKEM_512;
    } else if (strcmp(parameterSet, "ML-KEM-768") == 0) {
        return CRYPT_KEM_TYPE_MLKEM_768;
    } else if (strcmp(parameterSet, "ML-KEM-1024") == 0) {
        return CRYPT_KEM_TYPE_MLKEM_1024;
    } else {
        return -1;
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_mlkemCreateContext
  (JNIEnv *env, jclass cls, jstring jparameterSet) {
    if (jparameterSet == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Parameter set cannot be null");
        return 0;
    }
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get parameter set string");
        return 0;
    }
    int paramId = getMlKemParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported MLKEM parameter set");
        return 0;
    }

    int ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
    if (pkey == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create MLKEM context");
        return 0;
    }

    ret = CRYPT_EAL_PkeySetParaById(pkey, paramId);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set MLKEM parameter set", ret);
        return 0;
    }

    return (jlong)pkey;
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_mlkemGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef, jstring jparameterSet) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    int publicKeySize;
    int privateKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    int paramId = getMlKemParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    switch (paramId) {
        case CRYPT_KEM_TYPE_MLKEM_512:
            publicKeySize = 800;
            privateKeySize = 1632;
            break;
        case CRYPT_KEM_TYPE_MLKEM_768:
            publicKeySize = 1184;
            privateKeySize = 2400;
            break;
        case CRYPT_KEM_TYPE_MLKEM_1024:
            publicKeySize = 1568;
            privateKeySize = 3168;
            break;
        default:
            throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported MLKEM parameter set");
            return NULL;
    }

    // generate keyPair
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate key pair", ret);
        return NULL;
    }

    // get public Key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = CRYPT_PKEY_ML_KEM;
    pubKey.key.kemEk.data = malloc(publicKeySize);
    pubKey.key.kemEk.len = publicKeySize;
    if (pubKey.key.kemEk.data == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for public key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.kemEk.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get public key", ret);
        return NULL;
    }

    // get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = CRYPT_PKEY_ML_KEM;
    privKey.key.kemDk.data = malloc(privateKeySize);
    privKey.key.kemDk.len = privateKeySize;
    if (privKey.key.kemDk.data == NULL) {
        free(pubKey.key.kemEk.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for private key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPrv(pkey, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.kemEk.data);
        secureZeroFree(privKey.key.kemDk.data, privKey.key.kemDk.len);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get private key", ret);
        return NULL;
    }

    // Create byte arrays for publicKey data and privateKey data
    jbyteArray publicKeyArray = (*env)->NewByteArray(env, pubKey.key.kemEk.len);
    jbyteArray privateKeyArray = (*env)->NewByteArray(env, privKey.key.kemDk.len);
    if (publicKeyArray == NULL || privateKeyArray == NULL) {
        free(pubKey.key.kemEk.data);
        secureZeroFree(privKey.key.kemDk.data, privKey.key.kemDk.len);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte arrays for public key or private key");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, publicKeyArray, 0, pubKey.key.kemEk.len, (jbyte *)pubKey.key.kemEk.data);
    (*env)->SetByteArrayRegion(env, privateKeyArray, 0, privKey.key.kemDk.len, (jbyte *)privKey.key.kemDk.data);

    free(pubKey.key.kemEk.data);
    secureZeroFree(privKey.key.kemDk.data, privKey.key.kemDk.len);

    // Create byte arrays for keyPair
    jobjectArray keyPair = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, publicKeyArray), NULL);
    if (keyPair == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte arrays for keyPair");
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, keyPair, 0, publicKeyArray);
    (*env)->SetObjectArrayElement(env, keyPair, 1, privateKeyArray);

    return keyPair;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mlkemSetKeys
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray jencapKey, jbyteArray jdecapKey) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (jencapKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_ML_KEM;
        pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
        pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
        (*env)->ReleaseByteArrayElements(env, jencapKey, (jbyte *)pubKey.key.kemEk.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set encapsulate key", ret);
            return;
        }
    }

    if (jdecapKey != NULL) {
        CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_ML_KEM;
        privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
        privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        (*env)->ReleaseByteArrayElements(env, jdecapKey, (jbyte *)privKey.key.kemDk.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set decapsulate key", ret);
            return;
        }
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mlkemFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_mlkemEncapsulate
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    // Get ciphertext and shared key lengths
    uint32_t ciphertextLen;
    uint32_t sharedKeyLen;
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ciphertextLen, sizeof(ciphertextLen));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get ciphertext length", ret);
        return NULL;
    }

    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedKeyLen, sizeof(sharedKeyLen));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get shared key length", ret);
        return NULL;
    }

    // Create ciphertext and shared key buffers
    uint8_t *ciphertext = malloc(ciphertextLen);
    uint8_t *sharedKey = malloc(sharedKeyLen);
    if (ciphertext == NULL || sharedKey == NULL) {
        if (ciphertext) free(ciphertext);
        if (sharedKey) free(sharedKey);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for encapsulation");
        return NULL;
    }

    // Encapsulation
    ret = CRYPT_EAL_PkeyEncaps(pkey, ciphertext, &ciphertextLen, sharedKey, &sharedKeyLen);
    if (ret != CRYPT_SUCCESS) {
        free(ciphertext);
        secureZeroFree(sharedKey, sharedKeyLen);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to encapsulate", ret);
        return NULL;
    }

    // Create byte arrays for ciphertext and sharedKey
    jbyteArray ciphertextArray = (*env)->NewByteArray(env, ciphertextLen);
    jbyteArray sharedKeyArray = (*env)->NewByteArray(env, sharedKeyLen);
    if (ciphertextArray == NULL || sharedKeyArray == NULL) {
        free(ciphertext);
        secureZeroFree(sharedKey, sharedKeyLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte arrays for encapsulation result");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, ciphertextArray, 0, ciphertextLen, (jbyte *)ciphertext);
    (*env)->SetByteArrayRegion(env, sharedKeyArray, 0, sharedKeyLen, (jbyte *)sharedKey);

    free(ciphertext);
    secureZeroFree(sharedKey, sharedKeyLen);

    // Create byte arrays for result and return
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, ciphertextArray), NULL);
    if (result == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, result, 0, ciphertextArray);
    (*env)->SetObjectArrayElement(env, result, 1, sharedKeyArray);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_mlkemDecapsulate
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray jciphertext) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    jbyte *ciphertext = (*env)->GetByteArrayElements(env, jciphertext, NULL);
    jsize ciphertextLen = (*env)->GetArrayLength(env, jciphertext);
    if (ciphertext == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get ciphertext bytes");
        return NULL;
    }

    // Get shared key length and allocate memory for shared key
    uint32_t sharedKeyLen;
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedKeyLen, sizeof(sharedKeyLen));
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, jciphertext, ciphertext, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get shared key length", ret);
        return NULL;
    }
    uint8_t *sharedKey = malloc(sharedKeyLen);
    if (sharedKey == NULL) {
        (*env)->ReleaseByteArrayElements(env, jciphertext, ciphertext, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for shared key");
        return NULL;
    }

    // Decapsulation
    ret = CRYPT_EAL_PkeyDecaps(pkey, (const uint8_t *)ciphertext, (uint32_t)ciphertextLen, sharedKey, &sharedKeyLen);
    (*env)->ReleaseByteArrayElements(env, jciphertext, ciphertext, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        secureZeroFree(sharedKey, sharedKeyLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to decapsulate");
        return NULL;
    }

    // Create byte arrays for shared key and return
    jbyteArray sharedKeyArray = (*env)->NewByteArray(env, sharedKeyLen);
    if (sharedKeyArray == NULL) {
        secureZeroFree(sharedKey, sharedKeyLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte array for shared key");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, sharedKeyArray, 0, sharedKeyLen, (jbyte *)sharedKey);
    secureZeroFree(sharedKey, sharedKeyLen);

    return sharedKeyArray;
}

static int getSlhDsaParamId(const char *parameterSet) {
    if (parameterSet == NULL) {
        return -1;
    }
    
    if (strcmp(parameterSet, "SLH-DSA-SHA2-128s") == 0) {
        return CRYPT_SLH_DSA_SHA2_128S;
    } else if (strcmp(parameterSet, "SLH-DSA-SHA2-128f") == 0) {
        return CRYPT_SLH_DSA_SHA2_128F;
    } else if (strcmp(parameterSet, "SLH-DSA-SHA2-192s") == 0) {
        return CRYPT_SLH_DSA_SHA2_192S;
    } else if (strcmp(parameterSet, "SLH-DSA-SHA2-192f") == 0) {
        return CRYPT_SLH_DSA_SHA2_192F;
    } else if (strcmp(parameterSet, "SLH-DSA-SHA2-256s") == 0) {
        return CRYPT_SLH_DSA_SHA2_256S;
    } else if (strcmp(parameterSet, "SLH-DSA-SHA2-256f") == 0) {
        return CRYPT_SLH_DSA_SHA2_256F;
    } else if (strcmp(parameterSet, "SLH-DSA-SHAKE-128s") == 0) {
        return CRYPT_SLH_DSA_SHA2_128S;
    } else if (strcmp(parameterSet, "SLH-DSA-SHAKE-128f") == 0) {
        return CRYPT_SLH_DSA_SHA2_128F;
    } else if (strcmp(parameterSet, "SLH-DSA-SHAKE-192s") == 0) {
        return CRYPT_SLH_DSA_SHAKE_192S;
    } else if (strcmp(parameterSet, "SLH-DSA-SHAKE-192f") == 0) {
        return CRYPT_SLH_DSA_SHAKE_192F;
    } else if (strcmp(parameterSet, "SLH-DSA-SHAKE-256s") == 0) {
        return CRYPT_SLH_DSA_SHAKE_256S;
    } else if (strcmp(parameterSet, "SLH-DSA-SHAKE-256f") == 0) {
        return CRYPT_SLH_DSA_SHAKE_256F;
    }
    
    return -1;  // Unknown parameter set
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaCreateContext
  (JNIEnv *env, jclass cls, jstring jparameterSet) {
    if (jparameterSet == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Parameter set cannot be null");
        return 0;
    }
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get parameter set string");
        return 0;
    }
    int paramId = getSlhDsaParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid parameter set");
        return 0;
    }

    int ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    if (pkey == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create SLHDSA context");
        return 0;
    }

    ret = CRYPT_EAL_PkeySetParaById(pkey, paramId);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set SLHDSA parameter set", ret);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return 0;
    }

    return (jlong)pkey;
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef, jstring jparameterSet) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    // get key length
    uint32_t n;
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &n, sizeof(n));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get SLHDSA key length", ret);
        return NULL;
    }
    
    // generate keyPair
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate SLHDSA key pair", ret);
        return NULL;
    }

    // get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(pubKey));
    pubKey.id = CRYPT_PKEY_SLH_DSA;
    pubKey.key.slhDsaPub.seed = malloc(n);
    pubKey.key.slhDsaPub.root = malloc(n);
    pubKey.key.slhDsaPub.len = n;
    if (pubKey.key.slhDsaPub.seed == NULL || pubKey.key.slhDsaPub.root == NULL) {
        free(pubKey.key.slhDsaPub.seed);
        free(pubKey.key.slhDsaPub.root);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for SLHDSA public key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.slhDsaPub.seed);
        free(pubKey.key.slhDsaPub.root);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get SLHDSA public key", ret);
        return NULL;
    }

    // get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(privKey));
    privKey.id = CRYPT_PKEY_SLH_DSA;
    privKey.key.slhDsaPrv.seed = malloc(n);
    privKey.key.slhDsaPrv.prf = malloc(n);
    privKey.key.slhDsaPrv.pub.seed = malloc(n);
    privKey.key.slhDsaPrv.pub.root = malloc(n);
    privKey.key.slhDsaPrv.pub.len = n;
    if (privKey.key.slhDsaPrv.seed == NULL || privKey.key.slhDsaPrv.prf == NULL || privKey.key.slhDsaPrv.pub.seed == NULL || privKey.key.slhDsaPrv.pub.root == NULL) {
        free(pubKey.key.slhDsaPub.seed);
        free(pubKey.key.slhDsaPub.root);
        free(privKey.key.slhDsaPrv.seed);
        free(privKey.key.slhDsaPrv.prf);
        free(privKey.key.slhDsaPrv.pub.seed);
        free(privKey.key.slhDsaPrv.pub.root);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for SLHDSA private key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPrv(pkey, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.slhDsaPub.seed);
        free(pubKey.key.slhDsaPub.root);
        secureZeroFree(privKey.key.slhDsaPrv.seed, n);
        secureZeroFree(privKey.key.slhDsaPrv.prf, n);
        secureZeroFree(privKey.key.slhDsaPrv.pub.seed, n);
        secureZeroFree(privKey.key.slhDsaPrv.pub.root, n);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get SLHDSA private key", ret);
        return NULL;
    }

    // create byte arrays for public key and private key
    jbyteArray publicKeyArray = (*env)->NewByteArray(env, 2 * n);
    jbyteArray privateKeyArray = (*env)->NewByteArray(env, 4 * n);
    if (publicKeyArray == NULL || privateKeyArray == NULL) {
        free(pubKey.key.slhDsaPub.seed);
        free(pubKey.key.slhDsaPub.root);
        secureZeroFree(privKey.key.slhDsaPrv.seed, n);
        secureZeroFree(privKey.key.slhDsaPrv.prf, n);
        secureZeroFree(privKey.key.slhDsaPrv.pub.seed, n);
        secureZeroFree(privKey.key.slhDsaPrv.pub.root, n);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte array for SLHDSA public key");
        return NULL;
    }

    // copy public key and private key to byte array
    (*env)->SetByteArrayRegion(env, publicKeyArray, 0, n, (jbyte *)pubKey.key.slhDsaPub.seed);
    (*env)->SetByteArrayRegion(env, publicKeyArray, n, n, (jbyte *)pubKey.key.slhDsaPub.root);

    (*env)->SetByteArrayRegion(env, privateKeyArray, 0, n, (jbyte *)privKey.key.slhDsaPrv.seed);
    (*env)->SetByteArrayRegion(env, privateKeyArray, n, n, (jbyte *)privKey.key.slhDsaPrv.prf);
    (*env)->SetByteArrayRegion(env, privateKeyArray, 2 * n, n, (jbyte *)privKey.key.slhDsaPrv.pub.seed);
    (*env)->SetByteArrayRegion(env, privateKeyArray, 3 * n, n, (jbyte *)privKey.key.slhDsaPrv.pub.root);

    free(pubKey.key.slhDsaPub.seed);
    free(pubKey.key.slhDsaPub.root);
    secureZeroFree(privKey.key.slhDsaPrv.seed, n);
    secureZeroFree(privKey.key.slhDsaPrv.prf, n);
    secureZeroFree(privKey.key.slhDsaPrv.pub.seed, n);
    secureZeroFree(privKey.key.slhDsaPrv.pub.root, n);

    // create byte array for keyPair
    jobjectArray keyPair = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, publicKeyArray), NULL);
    if (keyPair == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte array for keyPair");
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, keyPair, 0, publicKeyArray);
    (*env)->SetObjectArrayElement(env, keyPair, 1, privateKeyArray);

    return keyPair;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaSetKeys
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey, jbyteArray privateKey) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (publicKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(pubKey));
        pubKey.id = CRYPT_PKEY_SLH_DSA;
        jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);

        pubKey.key.slhDsaPub.seed = malloc(pubKeyLen / 2);
        pubKey.key.slhDsaPub.root = malloc(pubKeyLen / 2);
        if (pubKey.key.slhDsaPub.seed == NULL || pubKey.key.slhDsaPub.root == NULL) {
            free(pubKey.key.slhDsaPub.seed);
            free(pubKey.key.slhDsaPub.root);
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for SLHDSA public key");
            return;
        }

        (*env)->GetByteArrayRegion(env, publicKey, 0, pubKeyLen / 2, (jbyte *)pubKey.key.slhDsaPub.seed);
        (*env)->GetByteArrayRegion(env, publicKey, pubKeyLen / 2, pubKeyLen / 2, (jbyte *)pubKey.key.slhDsaPub.root);
        pubKey.key.slhDsaPub.len = pubKeyLen / 2;

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
        free(pubKey.key.slhDsaPub.seed);
        free(pubKey.key.slhDsaPub.root);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set SLHDSA public key", ret);
            return;
        }
    }

    if (privateKey != NULL) {
        CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(privKey));
        privKey.id = CRYPT_PKEY_SLH_DSA;
        jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);

        privKey.key.slhDsaPrv.seed = malloc(privKeyLen / 4);
        privKey.key.slhDsaPrv.prf = malloc(privKeyLen / 4);
        privKey.key.slhDsaPrv.pub.seed = malloc(privKeyLen / 4);
        privKey.key.slhDsaPrv.pub.root = malloc(privKeyLen / 4);
        if (privKey.key.slhDsaPrv.seed == NULL || privKey.key.slhDsaPrv.prf == NULL || privKey.key.slhDsaPrv.pub.seed == NULL || privKey.key.slhDsaPrv.pub.root == NULL) {
            free(privKey.key.slhDsaPrv.seed);
            free(privKey.key.slhDsaPrv.prf);
            free(privKey.key.slhDsaPrv.pub.seed);
            free(privKey.key.slhDsaPrv.pub.root);
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for SLHDSA private key");
            return;
        }

        (*env)->GetByteArrayRegion(env, privateKey, 0, privKeyLen / 4, (jbyte *)privKey.key.slhDsaPrv.seed);
        (*env)->GetByteArrayRegion(env, privateKey, privKeyLen / 4, privKeyLen / 4, (jbyte *)privKey.key.slhDsaPrv.prf);
        (*env)->GetByteArrayRegion(env, privateKey, 2 * privKeyLen / 4, privKeyLen / 4, (jbyte *)privKey.key.slhDsaPrv.pub.seed);
        (*env)->GetByteArrayRegion(env, privateKey, 3 * privKeyLen / 4, privKeyLen / 4, (jbyte *)privKey.key.slhDsaPrv.pub.root);
        privKey.key.slhDsaPrv.pub.len = privKeyLen / 4;

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        secureZeroFree(privKey.key.slhDsaPrv.seed, privKeyLen / 4);
        secureZeroFree(privKey.key.slhDsaPrv.prf, privKeyLen / 4);
        secureZeroFree(privKey.key.slhDsaPrv.pub.seed, privKeyLen / 4);
        secureZeroFree(privKey.key.slhDsaPrv.pub.root, privKeyLen / 4);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set SLHDSA private key", ret);
            return;
        }
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
}

static uint32_t getSlhDsaSignatureLength(int parameterId) {
    switch (parameterId) {
        case CRYPT_SLH_DSA_SHA2_128S:
        case CRYPT_SLH_DSA_SHAKE_128S:
            return 7856;
        case CRYPT_SLH_DSA_SHA2_128F:
        case CRYPT_SLH_DSA_SHAKE_128F:
            return 17088;
        case CRYPT_SLH_DSA_SHA2_192S:
        case CRYPT_SLH_DSA_SHAKE_192S:
            return 16224;
        case CRYPT_SLH_DSA_SHA2_192F:
        case CRYPT_SLH_DSA_SHAKE_192F:
            return 35664;
        case CRYPT_SLH_DSA_SHA2_256S:
        case CRYPT_SLH_DSA_SHAKE_256S:
            return 29792;
        case CRYPT_SLH_DSA_SHA2_256F:
        case CRYPT_SLH_DSA_SHAKE_256F:
            return 49856;
        default:
            return 0; // Unknown algorithm
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaSign
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    // get signature length
    int32_t paraId;
    if (CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId)) != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get parameter ID");
        return NULL;
    }

    uint32_t signLen = getSlhDsaSignatureLength(paraId);
    if (signLen == 0) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get signature length");
        return NULL;
    }

    // create temporary buffer for signature
    uint8_t *signBuf = malloc(signLen);
    if (signBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for signature");
        return NULL;
    }

    // sign data
    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeySign(pkey, mdId, (uint8_t *)inputData, inputLen, signBuf, &signLen);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        free(signBuf);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to sign data", ret);
        return NULL;
    }

    // create byte array for signature
    jbyteArray result = (*env)->NewByteArray(env, signLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, signLen, (jbyte *)signBuf);
    }

    free(signBuf);
    return result;
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaVerify
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    // get inputData for native methods
    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return JNI_FALSE;
    }

    // get signData for native methods
    jbyte *signData = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize signLen = (*env)->GetArrayLength(env, signature);
    if (signData == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get sign data");
        return JNI_FALSE;
    }

    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeyVerify(pkey, mdId, (uint8_t *)inputData, inputLen, (uint8_t *)signData, signLen);

    (*env)->ReleaseByteArrayElements(env, signature, signData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return (ret == CRYPT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaSetDeterministic
  (JNIEnv *env, jclass cls, jlong nativeRef, jboolean deterministic) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    uint32_t val = deterministic ? 1 : 0;
    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set MLDSA deterministic flag", ret);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaSetPreHash
  (JNIEnv *env, jclass cls, jlong nativeRef, jboolean preHash) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    uint32_t val = preHash ? 1 : 0;
    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set MLDSA preHash flag", ret);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaSetCxt
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray context) {
    if (context == NULL) {
        return;
    }

    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;

    // get context for native methods
    jbyte *data = (*env)->GetByteArrayElements(env, context, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, context);
    if (data == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get context data");
        return;
    }

    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_CTX_INFO, (uint8_t *)data, dataLen);
    (*env)->ReleaseByteArrayElements(env, context, data, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set SLHDSA context", ret);
    }
    return;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_slhdsaSetAdditionalRandomness
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray additionalRandomness) {
    if (additionalRandomness == NULL) {
        return;
    }

    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;

    // get additionalRandomness for native methods
    jbyte *data = (*env)->GetByteArrayElements(env, additionalRandomness, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, additionalRandomness);
    if (data == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get additionalRandomness data");
        return;
    }

    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, (uint8_t *)data, dataLen);
    (*env)->ReleaseByteArrayElements(env, additionalRandomness, data, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set SLHDSA additionalRandomness", ret);
    }
    return;
}

// ==================== FrodoKEM ====================

static int getFrodoKemParamId(const char *parameterSet) {
    if (strcmp(parameterSet, "FrodoKEM-640-SHAKE") == 0) {
        return CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE;
    } else if (strcmp(parameterSet, "FrodoKEM-640-AES") == 0) {
        return CRYPT_KEM_TYPE_FRODOKEM_640_AES;
    } else if (strcmp(parameterSet, "FrodoKEM-976-SHAKE") == 0) {
        return CRYPT_KEM_TYPE_FRODOKEM_976_SHAKE;
    } else if (strcmp(parameterSet, "FrodoKEM-976-AES") == 0) {
        return CRYPT_KEM_TYPE_FRODOKEM_976_AES;
    } else if (strcmp(parameterSet, "FrodoKEM-1344-SHAKE") == 0) {
        return CRYPT_KEM_TYPE_FRODOKEM_1344_SHAKE;
    } else if (strcmp(parameterSet, "FrodoKEM-1344-AES") == 0) {
        return CRYPT_KEM_TYPE_FRODOKEM_1344_AES;
    } else {
        return -1;
    }
}

static void getFrodoKemKeySizes(int paramId, int *publicKeySize, int *privateKeySize) {
    switch (paramId) {
        case CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_640_AES:
            *publicKeySize = 9616;
            *privateKeySize = 19888;
            break;
        case CRYPT_KEM_TYPE_FRODOKEM_976_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_976_AES:
            *publicKeySize = 15632;
            *privateKeySize = 31296;
            break;
        case CRYPT_KEM_TYPE_FRODOKEM_1344_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_1344_AES:
            *publicKeySize = 21520;
            *privateKeySize = 43088;
            break;
        default:
            *publicKeySize = 0;
            *privateKeySize = 0;
            break;
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_frodoKemCreateContext
  (JNIEnv *env, jclass cls, jstring jparameterSet) {
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        return 0;
    }
    int paramId = getFrodoKemParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported FrodoKEM parameter set");
        return 0;
    }

    int ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    if (pkey == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create FrodoKEM context");
        return 0;
    }

    ret = CRYPT_EAL_PkeySetParaById(pkey, paramId);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set FrodoKEM parameter set", ret);
        return 0;
    }

    return (jlong)pkey;
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_frodoKemGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef, jstring jparameterSet) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    int publicKeySize;
    int privateKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        return NULL;
    }
    int paramId = getFrodoKemParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);

    getFrodoKemKeySizes(paramId, &publicKeySize, &privateKeySize);
    if (publicKeySize == 0) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported FrodoKEM parameter set");
        return NULL;
    }

    // generate keyPair
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate key pair", ret);
        return NULL;
    }

    // get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = CRYPT_PKEY_FRODOKEM;
    pubKey.key.kemEk.data = malloc(publicKeySize);
    pubKey.key.kemEk.len = publicKeySize;
    if (pubKey.key.kemEk.data == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for public key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.kemEk.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get public key", ret);
        return NULL;
    }

    // get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = CRYPT_PKEY_FRODOKEM;
    privKey.key.kemDk.data = malloc(privateKeySize);
    privKey.key.kemDk.len = privateKeySize;
    if (privKey.key.kemDk.data == NULL) {
        free(pubKey.key.kemEk.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for private key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPrv(pkey, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.kemEk.data);
        secureZeroFree(privKey.key.kemDk.data, privKey.key.kemDk.len);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray publicKeyArray = (*env)->NewByteArray(env, pubKey.key.kemEk.len);
    jbyteArray privateKeyArray = (*env)->NewByteArray(env, privKey.key.kemDk.len);
    if (publicKeyArray == NULL || privateKeyArray == NULL) {
        free(pubKey.key.kemEk.data);
        secureZeroFree(privKey.key.kemDk.data, privKey.key.kemDk.len);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte arrays for keys");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, publicKeyArray, 0, pubKey.key.kemEk.len, (jbyte *)pubKey.key.kemEk.data);
    (*env)->SetByteArrayRegion(env, privateKeyArray, 0, privKey.key.kemDk.len, (jbyte *)privKey.key.kemDk.data);

    free(pubKey.key.kemEk.data);
    secureZeroFree(privKey.key.kemDk.data, privKey.key.kemDk.len);

    // Create byte arrays for keyPair
    jobjectArray keyPair = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, publicKeyArray), NULL);
    if (keyPair == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte arrays for keyPair");
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, keyPair, 0, publicKeyArray);
    (*env)->SetObjectArrayElement(env, keyPair, 1, privateKeyArray);

    return keyPair;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_frodoKemSetKeys
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray jencapKey, jbyteArray jdecapKey) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (jencapKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_FRODOKEM;
        pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
        if (pubKey.key.kemEk.data == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get encapsulate key data");
            return;
        }
        pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
        (*env)->ReleaseByteArrayElements(env, jencapKey, (jbyte *)pubKey.key.kemEk.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set encapsulate key", ret);
            return;
        }
    }

    if (jdecapKey != NULL) {
        CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_FRODOKEM;
        privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
        if (privKey.key.kemDk.data == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get decapsulate key data");
            return;
        }
        privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        (*env)->ReleaseByteArrayElements(env, jdecapKey, (jbyte *)privKey.key.kemDk.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set decapsulate key", ret);
            return;
        }
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_frodoKemFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_frodoKemEncapsulate
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    // Get ciphertext and shared key lengths
    uint32_t ciphertextLen;
    uint32_t sharedKeyLen;
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ciphertextLen, sizeof(ciphertextLen));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get ciphertext length", ret);
        return NULL;
    }

    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedKeyLen, sizeof(sharedKeyLen));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get shared key length", ret);
        return NULL;
    }

    // Create ciphertext and shared key buffers
    uint8_t *ciphertext = malloc(ciphertextLen);
    uint8_t *sharedKey = malloc(sharedKeyLen);
    if (ciphertext == NULL || sharedKey == NULL) {
        if (ciphertext) free(ciphertext);
        if (sharedKey) free(sharedKey);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for encapsulation");
        return NULL;
    }

    // Encapsulation
    ret = CRYPT_EAL_PkeyEncaps(pkey, ciphertext, &ciphertextLen, sharedKey, &sharedKeyLen);
    if (ret != CRYPT_SUCCESS) {
        free(ciphertext);
        secureZeroFree(sharedKey, sharedKeyLen);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to encapsulate", ret);
        return NULL;
    }

    // Create byte arrays for ciphertext and sharedKey
    jbyteArray ciphertextArray = (*env)->NewByteArray(env, ciphertextLen);
    jbyteArray sharedKeyArray = (*env)->NewByteArray(env, sharedKeyLen);
    if (ciphertextArray == NULL || sharedKeyArray == NULL) {
        free(ciphertext);
        secureZeroFree(sharedKey, sharedKeyLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte arrays for encapsulation result");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, ciphertextArray, 0, ciphertextLen, (jbyte *)ciphertext);
    (*env)->SetByteArrayRegion(env, sharedKeyArray, 0, sharedKeyLen, (jbyte *)sharedKey);

    free(ciphertext);
    secureZeroFree(sharedKey, sharedKeyLen);

    // Create result array
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, ciphertextArray), NULL);
    if (result == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, result, 0, ciphertextArray);
    (*env)->SetObjectArrayElement(env, result, 1, sharedKeyArray);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_frodoKemDecapsulate
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray jciphertext) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    jbyte *ciphertext = (*env)->GetByteArrayElements(env, jciphertext, NULL);
    jsize ciphertextLen = (*env)->GetArrayLength(env, jciphertext);
    if (ciphertext == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get ciphertext bytes");
        return NULL;
    }

    // Get shared key length and allocate memory for shared key
    uint32_t sharedKeyLen;
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedKeyLen, sizeof(sharedKeyLen));
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, jciphertext, ciphertext, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get shared key length", ret);
        return NULL;
    }
    uint8_t *sharedKey = malloc(sharedKeyLen);
    if (sharedKey == NULL) {
        (*env)->ReleaseByteArrayElements(env, jciphertext, ciphertext, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for shared key");
        return NULL;
    }

    // Decapsulation
    ret = CRYPT_EAL_PkeyDecaps(pkey, (const uint8_t *)ciphertext, (uint32_t)ciphertextLen, sharedKey, &sharedKeyLen);
    (*env)->ReleaseByteArrayElements(env, jciphertext, ciphertext, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        secureZeroFree(sharedKey, sharedKeyLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to decapsulate");
        return NULL;
    }

    // Create byte array for shared key and return
    jbyteArray sharedKeyArray = (*env)->NewByteArray(env, sharedKeyLen);
    if (sharedKeyArray == NULL) {
        secureZeroFree(sharedKey, sharedKeyLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte array for shared key");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, sharedKeyArray, 0, sharedKeyLen, (jbyte *)sharedKey);
    secureZeroFree(sharedKey, sharedKeyLen);

    return sharedKeyArray;
}

// ==================== Classic McEliece ====================

static int getMcElieceParamId(const char *parameterSet) {
    if (strcmp(parameterSet, "McEliece-6688128") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_6688128;
    } else if (strcmp(parameterSet, "McEliece-6688128f") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_6688128_F;
    } else if (strcmp(parameterSet, "McEliece-6688128pc") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_6688128_PC;
    } else if (strcmp(parameterSet, "McEliece-6688128pcf") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_6688128_PCF;
    } else if (strcmp(parameterSet, "McEliece-6960119") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_6960119;
    } else if (strcmp(parameterSet, "McEliece-6960119f") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_6960119_F;
    } else if (strcmp(parameterSet, "McEliece-6960119pc") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_6960119_PC;
    } else if (strcmp(parameterSet, "McEliece-6960119pcf") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_6960119_PCF;
    } else if (strcmp(parameterSet, "McEliece-8192128") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_8192128;
    } else if (strcmp(parameterSet, "McEliece-8192128f") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_8192128_F;
    } else if (strcmp(parameterSet, "McEliece-8192128pc") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_8192128_PC;
    } else if (strcmp(parameterSet, "McEliece-8192128pcf") == 0) {
        return CRYPT_KEM_TYPE_MCELIECE_8192128_PCF;
    } else {
        return -1;
    }
}

static void getMcElieceKeySizes(int paramId, int *publicKeySize, int *privateKeySize) {
    switch (paramId) {
        case CRYPT_KEM_TYPE_MCELIECE_6688128:
        case CRYPT_KEM_TYPE_MCELIECE_6688128_F:
        case CRYPT_KEM_TYPE_MCELIECE_6688128_PC:
        case CRYPT_KEM_TYPE_MCELIECE_6688128_PCF:
            *publicKeySize = 1044992;
            *privateKeySize = 13932;
            break;
        case CRYPT_KEM_TYPE_MCELIECE_6960119:
        case CRYPT_KEM_TYPE_MCELIECE_6960119_F:
        case CRYPT_KEM_TYPE_MCELIECE_6960119_PC:
        case CRYPT_KEM_TYPE_MCELIECE_6960119_PCF:
            *publicKeySize = 1047319;
            *privateKeySize = 13948;
            break;
        case CRYPT_KEM_TYPE_MCELIECE_8192128:
        case CRYPT_KEM_TYPE_MCELIECE_8192128_F:
        case CRYPT_KEM_TYPE_MCELIECE_8192128_PC:
        case CRYPT_KEM_TYPE_MCELIECE_8192128_PCF:
            *publicKeySize = 1357824;
            *privateKeySize = 14120;
            break;
        default:
            *publicKeySize = 0;
            *privateKeySize = 0;
            break;
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_mcelieceCreateContext
  (JNIEnv *env, jclass cls, jstring jparameterSet) {
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        return 0;
    }
    int paramId = getMcElieceParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported Classic McEliece parameter set");
        return 0;
    }

    int ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
    if (pkey == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create Classic McEliece context");
        return 0;
    }

    ret = CRYPT_EAL_PkeySetParaById(pkey, paramId);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set Classic McEliece parameter set", ret);
        return 0;
    }

    return (jlong)pkey;
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_mcelieceGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef, jstring jparameterSet) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    int publicKeySize;
    int privateKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        return NULL;
    }
    int paramId = getMcElieceParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);

    getMcElieceKeySizes(paramId, &publicKeySize, &privateKeySize);
    if (publicKeySize == 0) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported Classic McEliece parameter set");
        return NULL;
    }

    // generate keyPair
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate key pair", ret);
        return NULL;
    }

    // get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = CRYPT_PKEY_MCELIECE;
    pubKey.key.kemEk.data = malloc(publicKeySize);
    pubKey.key.kemEk.len = publicKeySize;
    if (pubKey.key.kemEk.data == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for public key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.kemEk.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get public key", ret);
        return NULL;
    }

    // get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = CRYPT_PKEY_MCELIECE;
    privKey.key.kemDk.data = malloc(privateKeySize);
    privKey.key.kemDk.len = privateKeySize;
    if (privKey.key.kemDk.data == NULL) {
        free(pubKey.key.kemEk.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for private key");
        return NULL;
    }
    ret = CRYPT_EAL_PkeyGetPrv(pkey, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.kemEk.data);
        secureZeroFree(privKey.key.kemDk.data, privKey.key.kemDk.len);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray publicKeyArray = (*env)->NewByteArray(env, pubKey.key.kemEk.len);
    jbyteArray privateKeyArray = (*env)->NewByteArray(env, privKey.key.kemDk.len);
    if (publicKeyArray == NULL || privateKeyArray == NULL) {
        free(pubKey.key.kemEk.data);
        secureZeroFree(privKey.key.kemDk.data, privKey.key.kemDk.len);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte arrays for keys");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, publicKeyArray, 0, pubKey.key.kemEk.len, (jbyte *)pubKey.key.kemEk.data);
    (*env)->SetByteArrayRegion(env, privateKeyArray, 0, privKey.key.kemDk.len, (jbyte *)privKey.key.kemDk.data);

    free(pubKey.key.kemEk.data);
    secureZeroFree(privKey.key.kemDk.data, privKey.key.kemDk.len);

    // Create byte arrays for keyPair
    jobjectArray keyPair = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, publicKeyArray), NULL);
    if (keyPair == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte arrays for keyPair");
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, keyPair, 0, publicKeyArray);
    (*env)->SetObjectArrayElement(env, keyPair, 1, privateKeyArray);

    return keyPair;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mcelieceSetKeys
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray jencapKey, jbyteArray jdecapKey) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (jencapKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_MCELIECE;
        pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
        if (pubKey.key.kemEk.data == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get encapsulate key data");
            return;
        }
        pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
        (*env)->ReleaseByteArrayElements(env, jencapKey, (jbyte *)pubKey.key.kemEk.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set encapsulate key", ret);
            return;
        }
    }

    if (jdecapKey != NULL) {
        CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_MCELIECE;
        privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
        if (privKey.key.kemDk.data == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get decapsulate key data");
            return;
        }
        privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        (*env)->ReleaseByteArrayElements(env, jdecapKey, (jbyte *)privKey.key.kemDk.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set decapsulate key", ret);
            return;
        }
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_mcelieceFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_mcelieceEncapsulate
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    // Get ciphertext and shared key lengths
    uint32_t ciphertextLen;
    uint32_t sharedKeyLen;
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ciphertextLen, sizeof(ciphertextLen));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get ciphertext length", ret);
        return NULL;
    }

    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedKeyLen, sizeof(sharedKeyLen));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get shared key length", ret);
        return NULL;
    }

    // Create ciphertext and shared key buffers
    uint8_t *ciphertext = malloc(ciphertextLen);
    uint8_t *sharedKey = malloc(sharedKeyLen);
    if (ciphertext == NULL || sharedKey == NULL) {
        if (ciphertext) free(ciphertext);
        if (sharedKey) free(sharedKey);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for encapsulation");
        return NULL;
    }

    // Encapsulation
    ret = CRYPT_EAL_PkeyEncaps(pkey, ciphertext, &ciphertextLen, sharedKey, &sharedKeyLen);
    if (ret != CRYPT_SUCCESS) {
        free(ciphertext);
        secureZeroFree(sharedKey, sharedKeyLen);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to encapsulate", ret);
        return NULL;
    }

    // Create byte arrays for ciphertext and sharedKey
    jbyteArray ciphertextArray = (*env)->NewByteArray(env, ciphertextLen);
    jbyteArray sharedKeyArray = (*env)->NewByteArray(env, sharedKeyLen);
    if (ciphertextArray == NULL || sharedKeyArray == NULL) {
        free(ciphertext);
        secureZeroFree(sharedKey, sharedKeyLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte arrays for encapsulation result");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, ciphertextArray, 0, ciphertextLen, (jbyte *)ciphertext);
    (*env)->SetByteArrayRegion(env, sharedKeyArray, 0, sharedKeyLen, (jbyte *)sharedKey);

    free(ciphertext);
    secureZeroFree(sharedKey, sharedKeyLen);

    // Create result array
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, ciphertextArray), NULL);
    if (result == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, result, 0, ciphertextArray);
    (*env)->SetObjectArrayElement(env, result, 1, sharedKeyArray);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_mcelieceDecapsulate
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray jciphertext) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    jbyte *ciphertext = (*env)->GetByteArrayElements(env, jciphertext, NULL);
    jsize ciphertextLen = (*env)->GetArrayLength(env, jciphertext);
    if (ciphertext == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get ciphertext bytes");
        return NULL;
    }

    // Get shared key length and allocate memory for shared key
    uint32_t sharedKeyLen;
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedKeyLen, sizeof(sharedKeyLen));
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, jciphertext, ciphertext, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get shared key length", ret);
        return NULL;
    }
    uint8_t *sharedKey = malloc(sharedKeyLen);
    if (sharedKey == NULL) {
        (*env)->ReleaseByteArrayElements(env, jciphertext, ciphertext, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for shared key");
        return NULL;
    }

    // Decapsulation
    ret = CRYPT_EAL_PkeyDecaps(pkey, (const uint8_t *)ciphertext, (uint32_t)ciphertextLen, sharedKey, &sharedKeyLen);
    (*env)->ReleaseByteArrayElements(env, jciphertext, ciphertext, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        secureZeroFree(sharedKey, sharedKeyLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to decapsulate");
        return NULL;
    }

    // Create byte array for shared key and return
    jbyteArray sharedKeyArray = (*env)->NewByteArray(env, sharedKeyLen);
    if (sharedKeyArray == NULL) {
        secureZeroFree(sharedKey, sharedKeyLen);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create byte array for shared key");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, sharedKeyArray, 0, sharedKeyLen, (jbyte *)sharedKey);
    secureZeroFree(sharedKey, sharedKeyLen);

    return sharedKeyArray;
}
