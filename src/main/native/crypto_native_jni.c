#include <jni.h>
#include "org_openhitls_crypto_core_CryptoNative.h"
#include "org_openhitls_crypto_jce_provider_ProviderConfig.h"
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
#include <crypto/crypt_types.h>
#include <bsl/bsl_params.h>
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

static bool isRsaVerificationFailure(int32_t errorCode) {
    return errorCode == CRYPT_RSA_NOR_VERIFY_FAIL ||
        errorCode == CRYPT_RSA_ERR_PSS_SALT_LEN ||
        errorCode == CRYPT_RSA_ERR_PSS_SALT_DATA ||
        errorCode == CRYPT_RSA_ERR_INPUT_VALUE;
}

static int32_t configureRsaPss(CRYPT_EAL_PkeyCtx *ctx, int32_t hashAlg,
    int32_t mgf1HashAlg, int32_t saltLength) {
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashAlg, sizeof(hashAlg), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mgf1HashAlg, sizeof(mgf1HashAlg), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLength, sizeof(saltLength), 0},
        BSL_PARAM_END
    };
    return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0);
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
    jboolean isCopy;
} JByteArrayRef;

static bool getByteArrayRef(JNIEnv *env, jbyteArray array, JByteArrayRef *ref, const char *message, bool required) {
    ref->array = array;
    ref->bytes = NULL;
    ref->len = 0;
    ref->isCopy = JNI_FALSE;

    if (array == NULL) {
        if (required) {
            throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, message);
            return false;
        }
        return true;
    }

    ref->bytes = (*env)->GetByteArrayElements(env, array, &ref->isCopy);
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

static void releaseByteArrayRef(JNIEnv *env, JByteArrayRef *ref, bool sensitive) {
    if (ref->array != NULL && ref->bytes != NULL) {
        if (sensitive && ref->isCopy == JNI_TRUE && ref->len > 0) {
            memset(ref->bytes, 0, (size_t)ref->len);
        }
        (*env)->ReleaseByteArrayElements(env, ref->array, ref->bytes, JNI_ABORT);
    }
    ref->array = NULL;
    ref->bytes = NULL;
    ref->len = 0;
    ref->isCopy = JNI_FALSE;
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

// Global provider state
static CRYPT_EAL_LibCtx *g_libCtx = NULL;
static char *g_providerAttr = NULL;

static void clearProviderSelectionNoLock(void) {
    if (g_providerAttr != NULL) {
        free(g_providerAttr);
        g_providerAttr = NULL;
    }
}

static void freeProviderStateNoLock(void) {
    if (g_libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(g_libCtx);
        g_libCtx = NULL;
    }
    clearProviderSelectionNoLock();
}

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

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;

    pthread_mutex_lock(&g_init_mutex);
    freeProviderStateNoLock();
    pthread_mutex_unlock(&g_init_mutex);
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

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(g_libCtx, mdId, g_providerAttr);
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

    if (data == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Input data cannot be null");
        return;
    }

    jsize dataLen = (*env)->GetArrayLength(env, data);
    if (offset < 0 || length < 0 || offset > dataLen || length > dataLen - offset) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Invalid offset or length");
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

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestReset
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    (void)cls;
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid context");
        return;
    }

    int ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to reset message digest", ret);
    }
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
    
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_ProviderMacNewCtx(g_libCtx, algorithmId, g_providerAttr);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create HMAC context");
        return 0;
    }

    JByteArrayRef keyRef = {0};
    
    if (key != NULL) {
        if (!getByteArrayRef(env, key, &keyRef, "Failed to get key bytes", true)) {
            CRYPT_EAL_MacFreeCtx(ctx);
            return 0;
        }
    }
    
    int result = CRYPT_EAL_MacInit(ctx, (uint8_t *)keyRef.bytes, keyRef.len);
    if (result != CRYPT_SUCCESS) {
        releaseByteArrayRef(env, &keyRef, true);
        CRYPT_EAL_MacFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to initialize HMAC");
        return 0;
    }

    releaseByteArrayRef(env, &keyRef, true);
    
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

static const char *getEcCurveNameById(int curveId) {
    switch (curveId) {
        case CRYPT_ECC_SM2:
            return "sm2p256v1";
        case CRYPT_ECC_NISTP256:
            return "secp256r1";
        case CRYPT_ECC_NISTP384:
            return "secp384r1";
        case CRYPT_ECC_NISTP521:
            return "secp521r1";
        default:
            return NULL;
    }
}

static int getEcPrivateKeySizeById(int curveId) {
    switch (curveId) {
        case CRYPT_ECC_SM2:
        case CRYPT_ECC_NISTP256:
            return 32;
        case CRYPT_ECC_NISTP384:
            return 48;
        case CRYPT_ECC_NISTP521:
            return 66;
        default:
            return -1;
    }
}

static int getEcPublicKeySizeById(int curveId) {
    int privateKeySize = getEcPrivateKeySizeById(curveId);
    return privateKeySize > 0 ? 1 + 2 * privateKeySize : -1;
}

static bool isEcPkeyId(int keyId) {
    return keyId == CRYPT_PKEY_ECDSA || keyId == CRYPT_PKEY_SM2;
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

static CRYPT_EAL_PkeyCtx *newEcContextByCurveId(JNIEnv *env, int curveId, bool setDefaultSm2UserId) {
    int keyType = (curveId == CRYPT_ECC_SM2) ? CRYPT_PKEY_SM2 : CRYPT_PKEY_ECDSA;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(g_libCtx, keyType,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, g_providerAttr);
    if (pkey == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create EC context");
        return NULL;
    }

    if (curveId == CRYPT_ECC_SM2) {
        if (setDefaultSm2UserId) {
            const char *defaultUserId = "1234567812345678";
            int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SM2_USER_ID,
                (void *)defaultUserId, strlen(defaultUserId));
            if (ret != CRYPT_SUCCESS) {
                CRYPT_EAL_PkeyFreeCtx(pkey);
                throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set default user ID", ret);
                return NULL;
            }
        }
    } else {
        int ret = CRYPT_EAL_PkeySetParaById(pkey, curveId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set curve parameters", ret);
            return NULL;
        }
    }

    return pkey;
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

    CRYPT_EAL_PkeyCtx *pkey = newEcContextByCurveId(env, curveId, true);
    if (pkey == NULL) {
        return 0;
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
        JByteArrayRef privKeyRef = {0};
        if (!getByteArrayRef(env, privateKey, &privKeyRef, "Failed to get private key", true)) {
            return;
        }
        privKey.key.eccPrv.data = (uint8_t *)privKeyRef.bytes;
        privKey.key.eccPrv.len = privKeyRef.len;

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        releaseByteArrayRef(env, &privKeyRef, true);
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

static jbyteArray encodeEcKey(JNIEnv *env, jstring jcurveName, jbyteArray jkey, bool privateKey) {
    if (jcurveName == NULL || jkey == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "EC key encoding inputs cannot be null");
        return NULL;
    }

    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
    if (curveName == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get EC curve name string");
        return NULL;
    }
    int curveId = getEcCurveId(curveName);
    (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);
    if (curveId == -1) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported curve");
        return NULL;
    }

    JByteArrayRef key = {0};
    if (!getByteArrayRef(env, jkey, &key, "Failed to get EC key bytes", true)) {
        return NULL;
    }

    CRYPT_EAL_PkeyCtx *ctx = newEcContextByCurveId(env, curveId, false);
    if (ctx == NULL) {
        if (privateKey) {
            releaseByteArrayRef(env, &key, true);
        } else {
            releaseByteArrayRef(env, &key, false);
        }
        return NULL;
    }

    int keyType = (curveId == CRYPT_ECC_SM2) ? CRYPT_PKEY_SM2 : CRYPT_PKEY_ECDSA;
    int32_t ret;
    if (privateKey) {
        CRYPT_EAL_PkeyPrv prv;
        memset(&prv, 0, sizeof(prv));
        prv.id = keyType;
        prv.key.eccPrv.data = (uint8_t *)key.bytes;
        prv.key.eccPrv.len = key.len;
        ret = CRYPT_EAL_PkeySetPrv(ctx, &prv);
    } else {
        CRYPT_EAL_PkeyPub pub;
        memset(&pub, 0, sizeof(pub));
        pub.id = keyType;
        pub.key.eccPub.data = (uint8_t *)key.bytes;
        pub.key.eccPub.len = key.len;
        ret = CRYPT_EAL_PkeySetPub(ctx, &pub);
    }
    if (privateKey) {
        releaseByteArrayRef(env, &key, true);
    } else {
        releaseByteArrayRef(env, &key, false);
    }
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION,
            privateKey ? "Failed to set EC private key" : "Failed to set EC public key", ret);
        return NULL;
    }

    BSL_Buffer encoded = {0};
    ret = CRYPT_EAL_EncodeBuffKey(ctx, NULL, BSL_FORMAT_ASN1,
        privateKey ? CRYPT_PRIKEY_PKCS8_UNENCRYPT : CRYPT_PUBKEY_SUBKEY, &encoded);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION,
            privateKey ? "Failed to encode EC private key" : "Failed to encode EC public key", ret);
        return NULL;
    }

    jbyteArray result = newByteArrayFromData(env, encoded.data, encoded.dataLen);
    if (privateKey) {
        BSL_SAL_ClearFree(encoded.data, encoded.dataLen);
    } else {
        BSL_SAL_FREE(encoded.data);
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecEncodePublicKey
  (JNIEnv *env, jclass cls, jstring jcurveName, jbyteArray jpublicKey) {
    return encodeEcKey(env, jcurveName, jpublicKey, false);
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecEncodePrivateKey
  (JNIEnv *env, jclass cls, jstring jcurveName, jbyteArray jprivateKey) {
    return encodeEcKey(env, jcurveName, jprivateKey, true);
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecDecodePublicKey
  (JNIEnv *env, jclass cls, jbyteArray jencodedKey) {
    if (jencodedKey == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Encoded EC public key cannot be null");
        return NULL;
    }

    uint32_t encodedLen = 0;
    uint8_t *encodedBytes = copyByteArrayWithTerminator(env, jencodedKey, &encodedLen,
        "Failed to copy encoded EC public key bytes");
    if (encodedBytes == NULL) {
        return NULL;
    }

    BSL_Buffer encoded = {encodedBytes, encodedLen};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encoded, NULL, 0, &ctx);
    free(encodedBytes);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to decode EC public key", ret);
        return NULL;
    }

    int keyId = CRYPT_EAL_PkeyGetId(ctx);
    if (!isEcPkeyId(keyId)) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Decoded public key is not an EC key");
        return NULL;
    }

    int curveId = keyId == CRYPT_PKEY_SM2 ? CRYPT_ECC_SM2 : CRYPT_EAL_PkeyGetParaId(ctx);
    const char *curveName = getEcCurveNameById(curveId);
    int publicKeySize = getEcPublicKeySizeById(curveId);
    if (curveName == NULL || publicKeySize <= 0) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Decoded EC public key uses an unsupported curve");
        return NULL;
    }

    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(pubKey));
    pubKey.id = keyId;
    pubKey.key.eccPub.data = malloc((size_t)publicKeySize);
    pubKey.key.eccPub.len = (uint32_t)publicKeySize;
    if (pubKey.key.eccPub.data == NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate EC public key buffer");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyGetPub(ctx, &pubKey);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.eccPub.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to extract EC public key", ret);
        return NULL;
    }

    jobjectArray result = newByteArrayObjectArray(env, 2);
    if (result == NULL) {
        free(pubKey.key.eccPub.data);
        return NULL;
    }

    jbyteArray keyParts[2] = {
        newByteArrayFromData(env, (const uint8_t *)curveName, (uint32_t)strlen(curveName)),
        newByteArrayFromData(env, pubKey.key.eccPub.data, pubKey.key.eccPub.len)
    };
    if (!allByteArraysCreated(keyParts, 2)) {
        deleteLocalByteArrays(env, keyParts, 2);
        free(pubKey.key.eccPub.data);
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, keyParts[0]);
    (*env)->SetObjectArrayElement(env, result, 1, keyParts[1]);
    deleteLocalByteArrays(env, keyParts, 2);
    free(pubKey.key.eccPub.data);
    return result;
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecDecodePrivateKey
  (JNIEnv *env, jclass cls, jbyteArray jencodedKey) {
    if (jencodedKey == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Encoded EC private key cannot be null");
        return NULL;
    }

    uint32_t encodedLen = 0;
    uint8_t *encodedBytes = copyByteArrayWithTerminator(env, jencodedKey, &encodedLen,
        "Failed to copy encoded EC private key bytes");
    if (encodedBytes == NULL) {
        return NULL;
    }

    BSL_Buffer encoded = {encodedBytes, encodedLen};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encoded, NULL, 0, &ctx);
    secureZeroFree(encodedBytes, (size_t)encodedLen + 1);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to decode EC private key", ret);
        return NULL;
    }

    int keyId = CRYPT_EAL_PkeyGetId(ctx);
    if (!isEcPkeyId(keyId)) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Decoded private key is not an EC key");
        return NULL;
    }

    int curveId = keyId == CRYPT_PKEY_SM2 ? CRYPT_ECC_SM2 : CRYPT_EAL_PkeyGetParaId(ctx);
    const char *curveName = getEcCurveNameById(curveId);
    int privateKeySize = getEcPrivateKeySizeById(curveId);
    if (curveName == NULL || privateKeySize <= 0) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Decoded EC private key uses an unsupported curve");
        return NULL;
    }

    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(privKey));
    privKey.id = keyId;
    privKey.key.eccPrv.data = calloc(1, (size_t)privateKeySize);
    privKey.key.eccPrv.len = (uint32_t)privateKeySize;
    if (privKey.key.eccPrv.data == NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate EC private key buffer");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyGetPrv(ctx, &privKey);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        secureZeroFree(privKey.key.eccPrv.data, privKey.key.eccPrv.len);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to extract EC private key", ret);
        return NULL;
    }

    jobjectArray result = newByteArrayObjectArray(env, 2);
    if (result == NULL) {
        secureZeroFree(privKey.key.eccPrv.data, privKey.key.eccPrv.len);
        return NULL;
    }

    jbyteArray keyParts[2] = {
        newByteArrayFromData(env, (const uint8_t *)curveName, (uint32_t)strlen(curveName)),
        newByteArrayFromData(env, privKey.key.eccPrv.data, privKey.key.eccPrv.len)
    };
    if (!allByteArraysCreated(keyParts, 2)) {
        deleteLocalByteArrays(env, keyParts, 2);
        secureZeroFree(privKey.key.eccPrv.data, privKey.key.eccPrv.len);
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, keyParts[0]);
    (*env)->SetObjectArrayElement(env, result, 1, keyParts[1]);
    deleteLocalByteArrays(env, keyParts, 2);
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

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_ProviderCipherNewCtx(g_libCtx, algId, g_providerAttr);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create cipher context");
        return 0;
    }
    JByteArrayRef keyRef = {0};
    if (!getByteArrayRef(env, key, &keyRef, "Failed to get key bytes", true)) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        return 0;
    }

    jbyte *ivBytes = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        if (ivBytes == NULL) {
            releaseByteArrayRef(env, &keyRef, true);
            CRYPT_EAL_CipherFreeCtx(ctx);
            throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get IV bytes");
            return 0;
        }
        ivLen = (*env)->GetArrayLength(env, iv);
    }

    int result = CRYPT_EAL_CipherInit(ctx,
                                (const uint8_t *)keyRef.bytes,
                                keyRef.len,
                                ivBytes != NULL ? (const uint8_t *)ivBytes : NULL,
                                (uint32_t)ivLen,
                                mode == 1);

    if (result != CRYPT_SUCCESS) {
        if (ivBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        }
        releaseByteArrayRef(env, &keyRef, true);
        CRYPT_EAL_CipherFreeCtx(ctx);
        throwException(env, INVALID_KEY_EXCEPTION, "Failed to initialize cipher");
        return 0;
    }

    releaseByteArrayRef(env, &keyRef, true);
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
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(g_libCtx, CRYPT_PKEY_DSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, g_providerAttr);
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
        JByteArrayRef privKeyRef = {0};
        if (!getByteArrayRef(env, privateKey, &privKeyRef, "Failed to get private key", true)) {
            return;
        }
        privKey.key.dsaPrv.data = (uint8_t *)privKeyRef.bytes;
        privKey.key.dsaPrv.len = privKeyRef.len;

        int ret = CRYPT_EAL_PkeySetPrv(ctx, &privKey);
        releaseByteArrayRef(env, &privKeyRef, true);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set private key", ret);
            return;
        }
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaCreateContext
  (JNIEnv *env, jclass cls) {
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(g_libCtx, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, g_providerAttr);
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
        JByteArrayRef privKeyRef = {0};
        if (!getByteArrayRef(env, privateKey, &privKeyRef, "Failed to get private key bytes", true)) {
            if (releaseExponent) {
                (*env)->ReleaseByteArrayElements(env, publicExponent, (jbyte *)eBytes, JNI_ABORT);
            }
            return;
        }
        prv.key.rsaPrv.d = (uint8_t *)privKeyRef.bytes;
        prv.key.rsaPrv.dLen = privKeyRef.len;
        prv.key.rsaPrv.e = eBytes;
        prv.key.rsaPrv.eLen = eLen;

        // Get modulus from public key if available
        if (publicKey != NULL) {
            jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
            prv.key.rsaPrv.n = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
            if (prv.key.rsaPrv.n == NULL) {
                releaseByteArrayRef(env, &privKeyRef, true);
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
        releaseByteArrayRef(env, &privKeyRef, true);

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

static void releaseRsaPrivateEncodeRefs(JNIEnv *env, JByteArrayRef *modulus, JByteArrayRef *privateExponent,
    JByteArrayRef *publicExponent, JByteArrayRef *primeP, JByteArrayRef *primeQ,
    JByteArrayRef *primeExponentP, JByteArrayRef *primeExponentQ, JByteArrayRef *crtCoefficient)
{
    releaseByteArrayRef(env, modulus, false);
    releaseByteArrayRef(env, privateExponent, true);
    releaseByteArrayRef(env, publicExponent, false);
    releaseByteArrayRef(env, primeP, true);
    releaseByteArrayRef(env, primeQ, true);
    releaseByteArrayRef(env, primeExponentP, true);
    releaseByteArrayRef(env, primeExponentQ, true);
    releaseByteArrayRef(env, crtCoefficient, true);
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
        releaseRsaPrivateEncodeRefs(env, &modulus, &privateExponent, &publicExponent, &primeP, &primeQ,
            &primeExponentP, &primeExponentQ, &crtCoefficient);
        return NULL;
    }

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (ctx == NULL) {
        releaseRsaPrivateEncodeRefs(env, &modulus, &privateExponent, &publicExponent, &primeP, &primeQ,
            &primeExponentP, &primeExponentQ, &crtCoefficient);
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

    releaseRsaPrivateEncodeRefs(env, &modulus, &privateExponent, &publicExponent, &primeP, &primeQ,
        &primeExponentP, &primeExponentQ, &crtCoefficient);
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
    if (isRsaVerificationFailure(ret)) {
        return JNI_FALSE;
    }

    // Only throw exceptions for other errors that indicate real problems
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, "java/security/SignatureException", "Failed to verify signature", ret);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaSignDigest
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray digest, jstring digestAlgorithm) {
    if (nativeRef == 0 || digest == NULL || digestAlgorithm == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Invalid arguments");
        return NULL;
    }

    const char *algorithm = (*env)->GetStringUTFChars(env, digestAlgorithm, NULL);
    if (algorithm == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get digest algorithm");
        return NULL;
    }
    int hashAlg = getHashAlgorithmId(env, algorithm);
    (*env)->ReleaseStringUTFChars(env, digestAlgorithm, algorithm);
    if (hashAlg == -1) {
        return NULL;
    }

    JByteArrayRef digestRef = {0};
    if (!getByteArrayRef(env, digest, &digestRef, "Failed to get digest bytes", true)) {
        return NULL;
    }

    int32_t pkcsv15 = hashAlg;
    int ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)nativeRef,
        CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15));
    if (ret != CRYPT_SUCCESS) {
        releaseByteArrayRef(env, &digestRef, true);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA padding", ret);
        return NULL;
    }

    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen((CRYPT_EAL_PkeyCtx *)nativeRef);
    if (signLen == 0) {
        releaseByteArrayRef(env, &digestRef, true);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get signature length");
        return NULL;
    }

    uint8_t *signature = (uint8_t *)malloc(signLen);
    if (signature == NULL) {
        releaseByteArrayRef(env, &digestRef, true);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate memory for signature");
        return NULL;
    }

    ret = CRYPT_EAL_PkeySignData((CRYPT_EAL_PkeyCtx *)nativeRef,
        (const uint8_t *)digestRef.bytes, digestRef.len, signature, &signLen);
    releaseByteArrayRef(env, &digestRef, true);

    if (ret != CRYPT_SUCCESS) {
        free(signature);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to sign digest", ret);
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

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaVerifyDigest
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray digest, jbyteArray signature, jstring digestAlgorithm) {
    if (nativeRef == 0 || digest == NULL || signature == NULL || digestAlgorithm == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Invalid arguments");
        return JNI_FALSE;
    }

    const char *algorithm = (*env)->GetStringUTFChars(env, digestAlgorithm, NULL);
    if (algorithm == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get digest algorithm");
        return JNI_FALSE;
    }
    int hashAlg = getHashAlgorithmId(env, algorithm);
    (*env)->ReleaseStringUTFChars(env, digestAlgorithm, algorithm);
    if (hashAlg == -1) {
        return JNI_FALSE;
    }

    JByteArrayRef digestRef = {0};
    JByteArrayRef signatureRef = {0};
    if (!getByteArrayRef(env, digest, &digestRef, "Failed to get digest bytes", true) ||
            !getByteArrayRef(env, signature, &signatureRef, "Failed to get signature bytes", true)) {
        releaseByteArrayRef(env, &digestRef, true);
        releaseByteArrayRef(env, &signatureRef, false);
        return JNI_FALSE;
    }

    int32_t pkcsv15 = hashAlg;
    int ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)nativeRef,
        CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15));
    if (ret != CRYPT_SUCCESS) {
        releaseByteArrayRef(env, &digestRef, true);
        releaseByteArrayRef(env, &signatureRef, false);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA padding", ret);
        return JNI_FALSE;
    }

    ret = CRYPT_EAL_PkeyVerifyData((CRYPT_EAL_PkeyCtx *)nativeRef,
        (const uint8_t *)digestRef.bytes, digestRef.len,
        (const uint8_t *)signatureRef.bytes, signatureRef.len);

    releaseByteArrayRef(env, &digestRef, true);
    releaseByteArrayRef(env, &signatureRef, false);

    if (isRsaVerificationFailure(ret)) {
        return JNI_FALSE;
    }
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to verify digest signature", ret);
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

    int ret = configureRsaPss((CRYPT_EAL_PkeyCtx *)nativeRef, hashAlg, mgf1HashAlg, saltLength);
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

    int ret = configureRsaPss((CRYPT_EAL_PkeyCtx *)nativeRef, hashAlg, mgf1HashAlg, saltLength);
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

    if (isRsaVerificationFailure(ret)) {
        return JNI_FALSE;
    }
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to verify signature", ret);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaSignDigestPSS
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray digest, jstring digestAlgorithm,
   jstring mgf1Algorithm, jint saltLength, jint trailerField) {
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");
        return NULL;
    }
    if (digest == NULL || digestAlgorithm == NULL || mgf1Algorithm == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Input parameters cannot be null");
        return NULL;
    }
    const char* digestAlgStr = (*env)->GetStringUTFChars(env, digestAlgorithm, NULL);
    const char* mgf1AlgStr = (*env)->GetStringUTFChars(env, mgf1Algorithm, NULL);
    if (digestAlgStr == NULL || mgf1AlgStr == NULL) {
        if (digestAlgStr) (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        if (mgf1AlgStr) (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to get native resources");
        return NULL;
    }

    int hashAlg = getHashAlgorithmId(env, digestAlgStr);
    int mgf1HashAlg = getHashAlgorithmId(env, mgf1AlgStr);
    (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
    (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
    if (hashAlg == -1 || mgf1HashAlg == -1) {
        return NULL;
    }

    JByteArrayRef digestRef = {0};
    if (!getByteArrayRef(env, digest, &digestRef, "Failed to get digest bytes", true)) {
        return NULL;
    }

    int ret = configureRsaPss((CRYPT_EAL_PkeyCtx *)nativeRef, hashAlg, mgf1HashAlg, saltLength);
    if (ret != CRYPT_SUCCESS) {
        releaseByteArrayRef(env, &digestRef, true);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to set PSS parameters", ret);
        return NULL;
    }

    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen((CRYPT_EAL_PkeyCtx *)nativeRef);
    if (signLen == 0) {
        releaseByteArrayRef(env, &digestRef, true);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get signature length");
        return NULL;
    }

    uint8_t *signature = (uint8_t *)malloc(signLen);
    if (signature == NULL) {
        releaseByteArrayRef(env, &digestRef, true);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate memory for signature");
        return NULL;
    }

    ret = CRYPT_EAL_PkeySignData((CRYPT_EAL_PkeyCtx *)nativeRef,
        (const uint8_t *)digestRef.bytes, digestRef.len, signature, &signLen);
    releaseByteArrayRef(env, &digestRef, true);

    if (ret != CRYPT_SUCCESS) {
        free(signature);
        char errMsg[256];
        snprintf(errMsg, sizeof(errMsg), "Failed to sign digest (hash: %d, mgf1: %d, salt: %d)",
                hashAlg, mgf1HashAlg, saltLength);
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

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_rsaVerifyDigestPSS
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray digest, jbyteArray signature,
   jstring digestAlgorithm, jstring mgf1Algorithm, jint saltLength, jint trailerField) {
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");
        return JNI_FALSE;
    }
    if (digest == NULL || signature == NULL || digestAlgorithm == NULL || mgf1Algorithm == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Input parameters cannot be null");
        return JNI_FALSE;
    }
    const char* digestAlgStr = (*env)->GetStringUTFChars(env, digestAlgorithm, NULL);
    const char* mgf1AlgStr = (*env)->GetStringUTFChars(env, mgf1Algorithm, NULL);
    if (digestAlgStr == NULL || mgf1AlgStr == NULL) {
        if (digestAlgStr) (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
        if (mgf1AlgStr) (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to get native resources");
        return JNI_FALSE;
    }

    int hashAlg = getHashAlgorithmId(env, digestAlgStr);
    int mgf1HashAlg = getHashAlgorithmId(env, mgf1AlgStr);
    (*env)->ReleaseStringUTFChars(env, digestAlgorithm, digestAlgStr);
    (*env)->ReleaseStringUTFChars(env, mgf1Algorithm, mgf1AlgStr);
    if (hashAlg == -1 || mgf1HashAlg == -1) {
        return JNI_FALSE;
    }

    JByteArrayRef digestRef = {0};
    JByteArrayRef signatureRef = {0};
    if (!getByteArrayRef(env, digest, &digestRef, "Failed to get digest bytes", true) ||
            !getByteArrayRef(env, signature, &signatureRef, "Failed to get signature bytes", true)) {
        releaseByteArrayRef(env, &digestRef, true);
        releaseByteArrayRef(env, &signatureRef, false);
        return JNI_FALSE;
    }

    int ret = configureRsaPss((CRYPT_EAL_PkeyCtx *)nativeRef, hashAlg, mgf1HashAlg, saltLength);
    if (ret != CRYPT_SUCCESS) {
        releaseByteArrayRef(env, &digestRef, true);
        releaseByteArrayRef(env, &signatureRef, false);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to set PSS parameters", ret);
        return JNI_FALSE;
    }

    ret = CRYPT_EAL_PkeyVerifyData((CRYPT_EAL_PkeyCtx *)nativeRef,
        (const uint8_t *)digestRef.bytes, digestRef.len,
        (const uint8_t *)signatureRef.bytes, signatureRef.len);

    releaseByteArrayRef(env, &digestRef, true);
    releaseByteArrayRef(env, &signatureRef, false);

    if (isRsaVerificationFailure(ret)) {
        return JNI_FALSE;
    }
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to verify digest signature", ret);
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
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(g_libCtx, CRYPT_PKEY_ML_DSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, g_providerAttr);
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
        JByteArrayRef priKeyRef = {0};
        if (!getByteArrayRef(env, privateKey, &priKeyRef, "Failed to get private key", true)) {
            return;
        }
        priKey.key.mldsaPrv.data = (uint8_t *)priKeyRef.bytes;
        priKey.key.mldsaPrv.len = priKeyRef.len;

        ret = CRYPT_EAL_PkeySetPrv(pkey, &priKey);
        releaseByteArrayRef(env, &priKeyRef, true);
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
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(g_libCtx, CRYPT_PKEY_ML_KEM,
        CRYPT_EAL_PKEY_KEM_OPERATE, g_providerAttr);
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
        JByteArrayRef decapKeyRef = {0};
        if (!getByteArrayRef(env, jdecapKey, &decapKeyRef, "Failed to get decapsulate key", true)) {
            return;
        }
        privKey.key.kemDk.data = (uint8_t *)decapKeyRef.bytes;
        privKey.key.kemDk.len = decapKeyRef.len;

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        releaseByteArrayRef(env, &decapKeyRef, true);
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
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(g_libCtx, CRYPT_PKEY_SLH_DSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, g_providerAttr);
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
    JByteArrayRef dataRef = {0};
    if (!getByteArrayRef(env, additionalRandomness, &dataRef, "Failed to get additionalRandomness data", true)) {
        return;
    }

    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, (uint8_t *)dataRef.bytes, dataRef.len);
    releaseByteArrayRef(env, &dataRef, true);
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
    if (jparameterSet == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Parameter set cannot be null");
        return 0;
    }

    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get parameter set string");
        return 0;
    }
    int paramId = getFrodoKemParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported FrodoKEM parameter set");
        return 0;
    }

    int ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(g_libCtx, CRYPT_PKEY_FRODOKEM,
        CRYPT_EAL_PKEY_KEM_OPERATE, g_providerAttr);
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
    if (jparameterSet == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Parameter set cannot be null");
        return NULL;
    }
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid FrodoKEM context");
        return NULL;
    }

    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    int publicKeySize;
    int privateKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get parameter set string");
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
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid FrodoKEM context");
        return;
    }

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
        JByteArrayRef decapKeyRef = {0};
        if (!getByteArrayRef(env, jdecapKey, &decapKeyRef, "Failed to get decapsulate key data", true)) {
            return;
        }
        privKey.key.kemDk.data = (uint8_t *)decapKeyRef.bytes;
        privKey.key.kemDk.len = decapKeyRef.len;

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        releaseByteArrayRef(env, &decapKeyRef, true);
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
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid FrodoKEM context");
        return NULL;
    }

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
    if (jciphertext == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Ciphertext cannot be null");
        return NULL;
    }
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid FrodoKEM context");
        return NULL;
    }

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
    if (jparameterSet == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Parameter set cannot be null");
        return 0;
    }

    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get parameter set string");
        return 0;
    }
    int paramId = getMcElieceParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported Classic McEliece parameter set");
        return 0;
    }

    int ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(g_libCtx, CRYPT_PKEY_MCELIECE,
        CRYPT_EAL_PKEY_KEM_OPERATE, g_providerAttr);
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
    if (jparameterSet == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Parameter set cannot be null");
        return NULL;
    }
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid Classic McEliece context");
        return NULL;
    }

    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    int publicKeySize;
    int privateKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get parameter set string");
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
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid Classic McEliece context");
        return;
    }

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
        JByteArrayRef decapKeyRef = {0};
        if (!getByteArrayRef(env, jdecapKey, &decapKeyRef, "Failed to get decapsulate key data", true)) {
            return;
        }
        privKey.key.kemDk.data = (uint8_t *)decapKeyRef.bytes;
        privKey.key.kemDk.len = decapKeyRef.len;

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        releaseByteArrayRef(env, &decapKeyRef, true);
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
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid Classic McEliece context");
        return NULL;
    }

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
    if (jciphertext == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Ciphertext cannot be null");
        return NULL;
    }
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid Classic McEliece context");
        return NULL;
    }

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

/*
 * Provider management JNI functions
 */
JNIEXPORT void JNICALL Java_org_openhitls_crypto_jce_provider_ProviderConfig_loadProviderNative
  (JNIEnv *env, jclass cls, jstring jProviderPath, jstring jProviderName, jstring jAttrName) {
    (void)cls;

    const char *providerPath = (*env)->GetStringUTFChars(env, jProviderPath, NULL);
    const char *providerName = (*env)->GetStringUTFChars(env, jProviderName, NULL);
    const char *attrName = NULL;
    if (jAttrName != NULL) {
        attrName = (*env)->GetStringUTFChars(env, jAttrName, NULL);
    }

    if (providerPath == NULL || providerName == NULL || (jAttrName != NULL && attrName == NULL)) {
        if (providerPath != NULL) (*env)->ReleaseStringUTFChars(env, jProviderPath, providerPath);
        if (providerName != NULL) (*env)->ReleaseStringUTFChars(env, jProviderName, providerName);
        if (attrName != NULL) (*env)->ReleaseStringUTFChars(env, jAttrName, attrName);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to get string characters");
        return;
    }

    const char *providerAttr = NULL;
    if (attrName != NULL && attrName[0] != '\0') {
        providerAttr = attrName;
    }

    char *providerAttrCopy = NULL;
    if (providerAttr != NULL) {
        providerAttrCopy = strdup(providerAttr);
    } else {
        size_t providerAttrLen = strlen("provider=") + strlen(providerName) + 1;
        providerAttrCopy = malloc(providerAttrLen);
        if (providerAttrCopy != NULL) {
            snprintf(providerAttrCopy, providerAttrLen, "provider=%s", providerName);
        }
    }
    if (providerAttrCopy == NULL) {
        (*env)->ReleaseStringUTFChars(env, jProviderPath, providerPath);
        (*env)->ReleaseStringUTFChars(env, jProviderName, providerName);
        if (attrName != NULL) (*env)->ReleaseStringUTFChars(env, jAttrName, attrName);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate provider state");
        return;
    }

    CRYPT_EAL_LibCtx *newLibCtx = NULL;

    pthread_mutex_lock(&g_init_mutex);

    if (g_libCtx != NULL) {
        pthread_mutex_unlock(&g_init_mutex);
        free(providerAttrCopy);
        (*env)->ReleaseStringUTFChars(env, jProviderPath, providerPath);
        (*env)->ReleaseStringUTFChars(env, jProviderName, providerName);
        if (attrName != NULL) (*env)->ReleaseStringUTFChars(env, jAttrName, attrName);
        throwException(env, ILLEGAL_STATE_EXCEPTION,
            "An openHiTLS provider is already loaded; unload it before loading another provider");
        return;
    }

    // Provider selection is process-wide and cannot be replaced while active.
    newLibCtx = CRYPT_EAL_LibCtxNew();
    if (newLibCtx == NULL) {
        pthread_mutex_unlock(&g_init_mutex);
        free(providerAttrCopy);
        (*env)->ReleaseStringUTFChars(env, jProviderPath, providerPath);
        (*env)->ReleaseStringUTFChars(env, jProviderName, providerName);
        if (attrName != NULL) (*env)->ReleaseStringUTFChars(env, jAttrName, attrName);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create library context");
        return;
    }

    // Set provider search path
    int32_t ret = CRYPT_EAL_ProviderSetLoadPath(newLibCtx, providerPath);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_LibCtxFree(newLibCtx);
        pthread_mutex_unlock(&g_init_mutex);
        free(providerAttrCopy);
        (*env)->ReleaseStringUTFChars(env, jProviderPath, providerPath);
        (*env)->ReleaseStringUTFChars(env, jProviderName, providerName);
        if (attrName != NULL) (*env)->ReleaseStringUTFChars(env, jAttrName, attrName);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set provider load path", ret);
        return;
    }

    ret = CRYPT_EAL_ProviderLoad(newLibCtx, BSL_SAL_LIB_FMT_LIBSO, providerName, NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_LibCtxFree(newLibCtx);
        pthread_mutex_unlock(&g_init_mutex);
        free(providerAttrCopy);
        (*env)->ReleaseStringUTFChars(env, jProviderPath, providerPath);
        (*env)->ReleaseStringUTFChars(env, jProviderName, providerName);
        if (attrName != NULL) (*env)->ReleaseStringUTFChars(env, jAttrName, attrName);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to load provider", ret);
        return;
    }

    g_libCtx = newLibCtx;
    g_providerAttr = providerAttrCopy;

    if (attrName != NULL) {
        (*env)->ReleaseStringUTFChars(env, jAttrName, attrName);
    }

    pthread_mutex_unlock(&g_init_mutex);

    (*env)->ReleaseStringUTFChars(env, jProviderPath, providerPath);
    (*env)->ReleaseStringUTFChars(env, jProviderName, providerName);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_jce_provider_ProviderConfig_unloadProviderNative
  (JNIEnv *env, jclass cls) {
    (void)env;
    (void)cls;

    pthread_mutex_lock(&g_init_mutex);
    freeProviderStateNoLock();
    pthread_mutex_unlock(&g_init_mutex);
}

// ==================== Stateful hash-based signatures ====================

#ifndef CRYPT_LMS_SHA256_M32_H5
#define CRYPT_LMS_SHA256_M32_H5  0x00000005u
#define CRYPT_LMS_SHA256_M32_H10 0x00000006u
#define CRYPT_LMS_SHA256_M32_H15 0x00000007u
#define CRYPT_LMS_SHA256_M32_H20 0x00000008u
#define CRYPT_LMS_SHA256_M32_H25 0x00000009u
#endif

#ifndef CRYPT_LMOTS_SHA256_N32_W1
#define CRYPT_LMOTS_SHA256_N32_W1 0x00000001u
#define CRYPT_LMOTS_SHA256_N32_W2 0x00000002u
#define CRYPT_LMOTS_SHA256_N32_W4 0x00000003u
#define CRYPT_LMOTS_SHA256_N32_W8 0x00000004u
#endif

#define HBS_XMSS_PUB_BLOB_VERSION 1u
#define HBS_XMSS_PRV_BLOB_VERSION 1u
#define HBS_XMSS_PUB_HEADER_LEN 12u
#define HBS_XMSS_PRV_HEADER_LEN 20u

static int getLmsTypeId(const char *typeName) {
    if (typeName == NULL) {
        return -1;
    }
    if (strcmp(typeName, "CRYPT_LMS_SHA256_M32_H5") == 0) return CRYPT_LMS_SHA256_M32_H5;
    if (strcmp(typeName, "CRYPT_LMS_SHA256_M32_H10") == 0) return CRYPT_LMS_SHA256_M32_H10;
    if (strcmp(typeName, "CRYPT_LMS_SHA256_M32_H15") == 0) return CRYPT_LMS_SHA256_M32_H15;
    if (strcmp(typeName, "CRYPT_LMS_SHA256_M32_H20") == 0) return CRYPT_LMS_SHA256_M32_H20;
    if (strcmp(typeName, "CRYPT_LMS_SHA256_M32_H25") == 0) return CRYPT_LMS_SHA256_M32_H25;
    return -1;
}

static int getLmotsTypeId(const char *typeName) {
    if (typeName == NULL) {
        return -1;
    }
    if (strcmp(typeName, "CRYPT_LMOTS_SHA256_N32_W1") == 0) return CRYPT_LMOTS_SHA256_N32_W1;
    if (strcmp(typeName, "CRYPT_LMOTS_SHA256_N32_W2") == 0) return CRYPT_LMOTS_SHA256_N32_W2;
    if (strcmp(typeName, "CRYPT_LMOTS_SHA256_N32_W4") == 0) return CRYPT_LMOTS_SHA256_N32_W4;
    if (strcmp(typeName, "CRYPT_LMOTS_SHA256_N32_W8") == 0) return CRYPT_LMOTS_SHA256_N32_W8;
    return -1;
}

static int getXmssParamId(const char *parameterSet) {
    if (parameterSet == NULL) {
        return -1;
    }
    if (strcmp(parameterSet, "CRYPT_XMSS_SHA2_10_256") == 0) return CRYPT_XMSS_SHA2_10_256;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHA2_16_256") == 0) return CRYPT_XMSS_SHA2_16_256;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHA2_20_256") == 0) return CRYPT_XMSS_SHA2_20_256;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHA2_10_512") == 0) return CRYPT_XMSS_SHA2_10_512;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHA2_16_512") == 0) return CRYPT_XMSS_SHA2_16_512;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHA2_20_512") == 0) return CRYPT_XMSS_SHA2_20_512;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE_10_256") == 0) return CRYPT_XMSS_SHAKE_10_256;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE_16_256") == 0) return CRYPT_XMSS_SHAKE_16_256;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE_20_256") == 0) return CRYPT_XMSS_SHAKE_20_256;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE_10_512") == 0) return CRYPT_XMSS_SHAKE_10_512;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE_16_512") == 0) return CRYPT_XMSS_SHAKE_16_512;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE_20_512") == 0) return CRYPT_XMSS_SHAKE_20_512;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHA2_10_192") == 0) return CRYPT_XMSS_SHA2_10_192;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHA2_16_192") == 0) return CRYPT_XMSS_SHA2_16_192;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHA2_20_192") == 0) return CRYPT_XMSS_SHA2_20_192;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE256_10_256") == 0) return CRYPT_XMSS_SHAKE256_10_256;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE256_16_256") == 0) return CRYPT_XMSS_SHAKE256_16_256;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE256_20_256") == 0) return CRYPT_XMSS_SHAKE256_20_256;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE256_10_192") == 0) return CRYPT_XMSS_SHAKE256_10_192;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE256_16_192") == 0) return CRYPT_XMSS_SHAKE256_16_192;
    if (strcmp(parameterSet, "CRYPT_XMSS_SHAKE256_20_192") == 0) return CRYPT_XMSS_SHAKE256_20_192;
    return -1;
}

static int getXmssmtParamId(const char *parameterSet) {
    if (parameterSet == NULL) {
        return -1;
    }
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_20_2_256") == 0) return CRYPT_XMSSMT_SHA2_20_2_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_20_4_256") == 0) return CRYPT_XMSSMT_SHA2_20_4_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_40_2_256") == 0) return CRYPT_XMSSMT_SHA2_40_2_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_40_4_256") == 0) return CRYPT_XMSSMT_SHA2_40_4_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_40_8_256") == 0) return CRYPT_XMSSMT_SHA2_40_8_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_60_3_256") == 0) return CRYPT_XMSSMT_SHA2_60_3_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_60_6_256") == 0) return CRYPT_XMSSMT_SHA2_60_6_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_60_12_256") == 0) return CRYPT_XMSSMT_SHA2_60_12_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_20_2_512") == 0) return CRYPT_XMSSMT_SHA2_20_2_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_20_4_512") == 0) return CRYPT_XMSSMT_SHA2_20_4_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_40_2_512") == 0) return CRYPT_XMSSMT_SHA2_40_2_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_40_4_512") == 0) return CRYPT_XMSSMT_SHA2_40_4_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_40_8_512") == 0) return CRYPT_XMSSMT_SHA2_40_8_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_60_3_512") == 0) return CRYPT_XMSSMT_SHA2_60_3_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_60_6_512") == 0) return CRYPT_XMSSMT_SHA2_60_6_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_60_12_512") == 0) return CRYPT_XMSSMT_SHA2_60_12_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_20_2_256") == 0) return CRYPT_XMSSMT_SHAKE_20_2_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_20_4_256") == 0) return CRYPT_XMSSMT_SHAKE_20_4_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_40_2_256") == 0) return CRYPT_XMSSMT_SHAKE_40_2_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_40_4_256") == 0) return CRYPT_XMSSMT_SHAKE_40_4_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_40_8_256") == 0) return CRYPT_XMSSMT_SHAKE_40_8_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_60_3_256") == 0) return CRYPT_XMSSMT_SHAKE_60_3_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_60_6_256") == 0) return CRYPT_XMSSMT_SHAKE_60_6_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_60_12_256") == 0) return CRYPT_XMSSMT_SHAKE_60_12_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_20_2_512") == 0) return CRYPT_XMSSMT_SHAKE_20_2_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_20_4_512") == 0) return CRYPT_XMSSMT_SHAKE_20_4_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_40_2_512") == 0) return CRYPT_XMSSMT_SHAKE_40_2_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_40_4_512") == 0) return CRYPT_XMSSMT_SHAKE_40_4_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_40_8_512") == 0) return CRYPT_XMSSMT_SHAKE_40_8_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_60_3_512") == 0) return CRYPT_XMSSMT_SHAKE_60_3_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_60_6_512") == 0) return CRYPT_XMSSMT_SHAKE_60_6_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE_60_12_512") == 0) return CRYPT_XMSSMT_SHAKE_60_12_512;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_20_2_192") == 0) return CRYPT_XMSSMT_SHA2_20_2_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_20_4_192") == 0) return CRYPT_XMSSMT_SHA2_20_4_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_40_2_192") == 0) return CRYPT_XMSSMT_SHA2_40_2_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_40_4_192") == 0) return CRYPT_XMSSMT_SHA2_40_4_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_40_8_192") == 0) return CRYPT_XMSSMT_SHA2_40_8_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_60_3_192") == 0) return CRYPT_XMSSMT_SHA2_60_3_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_60_6_192") == 0) return CRYPT_XMSSMT_SHA2_60_6_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHA2_60_12_192") == 0) return CRYPT_XMSSMT_SHA2_60_12_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_20_2_256") == 0) return CRYPT_XMSSMT_SHAKE256_20_2_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_20_4_256") == 0) return CRYPT_XMSSMT_SHAKE256_20_4_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_40_2_256") == 0) return CRYPT_XMSSMT_SHAKE256_40_2_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_40_4_256") == 0) return CRYPT_XMSSMT_SHAKE256_40_4_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_40_8_256") == 0) return CRYPT_XMSSMT_SHAKE256_40_8_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_60_3_256") == 0) return CRYPT_XMSSMT_SHAKE256_60_3_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_60_6_256") == 0) return CRYPT_XMSSMT_SHAKE256_60_6_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_60_12_256") == 0) return CRYPT_XMSSMT_SHAKE256_60_12_256;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_20_2_192") == 0) return CRYPT_XMSSMT_SHAKE256_20_2_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_20_4_192") == 0) return CRYPT_XMSSMT_SHAKE256_20_4_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_40_2_192") == 0) return CRYPT_XMSSMT_SHAKE256_40_2_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_40_4_192") == 0) return CRYPT_XMSSMT_SHAKE256_40_4_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_40_8_192") == 0) return CRYPT_XMSSMT_SHAKE256_40_8_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_60_3_192") == 0) return CRYPT_XMSSMT_SHAKE256_60_3_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_60_6_192") == 0) return CRYPT_XMSSMT_SHAKE256_60_6_192;
    if (strcmp(parameterSet, "CRYPT_XMSSMT_SHAKE256_60_12_192") == 0) return CRYPT_XMSSMT_SHAKE256_60_12_192;
    return -1;
}

static void putUint32Be(uint8_t *buf, uint32_t value) {
    buf[0] = (uint8_t)(value >> 24);
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)value;
}

static uint32_t getUint32Be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}

static void putUint64Be(uint8_t *buf, uint64_t value) {
    for (int i = 7; i >= 0; i--) {
        buf[i] = (uint8_t)value;
        value >>= 8;
    }
}

static uint64_t getUint64Be(const uint8_t *buf) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | (uint64_t)buf[i];
    }
    return value;
}

static jbyteArray hbsNewByteArray(JNIEnv *env, const uint8_t *data, uint32_t dataLen) {
    jbyteArray array = (*env)->NewByteArray(env, (jsize)dataLen);
    if (array == NULL) {
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate byte array");
        return NULL;
    }
    if (dataLen > 0) {
        (*env)->SetByteArrayRegion(env, array, 0, (jsize)dataLen, (const jbyte *)data);
    }
    return array;
}

static jobjectArray hbsNewByteArrayPair(JNIEnv *env, jbyteArray first, jbyteArray second) {
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->FindClass(env, "[B"), NULL);
    if (result == NULL) {
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate result array");
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, result, 0, first);
    (*env)->SetObjectArrayElement(env, result, 1, second);
    return result;
}

static int configureHssLmsCtx(CRYPT_EAL_PkeyCtx *pkey, uint32_t levels,
    const uint32_t *lmsTypes, const uint32_t *otsTypes) {
    static const int32_t lmsKeys[] = {
        CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE,
        CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE,
        CRYPT_PARAM_HSS_LEVEL3_LMS_TYPE
    };
    static const int32_t otsKeys[] = {
        CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE,
        CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE,
        CRYPT_PARAM_HSS_LEVEL3_OTS_TYPE
    };
    if (levels < 1 || levels > 3) {
        return CRYPT_INVALID_ARG;
    }

    BSL_Param params[8] = {0};
    size_t pos = 0;
    params[pos++] = (BSL_Param){CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0};
    for (uint32_t i = 0; i < levels; i++) {
        params[pos++] = (BSL_Param){lmsKeys[i], BSL_PARAM_TYPE_UINT32, (void *)&lmsTypes[i], sizeof(lmsTypes[i]), 0};
        params[pos++] = (BSL_Param){otsKeys[i], BSL_PARAM_TYPE_UINT32, (void *)&otsTypes[i], sizeof(otsTypes[i]), 0};
    }
    return CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
}

static CRYPT_EAL_PkeyCtx *createHssLmsContext(JNIEnv *env, uint32_t levels,
    const uint32_t *lmsTypes, const uint32_t *otsTypes) {
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    if (pkey == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create HSS_LMS context");
        return NULL;
    }
    int ret = configureHssLmsCtx(pkey, levels, lmsTypes, otsTypes);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to configure HSS_LMS context", ret);
        return NULL;
    }
    return pkey;
}

static int setHssLmsPublicKey(CRYPT_EAL_PkeyCtx *pkey, const uint8_t *publicKey, uint32_t publicKeyLen) {
    BSL_Param keyParam[2] = {0};
    BSL_PARAM_InitValue(&keyParam[0], CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS,
        (void *)publicKey, publicKeyLen);
    return CRYPT_EAL_PkeySetPubEx(pkey, keyParam);
}

static int setHssLmsPublicKeyFromArray(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, jbyteArray publicKey) {
    JByteArrayRef keyRef = {0};
    if (!getByteArrayRef(env, publicKey, &keyRef, "Failed to get HSS public key bytes", true)) {
        return -1;
    }
    int ret = setHssLmsPublicKey(pkey, (const uint8_t *)keyRef.bytes, keyRef.len);
    releaseByteArrayRef(env, &keyRef, false);
    return ret;
}

static jboolean verifyHssLmsBuffers(CRYPT_EAL_PkeyCtx *pkey, const uint8_t *data, uint32_t dataLen,
    const uint8_t *signature, uint32_t signatureLen) {
    int ret = CRYPT_EAL_PkeyVerify(pkey, 0, data, dataLen, signature, signatureLen);
    return ret == CRYPT_SUCCESS ? JNI_TRUE : JNI_FALSE;
}

static jboolean verifyHssLmsArray(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, jbyteArray data, jbyteArray signature) {
    JByteArrayRef dataRef = {0};
    JByteArrayRef sigRef = {0};
    if (!getByteArrayRef(env, data, &dataRef, "Failed to get HSS input data", true)) {
        return JNI_FALSE;
    }
    if (!getByteArrayRef(env, signature, &sigRef, "Failed to get HSS signature data", true)) {
        releaseByteArrayRef(env, &dataRef, false);
        return JNI_FALSE;
    }
    jboolean result = verifyHssLmsBuffers(pkey, (const uint8_t *)dataRef.bytes, dataRef.len,
        (const uint8_t *)sigRef.bytes, sigRef.len);
    releaseByteArrayRef(env, &sigRef, false);
    releaseByteArrayRef(env, &dataRef, false);
    return result;
}

static int readHssTypeArray(JNIEnv *env, jobjectArray names, uint32_t *types, bool lmsTypes) {
    if (names == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "HSS parameter array cannot be null");
        return -1;
    }
    jsize levels = (*env)->GetArrayLength(env, names);
    if (levels < 1 || levels > 3) {
        throwException(env, INVALID_ALGORITHM_PARAMETER_EXCEPTION, "HSS supports 1 to 3 levels");
        return -1;
    }
    for (jsize i = 0; i < levels; i++) {
        jstring item = (jstring)(*env)->GetObjectArrayElement(env, names, i);
        if (item == NULL) {
            throwException(env, INVALID_ALGORITHM_PARAMETER_EXCEPTION, "HSS parameter cannot be null");
            return -1;
        }
        const char *name = (*env)->GetStringUTFChars(env, item, NULL);
        if (name == NULL) {
            (*env)->DeleteLocalRef(env, item);
            throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get HSS parameter string");
            return -1;
        }
        int type = lmsTypes ? getLmsTypeId(name) : getLmotsTypeId(name);
        (*env)->ReleaseStringUTFChars(env, item, name);
        (*env)->DeleteLocalRef(env, item);
        if (type < 0) {
            throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported HSS parameter set");
            return -1;
        }
        types[i] = (uint32_t)type;
    }
    return levels;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_lmsCreateContext
  (JNIEnv *env, jclass cls, jstring jlmsType, jstring jotsType) {
    (void)cls;
    const char *lmsTypeName = (*env)->GetStringUTFChars(env, jlmsType, NULL);
    const char *otsTypeName = (*env)->GetStringUTFChars(env, jotsType, NULL);
    if (lmsTypeName == NULL || otsTypeName == NULL) {
        if (lmsTypeName != NULL) (*env)->ReleaseStringUTFChars(env, jlmsType, lmsTypeName);
        if (otsTypeName != NULL) (*env)->ReleaseStringUTFChars(env, jotsType, otsTypeName);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get LMS parameter strings");
        return 0;
    }
    int lmsType = getLmsTypeId(lmsTypeName);
    int otsType = getLmotsTypeId(otsTypeName);
    (*env)->ReleaseStringUTFChars(env, jlmsType, lmsTypeName);
    (*env)->ReleaseStringUTFChars(env, jotsType, otsTypeName);
    if (lmsType < 0 || otsType < 0) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported LMS parameter set");
        return 0;
    }
    uint32_t lmsTypes[1] = {(uint32_t)lmsType};
    uint32_t otsTypes[1] = {(uint32_t)otsType};
    return (jlong)createHssLmsContext(env, 1, lmsTypes, otsTypes);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_lmsSetPublicKey
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey) {
    (void)cls;
    JByteArrayRef keyRef = {0};
    if (!getByteArrayRef(env, publicKey, &keyRef, "Failed to get LMS public key bytes", true)) {
        return;
    }
    uint32_t wrappedLen = keyRef.len + 4;
    uint8_t *wrapped = malloc(wrappedLen);
    if (wrapped == NULL) {
        releaseByteArrayRef(env, &keyRef, false);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate LMS public key wrapper");
        return;
    }
    putUint32Be(wrapped, 1);
    memcpy(wrapped + 4, keyRef.bytes, keyRef.len);
    int ret = setHssLmsPublicKey((CRYPT_EAL_PkeyCtx *)nativeRef, wrapped, wrappedLen);
    free(wrapped);
    releaseByteArrayRef(env, &keyRef, false);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, INVALID_KEY_EXCEPTION, "Failed to set LMS public key", ret);
    }
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_lmsVerify
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature) {
    (void)cls;
    JByteArrayRef dataRef = {0};
    JByteArrayRef sigRef = {0};
    if (!getByteArrayRef(env, data, &dataRef, "Failed to get LMS input data", true)) {
        return JNI_FALSE;
    }
    if (!getByteArrayRef(env, signature, &sigRef, "Failed to get LMS signature data", true)) {
        releaseByteArrayRef(env, &dataRef, false);
        return JNI_FALSE;
    }
    uint32_t wrappedLen = sigRef.len + 4;
    uint8_t *wrapped = malloc(wrappedLen);
    if (wrapped == NULL) {
        releaseByteArrayRef(env, &sigRef, false);
        releaseByteArrayRef(env, &dataRef, false);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate LMS signature wrapper");
        return JNI_FALSE;
    }
    putUint32Be(wrapped, 0);
    memcpy(wrapped + 4, sigRef.bytes, sigRef.len);
    jboolean result = verifyHssLmsBuffers((CRYPT_EAL_PkeyCtx *)nativeRef,
        (const uint8_t *)dataRef.bytes, dataRef.len, wrapped, wrappedLen);
    free(wrapped);
    releaseByteArrayRef(env, &sigRef, false);
    releaseByteArrayRef(env, &dataRef, false);
    return result;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_lmsFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    (void)env;
    (void)cls;
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyFreeCtx((CRYPT_EAL_PkeyCtx *)nativeRef);
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_hssCreateContext
  (JNIEnv *env, jclass cls, jobjectArray jlmsTypes, jobjectArray jotsTypes) {
    (void)cls;
    uint32_t lmsTypes[3] = {0};
    uint32_t otsTypes[3] = {0};
    int levels = readHssTypeArray(env, jlmsTypes, lmsTypes, true);
    if (levels < 0) {
        return 0;
    }
    int otsLevels = readHssTypeArray(env, jotsTypes, otsTypes, false);
    if (otsLevels < 0) {
        return 0;
    }
    if (levels != otsLevels) {
        throwException(env, INVALID_ALGORITHM_PARAMETER_EXCEPTION, "HSS LMS and OTS parameter counts differ");
        return 0;
    }
    return (jlong)createHssLmsContext(env, (uint32_t)levels, lmsTypes, otsTypes);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_hssSetPublicKey
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey) {
    (void)cls;
    int ret = setHssLmsPublicKeyFromArray(env, (CRYPT_EAL_PkeyCtx *)nativeRef, publicKey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, INVALID_KEY_EXCEPTION, "Failed to set HSS public key", ret);
    }
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_hssVerify
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature) {
    (void)cls;
    return verifyHssLmsArray(env, (CRYPT_EAL_PkeyCtx *)nativeRef, data, signature);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_hssFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    (void)env;
    (void)cls;
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyFreeCtx((CRYPT_EAL_PkeyCtx *)nativeRef);
    }
}

static CRYPT_EAL_PkeyCtx *createXmssLikeContext(JNIEnv *env, jstring jparameterSet,
    CRYPT_PKEY_AlgId algId, int (*paramResolver)(const char *), const char *name) {
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get parameter set string");
        return NULL;
    }
    int paramId = paramResolver(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId < 0) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported parameter set");
        return NULL;
    }
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(algId);
    if (pkey == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create XMSS context");
        return NULL;
    }
    int ret = CRYPT_EAL_PkeySetParaById(pkey, paramId);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        char message[128];
        snprintf(message, sizeof(message), "Failed to configure %s context", name);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, message, ret);
        return NULL;
    }
    return pkey;
}

static int getXmssLikeKeyLen(CRYPT_EAL_PkeyCtx *pkey, uint32_t *n) {
    uint32_t pubLen = 0;
    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (pubLen < 4 || ((pubLen - 4) % 2) != 0) {
        return -1;
    }
    *n = (pubLen - 4) / 2;
    return CRYPT_SUCCESS;
}

static jbyteArray encodeXmssLikePublicKey(JNIEnv *env, uint32_t paramId, const CRYPT_XmssPub *pub) {
    uint32_t outLen = HBS_XMSS_PUB_HEADER_LEN + 2 * pub->len;
    uint8_t *out = malloc(outLen);
    if (out == NULL) {
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate XMSS public key buffer");
        return NULL;
    }
    putUint32Be(out, HBS_XMSS_PUB_BLOB_VERSION);
    putUint32Be(out + 4, paramId);
    putUint32Be(out + 8, pub->len);
    memcpy(out + HBS_XMSS_PUB_HEADER_LEN, pub->seed, pub->len);
    memcpy(out + HBS_XMSS_PUB_HEADER_LEN + pub->len, pub->root, pub->len);
    jbyteArray result = hbsNewByteArray(env, out, outLen);
    free(out);
    return result;
}

static jbyteArray encodeXmssLikePrivateKey(JNIEnv *env, uint32_t paramId, const CRYPT_XmssPrv *prv) {
    uint32_t n = prv->pub.len;
    uint32_t outLen = HBS_XMSS_PRV_HEADER_LEN + 4 * n;
    uint8_t *out = malloc(outLen);
    if (out == NULL) {
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate XMSS private key buffer");
        return NULL;
    }
    putUint32Be(out, HBS_XMSS_PRV_BLOB_VERSION);
    putUint32Be(out + 4, paramId);
    putUint32Be(out + 8, n);
    putUint64Be(out + 12, prv->index);
    memcpy(out + HBS_XMSS_PRV_HEADER_LEN, prv->seed, n);
    memcpy(out + HBS_XMSS_PRV_HEADER_LEN + n, prv->prf, n);
    memcpy(out + HBS_XMSS_PRV_HEADER_LEN + 2 * n, prv->pub.seed, n);
    memcpy(out + HBS_XMSS_PRV_HEADER_LEN + 3 * n, prv->pub.root, n);
    jbyteArray result = hbsNewByteArray(env, out, outLen);
    secureZeroFree(out, outLen);
    return result;
}

static int getXmssLikeParamIdFromCtx(CRYPT_EAL_PkeyCtx *pkey, uint32_t *paramId) {
    int32_t paraId = 0;
    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *paramId = (uint32_t)paraId;
    return CRYPT_SUCCESS;
}

static int ensureXmssLikeParamId(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, uint32_t paramId) {
    uint32_t currentParamId = 0;
    int ret = getXmssLikeParamIdFromCtx(pkey, &currentParamId);
    if (ret == CRYPT_SUCCESS) {
        if (currentParamId != paramId) {
            throwException(env, INVALID_KEY_EXCEPTION, "XMSS key parameter set does not match context");
            return -1;
        }
        return CRYPT_SUCCESS;
    }
    if (ret != CRYPT_XMSS_KEYINFO_NOT_SET) {
        return ret;
    }
    return CRYPT_EAL_PkeySetParaById(pkey, (int32_t)paramId);
}

static int validateXmssLikeBlobKeyLen(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, uint32_t n) {
    uint32_t expectedN = 0;
    int ret = getXmssLikeKeyLen(pkey, &expectedN);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, INVALID_KEY_EXCEPTION, "Failed to get XMSS parameter key length", ret);
        return ret;
    }
    if (n != expectedN) {
        throwException(env, INVALID_KEY_EXCEPTION, "XMSS key length does not match parameter set");
        return -1;
    }
    return CRYPT_SUCCESS;
}

static int exportXmssLikePublic(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_AlgId algId,
    uint32_t paramId, jbyteArray *outArray) {
    uint32_t n = 0;
    int ret = getXmssLikeKeyLen(pkey, &n);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get XMSS key length", ret);
        return ret;
    }
    CRYPT_EAL_PkeyPub pub;
    memset(&pub, 0, sizeof(pub));
    pub.id = algId;
    pub.key.xmssPub.seed = malloc(n);
    pub.key.xmssPub.root = malloc(n);
    pub.key.xmssPub.len = n;
    if (pub.key.xmssPub.seed == NULL || pub.key.xmssPub.root == NULL) {
        free(pub.key.xmssPub.seed);
        free(pub.key.xmssPub.root);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate XMSS public key");
        return -1;
    }
    ret = CRYPT_EAL_PkeyGetPub(pkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        free(pub.key.xmssPub.seed);
        free(pub.key.xmssPub.root);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to export XMSS public key", ret);
        return ret;
    }
    *outArray = encodeXmssLikePublicKey(env, paramId, &pub.key.xmssPub);
    free(pub.key.xmssPub.seed);
    free(pub.key.xmssPub.root);
    return *outArray == NULL ? -1 : CRYPT_SUCCESS;
}

static int exportXmssLikePrivate(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_AlgId algId,
    uint32_t paramId, jbyteArray *outArray) {
    uint32_t n = 0;
    int ret = getXmssLikeKeyLen(pkey, &n);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get XMSS key length", ret);
        return ret;
    }
    CRYPT_EAL_PkeyPrv prv;
    memset(&prv, 0, sizeof(prv));
    prv.id = algId;
    prv.key.xmssPrv.seed = malloc(n);
    prv.key.xmssPrv.prf = malloc(n);
    prv.key.xmssPrv.pub.seed = malloc(n);
    prv.key.xmssPrv.pub.root = malloc(n);
    prv.key.xmssPrv.pub.len = n;
    if (prv.key.xmssPrv.seed == NULL || prv.key.xmssPrv.prf == NULL ||
        prv.key.xmssPrv.pub.seed == NULL || prv.key.xmssPrv.pub.root == NULL) {
        secureZeroFree(prv.key.xmssPrv.seed, n);
        secureZeroFree(prv.key.xmssPrv.prf, n);
        secureZeroFree(prv.key.xmssPrv.pub.seed, n);
        secureZeroFree(prv.key.xmssPrv.pub.root, n);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate XMSS private key");
        return -1;
    }
    ret = CRYPT_EAL_PkeyGetPrv(pkey, &prv);
    if (ret != CRYPT_SUCCESS) {
        secureZeroFree(prv.key.xmssPrv.seed, n);
        secureZeroFree(prv.key.xmssPrv.prf, n);
        secureZeroFree(prv.key.xmssPrv.pub.seed, n);
        secureZeroFree(prv.key.xmssPrv.pub.root, n);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to export XMSS private key", ret);
        return ret;
    }
    *outArray = encodeXmssLikePrivateKey(env, paramId, &prv.key.xmssPrv);
    secureZeroFree(prv.key.xmssPrv.seed, n);
    secureZeroFree(prv.key.xmssPrv.prf, n);
    secureZeroFree(prv.key.xmssPrv.pub.seed, n);
    secureZeroFree(prv.key.xmssPrv.pub.root, n);
    return *outArray == NULL ? -1 : CRYPT_SUCCESS;
}

static int importXmssLikePublic(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_AlgId algId, jbyteArray publicKey) {
    jsize keyLen = (*env)->GetArrayLength(env, publicKey);
    if (keyLen < (jsize)HBS_XMSS_PUB_HEADER_LEN) {
        throwException(env, INVALID_KEY_EXCEPTION, "XMSS public key blob is too short");
        return -1;
    }
    jbyte *keyData = (*env)->GetByteArrayElements(env, publicKey, NULL);
    if (keyData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get XMSS public key bytes");
        return -1;
    }
    uint8_t *bytes = (uint8_t *)keyData;
    uint32_t version = getUint32Be(bytes);
    uint32_t paramId = getUint32Be(bytes + 4);
    uint32_t n = getUint32Be(bytes + 8);
    uint64_t expectedLen = (uint64_t)HBS_XMSS_PUB_HEADER_LEN + 2ULL * (uint64_t)n;
    if (version != HBS_XMSS_PUB_BLOB_VERSION || n == 0 || expectedLen != (uint64_t)keyLen) {
        (*env)->ReleaseByteArrayElements(env, publicKey, keyData, JNI_ABORT);
        throwException(env, INVALID_KEY_EXCEPTION, "Invalid XMSS public key blob");
        return -1;
    }
    int ret = ensureXmssLikeParamId(env, pkey, paramId);
    if (ret == CRYPT_SUCCESS) {
        ret = validateXmssLikeBlobKeyLen(env, pkey, n);
    }
    if (ret == CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyPub pub;
        memset(&pub, 0, sizeof(pub));
        pub.id = algId;
        pub.key.xmssPub.seed = bytes + HBS_XMSS_PUB_HEADER_LEN;
        pub.key.xmssPub.root = bytes + HBS_XMSS_PUB_HEADER_LEN + n;
        pub.key.xmssPub.len = n;
        ret = CRYPT_EAL_PkeySetPub(pkey, &pub);
    }
    (*env)->ReleaseByteArrayElements(env, publicKey, keyData, JNI_ABORT);
    return ret;
}

static int importXmssLikePrivate(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_AlgId algId, jbyteArray privateKey) {
    jsize keyLen = (*env)->GetArrayLength(env, privateKey);
    if (keyLen < (jsize)HBS_XMSS_PRV_HEADER_LEN) {
        throwException(env, INVALID_KEY_EXCEPTION, "XMSS private key blob is too short");
        return -1;
    }
    JByteArrayRef keyRef = {0};
    if (!getByteArrayRef(env, privateKey, &keyRef, "Failed to get XMSS private key bytes", true)) {
        return -1;
    }
    uint8_t *bytes = (uint8_t *)keyRef.bytes;
    uint32_t version = getUint32Be(bytes);
    uint32_t paramId = getUint32Be(bytes + 4);
    uint32_t n = getUint32Be(bytes + 8);
    uint64_t expectedLen = (uint64_t)HBS_XMSS_PRV_HEADER_LEN + 4ULL * (uint64_t)n;
    if (version != HBS_XMSS_PRV_BLOB_VERSION || n == 0 || expectedLen != (uint64_t)keyLen) {
        releaseByteArrayRef(env, &keyRef, true);
        throwException(env, INVALID_KEY_EXCEPTION, "Invalid XMSS private key blob");
        return -1;
    }
    int ret = ensureXmssLikeParamId(env, pkey, paramId);
    if (ret == CRYPT_SUCCESS) {
        ret = validateXmssLikeBlobKeyLen(env, pkey, n);
    }
    if (ret == CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyPrv prv;
        memset(&prv, 0, sizeof(prv));
        prv.id = algId;
        prv.key.xmssPrv.index = getUint64Be(bytes + 12);
        prv.key.xmssPrv.seed = bytes + HBS_XMSS_PRV_HEADER_LEN;
        prv.key.xmssPrv.prf = bytes + HBS_XMSS_PRV_HEADER_LEN + n;
        prv.key.xmssPrv.pub.seed = bytes + HBS_XMSS_PRV_HEADER_LEN + 2 * n;
        prv.key.xmssPrv.pub.root = bytes + HBS_XMSS_PRV_HEADER_LEN + 3 * n;
        prv.key.xmssPrv.pub.len = n;
        ret = CRYPT_EAL_PkeySetPrv(pkey, &prv);
    }
    releaseByteArrayRef(env, &keyRef, true);
    return ret;
}

static jobjectArray xmssLikeGenerateKeyPair(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_AlgId algId) {
    int ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate XMSS key pair", ret);
        return NULL;
    }
    uint32_t paramId = 0;
    ret = getXmssLikeParamIdFromCtx(pkey, &paramId);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get XMSS parameter ID", ret);
        return NULL;
    }
    jbyteArray publicKey = NULL;
    jbyteArray privateKey = NULL;
    if (exportXmssLikePublic(env, pkey, algId, paramId, &publicKey) != CRYPT_SUCCESS) {
        return NULL;
    }
    if (exportXmssLikePrivate(env, pkey, algId, paramId, &privateKey) != CRYPT_SUCCESS) {
        return NULL;
    }
    return hbsNewByteArrayPair(env, publicKey, privateKey);
}

static jobjectArray xmssLikeSignAndExportState(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_AlgId algId,
    jbyteArray data) {
    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return NULL;
    }
    uint32_t signLen = 0;
    int ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SIGNLEN, &signLen, sizeof(signLen));
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get XMSS signature length", ret);
        return NULL;
    }
    uint8_t *signBuf = malloc(signLen);
    if (signBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, OUT_OF_MEMORY_ERROR, "Failed to allocate XMSS signature buffer");
        return NULL;
    }
    ret = CRYPT_EAL_PkeySign(pkey, 0, (uint8_t *)inputData, (uint32_t)(*env)->GetArrayLength(env, data),
        signBuf, &signLen);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
    if (ret != CRYPT_SUCCESS) {
        free(signBuf);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to sign data", ret);
        return NULL;
    }
    jbyteArray signature = hbsNewByteArray(env, signBuf, signLen);
    free(signBuf);
    if (signature == NULL) {
        return NULL;
    }
    uint32_t paramId = 0;
    ret = getXmssLikeParamIdFromCtx(pkey, &paramId);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get XMSS parameter ID", ret);
        return NULL;
    }
    jbyteArray privateKey = NULL;
    if (exportXmssLikePrivate(env, pkey, algId, paramId, &privateKey) != CRYPT_SUCCESS) {
        return NULL;
    }
    return hbsNewByteArrayPair(env, signature, privateKey);
}

static jboolean xmssLikeVerify(JNIEnv *env, CRYPT_EAL_PkeyCtx *pkey, jbyteArray data, jbyteArray signature) {
    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return JNI_FALSE;
    }
    jbyte *signData = (*env)->GetByteArrayElements(env, signature, NULL);
    if (signData == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get signature data");
        return JNI_FALSE;
    }
    int ret = CRYPT_EAL_PkeyVerify(pkey, 0,
        (uint8_t *)inputData, (uint32_t)(*env)->GetArrayLength(env, data),
        (uint8_t *)signData, (uint32_t)(*env)->GetArrayLength(env, signature));
    (*env)->ReleaseByteArrayElements(env, signature, signData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
    return ret == CRYPT_SUCCESS ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssCreateContext
  (JNIEnv *env, jclass cls, jstring jparameterSet) {
    CRYPT_EAL_PkeyCtx *pkey = createXmssLikeContext(env, jparameterSet, CRYPT_PKEY_XMSS, getXmssParamId, "XMSS");
    return (jlong)pkey;
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    return xmssLikeGenerateKeyPair(env, (CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_PKEY_XMSS);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssSetPublicKey
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey) {
    int ret = importXmssLikePublic(env, (CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_PKEY_XMSS, publicKey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, INVALID_KEY_EXCEPTION, "Failed to set XMSS public key", ret);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssSetPrivateKey
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray privateKey) {
    int ret = importXmssLikePrivate(env, (CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_PKEY_XMSS, privateKey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, INVALID_KEY_EXCEPTION, "Failed to set XMSS private key", ret);
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssSignAndExportState
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data) {
    return xmssLikeSignAndExportState(env, (CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_PKEY_XMSS, data);
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssVerify
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature) {
    return xmssLikeVerify(env, (CRYPT_EAL_PkeyCtx *)nativeRef, data, signature);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyFreeCtx((CRYPT_EAL_PkeyCtx *)nativeRef);
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssmtCreateContext
  (JNIEnv *env, jclass cls, jstring jparameterSet) {
    CRYPT_EAL_PkeyCtx *pkey = createXmssLikeContext(env, jparameterSet, CRYPT_PKEY_XMSSMT, getXmssmtParamId, "XMSSMT");
    return (jlong)pkey;
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssmtGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    return xmssLikeGenerateKeyPair(env, (CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_PKEY_XMSSMT);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssmtSetPublicKey
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey) {
    int ret = importXmssLikePublic(env, (CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_PKEY_XMSSMT, publicKey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, INVALID_KEY_EXCEPTION, "Failed to set XMSSMT public key", ret);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssmtSetPrivateKey
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray privateKey) {
    int ret = importXmssLikePrivate(env, (CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_PKEY_XMSSMT, privateKey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, INVALID_KEY_EXCEPTION, "Failed to set XMSSMT private key", ret);
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssmtSignAndExportState
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data) {
    return xmssLikeSignAndExportState(env, (CRYPT_EAL_PkeyCtx *)nativeRef, CRYPT_PKEY_XMSSMT, data);
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssmtVerify
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature) {
    return xmssLikeVerify(env, (CRYPT_EAL_PkeyCtx *)nativeRef, data, signature);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_xmssmtFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyFreeCtx((CRYPT_EAL_PkeyCtx *)nativeRef);
    }
}
