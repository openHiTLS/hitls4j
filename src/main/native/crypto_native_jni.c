#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <crypto/crypt_errno.h>
#include <crypto/crypt_algid.h>
#include <crypto/crypt_eal_provider.h>
#include <crypto/crypt_eal_pkey.h>
#include <crypto/crypt_eal_cipher.h>
#include <crypto/crypt_eal_mac.h>
#include <crypto/crypt_eal_md.h>
#include <crypto/crypt_errno.h>
#include <crypto/crypt_eal_rand.h>
#include <crypto/crypt_params_key.h>
#include <bsl/bsl_sal.h>
#include <bsl/bsl_err.h>
#include <bsl/bsl_err.h>
#include <bsl/bsl_sal.h>
#include <pthread.h>
#include <org_openhitls_crypto_core_CryptoNative.h>


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

static void bslInit() {
    BSL_ERR_Init();
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
}

static void initBSL() {
    static uint32_t onceControl = 0;
    BSL_SAL_ThreadRunOnce(&onceControl, bslInit);
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestInit
  (JNIEnv *env, jclass cls, jstring jalgorithm) {
    initBSL();

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
    initBSL();

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

static void ecdsaRandInit() {
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
}

static void ecdsaInitRand(JNIEnv *env) {
    static uint32_t onceControl = 0;
    BSL_SAL_ThreadRunOnce(&onceControl, ecdsaRandInit);
    
    uint8_t testBuf[32];
    int ret = CRYPT_EAL_Randbytes(testBuf, sizeof(testBuf));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate random number", ret);
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
        default:
            return CRYPT_MD_SHA256; // Default to SHA256
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaCreateContext
  (JNIEnv *env, jclass cls, jstring jcurveName) {
    initBSL();
    ecdsaInitRand(env);

    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
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
        free(privKey.key.eccPrv.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.eccPub.len);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.eccPrv.len);
    if (pubKeyArray == NULL || privKeyArray == NULL) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create key arrays");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.eccPub.len, (jbyte *)pubKey.key.eccPub.data);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.eccPrv.len, (jbyte *)privKey.key.eccPrv.data);

    // Create array of byte arrays to return both keys
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, pubKeyArray), NULL);
    if (result == NULL) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, pubKeyArray);
    (*env)->SetObjectArrayElement(env, result, 1, privKeyArray);

    free(pubKey.key.eccPub.data);
    free(privKey.key.eccPrv.data);

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
    initBSL();

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
        char errMsg[256];
        throwException(env, ILLEGAL_STATE_EXCEPTION, errMsg);
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
    initBSL();
    ecdsaInitRand(env);

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
        free(privKey.key.dsaPrv.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get DSA private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.dsaPub.len);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.dsaPrv.len);
    
    if (pubKeyArray == NULL || privKeyArray == NULL) {
        free(pubKey.key.dsaPub.data);
        free(privKey.key.dsaPrv.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create key arrays");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.dsaPub.len, (jbyte *)pubKey.key.dsaPub.data);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.dsaPrv.len, (jbyte *)privKey.key.dsaPrv.data);

    // Create array of byte arrays to return both keys
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, pubKeyArray), NULL);
    if (result == NULL) {
        free(pubKey.key.dsaPub.data);
        free(privKey.key.dsaPrv.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, pubKeyArray);
    (*env)->SetObjectArrayElement(env, result, 1, privKeyArray);

    free(pubKey.key.dsaPub.data);
    free(privKey.key.dsaPrv.data);

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
    initBSL();

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
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey, jbyteArray privateKey) {
    if (nativeRef == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid RSA context");
        return;
    }

    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;

    // Set the public key if provided
    if (publicKey != NULL) {
        CRYPT_EAL_PkeyPub pub;
        memset(&pub, 0, sizeof(CRYPT_EAL_PkeyPub));
        pub.id = CRYPT_PKEY_RSA;
        jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
        pub.key.rsaPub.n = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
        if (pub.key.rsaPub.n == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get public key bytes");
            return;
        }
        pub.key.rsaPub.nLen = pubKeyLen;

        // Set up public exponent (65537)
        uint8_t e[3] = {0x01, 0x00, 0x01};  // 65537 in big-endian
        pub.key.rsaPub.e = e;
        pub.key.rsaPub.eLen = sizeof(e);

        int ret = CRYPT_EAL_PkeySetPub(ctx, &pub);
        (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)pub.key.rsaPub.n, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
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
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get private key bytes");
            return;
        }
        prv.key.rsaPrv.dLen = privKeyLen;

        // Set up public exponent (65537)
        uint8_t e[3] = {0x01, 0x00, 0x01};  // 65537 in big-endian
        prv.key.rsaPrv.e = e;
        prv.key.rsaPrv.eLen = sizeof(e);

        // Get modulus from public key if available
        if (publicKey != NULL) {
            jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
            prv.key.rsaPrv.n = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
            if (prv.key.rsaPrv.n == NULL) {
                (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)prv.key.rsaPrv.d, JNI_ABORT);
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
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set RSA private key", ret);
            return;
        }
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
    if (privKey.key.rsaPrv.d == NULL || privKey.key.rsaPrv.n == NULL) {
        free(pubKey.key.rsaPub.n);
        free(pubKey.key.rsaPub.e);
        if (privKey.key.rsaPrv.d) free(privKey.key.rsaPrv.d);
        if (privKey.key.rsaPrv.n) free(privKey.key.rsaPrv.n);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for private key");
        return NULL;
    }
    privKey.key.rsaPrv.dLen = keyBytes;
    privKey.key.rsaPrv.nLen = keyBytes;

    ret = CRYPT_EAL_PkeyGetPrv(ctx, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.rsaPub.n);
        free(pubKey.key.rsaPub.e);
        free(privKey.key.rsaPrv.d);
        free(privKey.key.rsaPrv.n);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get RSA private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.rsaPub.nLen);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.rsaPrv.dLen);
    if (pubKeyArray == NULL || privKeyArray == NULL) {
        free(pubKey.key.rsaPub.n);
        free(pubKey.key.rsaPub.e);
        free(privKey.key.rsaPrv.d);
        free(privKey.key.rsaPrv.n);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create key arrays");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.rsaPub.nLen, (jbyte *)pubKey.key.rsaPub.n);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.rsaPrv.dLen, (jbyte *)privKey.key.rsaPrv.d);

    // Create array of byte arrays to return both keys
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, pubKeyArray), NULL);
    if (result == NULL) {
        free(pubKey.key.rsaPub.n);
        free(pubKey.key.rsaPub.e);
        free(privKey.key.rsaPrv.d);
        free(privKey.key.rsaPrv.n);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, pubKeyArray);
    (*env)->SetObjectArrayElement(env, result, 1, privKeyArray);

    free(pubKey.key.rsaPub.n);
    free(pubKey.key.rsaPub.e);
    free(privKey.key.rsaPrv.d);
    free(privKey.key.rsaPrv.n);

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