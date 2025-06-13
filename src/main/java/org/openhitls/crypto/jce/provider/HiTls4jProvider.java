package org.openhitls.crypto.jce.provider;

import org.openhitls.crypto.jce.cipher.SM4Cipher;
import org.openhitls.crypto.jce.cipher.AESCipher;
import org.openhitls.crypto.jce.cipher.RSACipher;
import java.security.Provider;
import org.openhitls.crypto.jce.key.generator.ECKeyPairGenerator;
import org.openhitls.crypto.jce.key.factory.ECKeyFactory;
import org.openhitls.crypto.jce.cipher.SM2Cipher;
import org.openhitls.crypto.jce.param.ECParameters;
import org.openhitls.crypto.jce.signer.ECDSASigner;
import org.openhitls.crypto.jce.key.generator.SymmetricCipherKeyGenerator;

public final class HiTls4jProvider extends Provider {
    public static final String PROVIDER_NAME = "HITLS4J";
    public static final double VERSION = 1.0;
    public static final String INFO = "HiTls4j Cryptographic Provider v1.0";

    public static class SM4CipherImpl extends SM4Cipher {
        public SM4CipherImpl() {
            super();
        }
    }

    public static class AESCipherImpl extends AESCipher {
        public AESCipherImpl() {
            super();
        }
    }

    public static class RSACipherImpl extends RSACipher {
        public RSACipherImpl() {
            super();
        }
    }

    static {
        // Load native libraries
        NativeLoader.load();
    }

    public HiTls4jProvider() {
        super(PROVIDER_NAME, VERSION, INFO);
        
        // Register symmetric ciphers
        put("Cipher.SM4", SM4CipherImpl.class.getName());
        put("Cipher.SM4 SupportedModes", "ECB|CBC|CTR|GCM|CFB|OFB|XTS");
        put("Cipher.SM4 SupportedPaddings", "NOPADDING|PKCS5PADDING|PKCS7PADDING|ZEROSPADDING|ISO7816PADDING|X923PADDING");
        put("Cipher.AES", AESCipherImpl.class.getName());
        put("Cipher.AES SupportedModes", "ECB|CBC|CTR|GCM");
        put("Cipher.AES SupportedPaddings", "NOPADDING|PKCS5PADDING|PKCS7PADDING|ZEROSPADDING|ISO7816PADDING|X923PADDING");

        // Register RSA cipher
        put("Cipher.RSA", RSACipherImpl.class.getName());
        put("Cipher.RSA SupportedModes", "ECB");
        put("Cipher.RSA SupportedPaddings", "PKCS1PADDING|NOPADDING");

        // Register RSA cipher transformations
        put("Cipher.RSA/ECB/PKCS1PADDING", RSACipherImpl.class.getName());
        put("Cipher.RSA/ECB/NOPADDING", RSACipherImpl.class.getName());

        // DSA functionality
        put("KeyPairGenerator.DSA", "org.openhitls.crypto.jce.key.generator.DSAKeyPairGenerator");
        put("Signature.DSA", "org.openhitls.crypto.jce.signer.DSASigner");
        put("Signature.SHA1withDSA", "org.openhitls.crypto.jce.signer.DSASigner");
        put("Signature.SHA224withDSA", "org.openhitls.crypto.jce.signer.DSASigner");
        put("Signature.SHA256withDSA", "org.openhitls.crypto.jce.signer.DSASigner");
        put("Signature.SHA384withDSA", "org.openhitls.crypto.jce.signer.DSASigner");
        put("Signature.SHA512withDSA", "org.openhitls.crypto.jce.signer.DSASigner");
        put("AlgorithmParameters.DSA", "org.openhitls.crypto.jce.param.DSAParameters");

        // RSA functionality
        put("KeyPairGenerator.RSA", "org.openhitls.crypto.jce.key.generator.RSAKeyPairGenerator");
        put("Signature.SHA224withRSA", "org.openhitls.crypto.jce.signer.RSASigner$SHA224withRSA");
        put("Signature.SHA256withRSA", "org.openhitls.crypto.jce.signer.RSASigner$SHA256withRSA");
        put("Signature.SHA384withRSA", "org.openhitls.crypto.jce.signer.RSASigner$SHA384withRSA");
        put("Signature.SHA512withRSA", "org.openhitls.crypto.jce.signer.RSASigner$SHA512withRSA");
        put("Signature.SM3withRSA", "org.openhitls.crypto.jce.signer.RSASigner$SM3withRSA");

        // RSA PSS Signatures
        put("Signature.SHA224withRSA/PSS", "org.openhitls.crypto.jce.signer.RSASigner$SHA224withRSAPSS");
        put("Signature.SHA256withRSA/PSS", "org.openhitls.crypto.jce.signer.RSASigner$SHA256withRSAPSS");
        put("Signature.SHA384withRSA/PSS", "org.openhitls.crypto.jce.signer.RSASigner$SHA384withRSAPSS");
        put("Signature.SHA512withRSA/PSS", "org.openhitls.crypto.jce.signer.RSASigner$SHA512withRSAPSS");
        put("Signature.SM3withRSA/PSS", "org.openhitls.crypto.jce.signer.RSASigner$SM3withRSAPSS");

        put("AlgorithmParameters.RSA", "org.openhitls.crypto.jce.param.RSAParameters");

        put("Cipher.SM2", SM2Cipher.class.getName());
        put("KeyPairGenerator.EC", ECKeyPairGenerator.class.getName());
        put("KeyFactory.EC", ECKeyFactory.class.getName());
        put("Signature.EC", ECDSASigner.class.getName());
        put("AlgorithmParameters.EC", ECParameters.class.getName());
        put("AlgorithmParameterGenerator.EC", "sun.security.ec.ECParameterGenerator");
        put("KeyAgreement.EC", "sun.security.ec.ECDHKeyAgreement");

                // Register specific transformations
        // ECB mode
        put("Cipher.AES/ECB/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/ECB/NOPADDING");
        put("Cipher.AES/ECB/PKCS5PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/ECB/PKCS5PADDING");
        put("Cipher.AES/ECB/PKCS7PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/ECB/PKCS7PADDING");
        put("Cipher.AES/ECB/ZEROSPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/ECB/ZEROSPADDING");
        put("Cipher.AES/ECB/ISO7816PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/ECB/ISO7816PADDING");
        put("Cipher.AES/ECB/X923PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/ECB/X923PADDING");
        
        // CBC mode
        put("Cipher.AES/CBC/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/CBC/NOPADDING");
        put("Cipher.AES/CBC/PKCS5PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/CBC/PKCS5PADDING");
        put("Cipher.AES/CBC/PKCS7PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/CBC/PKCS7PADDING");
        put("Cipher.AES/CBC/ZEROSPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/CBC/ZEROSPADDING");
        put("Cipher.AES/CBC/ISO7816PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/CBC/ISO7816PADDING");
        put("Cipher.AES/CBC/X923PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/CBC/X923PADDING");

        // CTR mode (stream cipher, no padding needed)
        put("Cipher.AES/CTR/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/CTR/NOPADDING");

        // GCM mode (authenticated encryption)
        put("Cipher.AES/GCM/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$AESCipherOidImpl AES/GCM/NOPADDING");


        // Register specific transformations
        // ECB mode
        put("Cipher.SM4/ECB/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/NOPADDING");
        put("Cipher.SM4/ECB/PKCS5PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/PKCS5PADDING");
        put("Cipher.SM4/ECB/PKCS7PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/PKCS7PADDING");
        put("Cipher.SM4/ECB/ZEROSPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/ZEROSPADDING");
        put("Cipher.SM4/ECB/ISO7816PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/ISO7816PADDING");
        put("Cipher.SM4/ECB/X923PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/X923PADDING");
        
        // CBC mode
        put("Cipher.SM4/CBC/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/NOPADDING");
        put("Cipher.SM4/CBC/PKCS5PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/PKCS5PADDING");
        put("Cipher.SM4/CBC/PKCS7PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/PKCS7PADDING");
        put("Cipher.SM4/CBC/ZEROSPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/ZEROSPADDING");
        put("Cipher.SM4/CBC/ISO7816PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/ISO7816PADDING");
        put("Cipher.SM4/CBC/X923PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/X923PADDING");

        // CTR mode (stream cipher, no padding needed)
        put("Cipher.SM4/CTR/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CTR/NOPADDING");

        // GCM mode (authenticated encryption)
        put("Cipher.SM4/GCM/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/GCM/NOPADDING");

        // CFB mode (stream cipher)
        put("Cipher.SM4/CFB/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CFB/NOPADDING");

        // OFB mode (stream cipher)
        put("Cipher.SM4/OFB/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/OFB/NOPADDING");

        // XTS mode
        put("Cipher.SM4/XTS/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/XTS/NOPADDING");

        // Register message digests
        put("MessageDigest.SHA-1", "org.openhitls.crypto.jce.digest.MessageDigest$SHA1");
        put("MessageDigest.SHA-224", "org.openhitls.crypto.jce.digest.MessageDigest$SHA224");
        put("MessageDigest.SHA-256", "org.openhitls.crypto.jce.digest.MessageDigest$SHA256");
        put("MessageDigest.SHA-384", "org.openhitls.crypto.jce.digest.MessageDigest$SHA384");
        put("MessageDigest.SHA-512", "org.openhitls.crypto.jce.digest.MessageDigest$SHA512");
        put("MessageDigest.SHA3-224", "org.openhitls.crypto.jce.digest.MessageDigest$SHA3_224");
        put("MessageDigest.SHA3-256", "org.openhitls.crypto.jce.digest.MessageDigest$SHA3_256");
        put("MessageDigest.SHA3-384", "org.openhitls.crypto.jce.digest.MessageDigest$SHA3_384");
        put("MessageDigest.SHA3-512", "org.openhitls.crypto.jce.digest.MessageDigest$SHA3_512");
        put("MessageDigest.SM3", "org.openhitls.crypto.jce.digest.MessageDigest$SM3");
        
        // Register algorithm aliases
        put("Alg.Alias.MessageDigest.SHA224", "SHA-224");
        put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
        put("Alg.Alias.MessageDigest.SHA512", "SHA-512");

        // Register HMAC implementations
        put("Mac.HMACSHA1", "org.openhitls.crypto.jce.mac.HMAC$HMACSHA1");
        put("Mac.HMACSHA224", "org.openhitls.crypto.jce.mac.HMAC$HMACSHA224");
        put("Mac.HMACSHA256", "org.openhitls.crypto.jce.mac.HMAC$HMACSHA256");
        put("Mac.HMACSHA384", "org.openhitls.crypto.jce.mac.HMAC$HMACSHA384");
        put("Mac.HMACSHA512", "org.openhitls.crypto.jce.mac.HMAC$HMACSHA512");
        put("Mac.HMACSHA3-224", "org.openhitls.crypto.jce.mac.HMAC$HMACSHA3_224");
        put("Mac.HMACSHA3-256", "org.openhitls.crypto.jce.mac.HMAC$HMACSHA3_256");
        put("Mac.HMACSHA3-384", "org.openhitls.crypto.jce.mac.HMAC$HMACSHA3_384");
        put("Mac.HMACSHA3-512", "org.openhitls.crypto.jce.mac.HMAC$HMACSHA3_512");
        put("Mac.HMACSM3", "org.openhitls.crypto.jce.mac.HMAC$HMACSM3");

        // Register HMAC algorithm aliases
        put("Alg.Alias.Mac.HMAC-SHA1", "HMACSHA1");
        put("Alg.Alias.Mac.HMAC-SHA224", "HMACSHA224");
        put("Alg.Alias.Mac.HMAC-SHA256", "HMACSHA256");
        put("Alg.Alias.Mac.HMAC-SHA384", "HMACSHA384");
        put("Alg.Alias.Mac.HMAC-SHA512", "HMACSHA512");
        put("Alg.Alias.Mac.HMAC-SHA3-224", "HMACSHA3-224");
        put("Alg.Alias.Mac.HMAC-SHA3-256", "HMACSHA3-256");
        put("Alg.Alias.Mac.HMAC-SHA3-384", "HMACSHA3-384");
        put("Alg.Alias.Mac.HMAC-SHA3-512", "HMACSHA3-512");
        put("Alg.Alias.Mac.HMAC-SM3", "HMACSM3");

        // Register SM4 key generator
        put("KeyGenerator.AES", SymmetricCipherKeyGenerator.class.getName());

        // Register ECDSA signature algorithms
        put("Signature.SHA256withECDSA", "org.openhitls.crypto.jce.signer.ECDSASigner$SHA256withECDSA");
        put("Signature.SHA384withECDSA", "org.openhitls.crypto.jce.signer.ECDSASigner$SHA384withECDSA");
        put("Signature.SHA512withECDSA", "org.openhitls.crypto.jce.signer.ECDSASigner$SHA512withECDSA");
        put("Signature.SM3withSM2", "org.openhitls.crypto.jce.signer.ECDSASigner$SM3withSM2");

        // Register supported curves
        put("Alg.Alias.Curve.P-256", "secp256r1");
        put("Alg.Alias.Curve.P-384", "secp384r1");
        put("Alg.Alias.Curve.P-521", "secp521r1");
        put("Alg.Alias.Curve.SM2", "sm2p256v1");
    }
}