package org.openhitls.crypto.jce.key.factory;

import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.jce.key.ECKeyCodec;
import org.openhitls.crypto.jce.key.ECPrivateKey;
import org.openhitls.crypto.jce.key.ECPublicKey;
import org.openhitls.crypto.jce.util.ECCurveRegistry;
import org.openhitls.crypto.jce.util.ECKeyEncoding;

public class ECKeyFactory extends KeyFactorySpi {
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("Key specification cannot be null");
        }
        try {
            if (keySpec instanceof X509EncodedKeySpec) {
                DecodedPublicKey decoded = decodeX509PublicKey(((X509EncodedKeySpec) keySpec).getEncoded());
                ensureSupported(decoded.params);
                validatePublicKey(decoded.w, decoded.params);
                return new ECPublicKey(decoded.w, decoded.params, getAlgorithmName());
            } else if (keySpec instanceof ECPublicKeySpec) {
                ECPublicKeySpec ecSpec = (ECPublicKeySpec) keySpec;
                ECParameterSpec params = ecSpec.getParams();
                ensureSupported(params);

                validatePublicKey(ecSpec.getW(), params);
                return new ECPublicKey(ecSpec.getW(), params, getAlgorithmName());
            }
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
        
        throw new InvalidKeySpecException("Unsupported key specification: " + 
            keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("Key specification cannot be null");
        }
        try {
            if (keySpec instanceof PKCS8EncodedKeySpec) {
                DecodedPrivateKey decoded = decodePkcs8PrivateKey(((PKCS8EncodedKeySpec) keySpec).getEncoded());
                ensureSupported(decoded.params);
                return new ECPrivateKey(decoded.s, decoded.params, getAlgorithmName());
            } else if (keySpec instanceof ECPrivateKeySpec) {
                ECPrivateKeySpec ecSpec = (ECPrivateKeySpec) keySpec;
                ECParameterSpec params = ecSpec.getParams();
                ensureSupported(params);

                return new ECPrivateKey(ecSpec.getS(), params, getAlgorithmName());
            }
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
        
        throw new InvalidKeySpecException("Unsupported key specification: " + 
            keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }
        if (keySpec == null) {
            throw new InvalidKeySpecException("Key specification cannot be null");
        }
        if (key instanceof ECPublicKey) {
            ECPublicKey sm2Key = (ECPublicKey)key;

            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                ECParameterSpec params = sm2Key.getParams();
                ensureSupported(params);
                return keySpec.cast(new X509EncodedKeySpec(encodePublicKeySpec(sm2Key, params)));
            }

            if (keySpec.isAssignableFrom(ECPublicKeySpec.class)) {
                ECParameterSpec params = sm2Key.getParams();
                ensureSupported(params);

                return keySpec.cast(new ECPublicKeySpec(sm2Key.getW(), params));
            }
        } else if (key instanceof ECPrivateKey) {
            ECPrivateKey sm2Key = (ECPrivateKey)key;

            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                ECParameterSpec params = sm2Key.getParams();
                ensureSupported(params);
                return keySpec.cast(new PKCS8EncodedKeySpec(encodePrivateKeySpec(sm2Key, params)));
            }

            if (keySpec.isAssignableFrom(ECPrivateKeySpec.class)) {
                ECParameterSpec params = sm2Key.getParams();
                ensureSupported(params);

                return keySpec.cast(new ECPrivateKeySpec(sm2Key.getS(), params));
            }
        }

        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("EC key cannot be null");
        }
        try {
            if (key instanceof java.security.interfaces.ECPublicKey) {
                java.security.interfaces.ECPublicKey ecKey = (java.security.interfaces.ECPublicKey) key;
                ECParameterSpec params = ecKey.getParams();
                ensureSupported(params);
                validatePublicKey(ecKey.getW(), params);
                return new ECPublicKey(ecKey.getW(), params, getAlgorithmName());
            }
            if (key instanceof java.security.interfaces.ECPrivateKey) {
                java.security.interfaces.ECPrivateKey ecKey = (java.security.interfaces.ECPrivateKey) key;
                ECParameterSpec params = ecKey.getParams();
                ensureSupported(params);
                return new ECPrivateKey(ecKey.getS(), params, getAlgorithmName());
            }
        } catch (InvalidKeySpecException | RuntimeException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
        
        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }

    protected String getAlgorithmName() {
        return "EC";
    }

    protected boolean isCurveSupported(String curveName) {
        return ECCurveRegistry.isNistCurve(curveName) || ECCurveRegistry.isSM2Curve(curveName);
    }

    private void ensureSupported(ECParameterSpec params) throws InvalidKeySpecException {
        String curveName = getCurveName(params);
        if (!isCurveSupported(curveName)) {
            throw new InvalidKeySpecException(
                    "Unsupported curve for " + getAlgorithmName() + ": " + curveName);
        }
    }

    private String getCurveName(ECParameterSpec params) throws InvalidKeySpecException {
        if (params == null) {
            throw new InvalidKeySpecException("Key parameters cannot be null");
        }

        try {
            return ECKeyEncoding.getCurveName(params);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
    }

    private void validatePublicKey(ECPoint point, ECParameterSpec params) throws InvalidKeySpecException {
        byte[] encoded = ECKeyEncoding.encodePublicPoint(point, params);
        String curveName = getCurveName(params);
        long nativeContext = 0;
        try {
            nativeContext = CryptoNative.ecdsaCreateContext(curveName);
            CryptoNative.ecdsaSetKeys(nativeContext, curveName, encoded, null);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Invalid EC public key", e);
        } finally {
            if (nativeContext != 0) {
                CryptoNative.ecdsaFreeContext(nativeContext);
            }
        }
    }

    private static byte[] encodePublicKeySpec(ECPublicKey key, ECParameterSpec params)
            throws InvalidKeySpecException {
        try {
            return ECKeyCodec.encodePublic(key.getW(), params);
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException("EC public key cannot be X.509 encoded", e);
        }
    }

    private static byte[] encodePrivateKeySpec(ECPrivateKey key, ECParameterSpec params)
            throws InvalidKeySpecException {
        try {
            return ECKeyCodec.encodePrivate(key.getS(), params);
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException("EC private key cannot be PKCS#8 encoded", e);
        }
    }

    private static DecodedPublicKey decodeX509PublicKey(byte[] encoded) throws InvalidKeySpecException {
        try {
            ECKeyCodec.DecodedPublicKey decoded = ECKeyCodec.decodePublic(encoded);
            ECParameterSpec params = ECCurveRegistry.getNamedCurve(decoded.getCurveName());
            return new DecodedPublicKey(ECKeyEncoding.decodePublicPoint(decoded.getPublicKey(), params), params);
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException("Invalid X.509 EC public key", e);
        }
    }

    private static DecodedPrivateKey decodePkcs8PrivateKey(byte[] encoded) throws InvalidKeySpecException {
        try {
            ECKeyCodec.DecodedPrivateKey decoded = ECKeyCodec.decodePrivate(encoded);
            ECParameterSpec params = ECCurveRegistry.getNamedCurve(decoded.getCurveName());
            return new DecodedPrivateKey(decoded.getPrivateValue(), params);
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException("Invalid PKCS#8 EC private key", e);
        }
    }

    private static boolean isNistCurve(String curveName) {
        return ECCurveRegistry.isNistCurve(curveName);
    }

    private static boolean isSM2Curve(String curveName) {
        return ECCurveRegistry.isSM2Curve(curveName);
    }

    public static final class ECDSA extends ECKeyFactory {
        @Override
        protected String getAlgorithmName() {
            return "ECDSA";
        }

        @Override
        protected boolean isCurveSupported(String curveName) {
            return isNistCurve(curveName);
        }
    }

    public static final class SM2 extends ECKeyFactory {
        @Override
        protected String getAlgorithmName() {
            return "SM2";
        }

        @Override
        protected boolean isCurveSupported(String curveName) {
            return isSM2Curve(curveName);
        }
    }

    private static final class DecodedPublicKey {
        private final ECPoint w;
        private final ECParameterSpec params;

        private DecodedPublicKey(ECPoint w, ECParameterSpec params) {
            this.w = w;
            this.params = params;
        }
    }

    private static final class DecodedPrivateKey {
        private final BigInteger s;
        private final ECParameterSpec params;

        private DecodedPrivateKey(BigInteger s, ECParameterSpec params) {
            this.s = s;
            this.params = params;
        }
    }
}
