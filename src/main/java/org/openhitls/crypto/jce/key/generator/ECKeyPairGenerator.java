package org.openhitls.crypto.jce.key.generator;

import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import org.openhitls.crypto.jce.key.ECPublicKey;
import org.openhitls.crypto.jce.key.ECPrivateKey;
import org.openhitls.crypto.jce.util.ECCurveRegistry;
import org.openhitls.crypto.jce.util.ECKeyEncoding;
import org.openhitls.crypto.core.asymmetric.ECDSAImpl;

public class ECKeyPairGenerator extends KeyPairGeneratorSpi {
    private ECParameterSpec params;
    private String curveName;

    @Override
    public void initialize(int keySize, SecureRandom random) {
        try {
            String curve = getDefaultCurveName(keySize);
            initialize(new ECGenParameterSpec(curve), random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("Parameters cannot be null");
        }

        ECParameterSpec resolvedParams;
        String resolvedCurveName;
        if (params instanceof ECParameterSpec) {
            resolvedParams = (ECParameterSpec) params;
            resolvedCurveName = getCurveName(resolvedParams);
        } else if (params instanceof ECGenParameterSpec) {
            resolvedParams = getNamedCurveSpec((ECGenParameterSpec) params);
            resolvedCurveName = getCurveName(resolvedParams);
        } else {
            throw new InvalidAlgorithmParameterException("Only ECParameterSpec and ECGenParameterSpec are supported");
        }

        if (!isCurveSupported(resolvedCurveName)) {
            throw new InvalidAlgorithmParameterException(
                    "Unsupported curve for " + getAlgorithmName() + ": " + resolvedCurveName);
        }

        this.params = resolvedParams;
        this.curveName = resolvedCurveName;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (params == null) {
            throw new IllegalStateException("ECParameterSpec not initialized");
        }
        try (ECDSAImpl ecdsaImpl = new ECDSAImpl(curveName)) {
            byte[] publicKey = ecdsaImpl.getPublicKey();
            byte[] privateKey = ecdsaImpl.getPrivateKey();

            try {
                return new KeyPair(
                    new ECPublicKey(publicKey, params, getAlgorithmName()),
                    new ECPrivateKey(privateKey, params, getAlgorithmName())
                );
            } finally {
                if (privateKey != null) {
                    Arrays.fill(privateKey, (byte) 0);
                }
            }
        }
    }

    protected String getAlgorithmName() {
        return "EC";
    }

    protected boolean isCurveSupported(String curveName) {
        return isNistCurve(curveName) || isSM2Curve(curveName);
    }

    protected String getDefaultCurveName(int keySize) {
        switch (keySize) {
            case 256:
                return "secp256r1";
            case 384:
                return "secp384r1";
            case 521:
                return "secp521r1";
            default:
                throw new InvalidParameterException("Unsupported key size: " + keySize);
        }
    }

    private ECParameterSpec getNamedCurveSpec(ECGenParameterSpec params)
            throws InvalidAlgorithmParameterException {
        String name = params.getName();
        if (name == null) {
            throw new InvalidAlgorithmParameterException("Curve name cannot be null");
        }

        try {
            return ECCurveRegistry.getNamedCurve(name);
        } catch (IllegalArgumentException e) {
            throw new InvalidAlgorithmParameterException("Unsupported curve: " + name);
        }
    }

    private String getCurveName(ECParameterSpec params) throws InvalidAlgorithmParameterException {
        try {
            return ECKeyEncoding.getCurveName(params);
        } catch (InvalidKeySpecException | RuntimeException e) {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
    }

    private static boolean isNistCurve(String curveName) {
        return ECCurveRegistry.isNistCurve(curveName);
    }

    private static boolean isSM2Curve(String curveName) {
        return ECCurveRegistry.isSM2Curve(curveName);
    }

    public static final class ECDSA extends ECKeyPairGenerator {
        @Override
        protected String getAlgorithmName() {
            return "ECDSA";
        }

        @Override
        protected boolean isCurveSupported(String curveName) {
            return isNistCurve(curveName);
        }
    }

    public static final class SM2 extends ECKeyPairGenerator {
        @Override
        protected String getAlgorithmName() {
            return "SM2";
        }

        @Override
        protected boolean isCurveSupported(String curveName) {
            return isSM2Curve(curveName);
        }

        @Override
        protected String getDefaultCurveName(int keySize) {
            if (keySize == 256) {
                return "sm2p256v1";
            }
            throw new InvalidParameterException("Unsupported key size for SM2: " + keySize);
        }
    }
}
