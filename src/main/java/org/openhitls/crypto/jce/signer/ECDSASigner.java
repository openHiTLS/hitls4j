package org.openhitls.crypto.jce.signer;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.asymmetric.ECDSAImpl;
import org.openhitls.crypto.jce.spec.SM2ParameterSpec;
import org.openhitls.crypto.jce.util.ECCurveRegistry;
import org.openhitls.crypto.jce.util.ECKeyEncoding;
import org.openhitls.crypto.core.CryptoConstants;

public class ECDSASigner extends SignatureSpi {
    private ECDSAImpl ecdsaImpl;
    private byte[] buffer;
    private final SignatureState state = new SignatureState();
    private byte[] userId;
    private final int algorithm;
    private final boolean sm2Signature;

    public ECDSASigner(String algorithmName) {
        this(algorithmName, "SM3".equals(algorithmName));
    }

    private ECDSASigner(String algorithmName, boolean sm2Signature) {
        this.algorithm = getHashAlgorithm(algorithmName);
        this.sm2Signature = sm2Signature;
    }

    // Inner classes for different signature algorithms
    public static final class SHA256withECDSA extends ECDSASigner {
        public SHA256withECDSA() {
            super("SHA256", false);
        }
    }

    public static final class SHA384withECDSA extends ECDSASigner {
        public SHA384withECDSA() {
            super("SHA384", false);
        }
    }

    public static final class SHA512withECDSA extends ECDSASigner {
        public SHA512withECDSA() {
            super("SHA512", false);
        }
    }

    public static final class SM3withSM2 extends ECDSASigner {
        public SM3withSM2() {
            super("SM3", true);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new InvalidKeyException("Key must implement ECPublicKey");
        }
        try {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            ECParameterSpec params = ecPublicKey.getParams();
            String curveName = getCurveName(params);
            ensureCurveAllowed(curveName);
            ECDSAImpl newImpl = new ECDSAImpl(
                    curveName,
                    algorithm,
                    ECKeyEncoding.encodePublicPoint(ecPublicKey.getW(), params),
                    null);
            try {
                if (userId != null) {
                    newImpl.setUserId(userId);
                }
                commitImpl(newImpl, false);
                newImpl = null;
            } catch (InvalidKeyException | RuntimeException e) {
                NativeResourceUtil.closeSuppressing(newImpl, e);
                throw e;
            }
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize ECDSA", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) 
            throws InvalidKeyException {
        if (!(privateKey instanceof ECPrivateKey)) {
            throw new InvalidKeyException("Key must implement ECPrivateKey");
        }
        try {
            ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
            ECParameterSpec params = ecPrivateKey.getParams();
            String curveName = getCurveName(params);
            ensureCurveAllowed(curveName);
            byte[] encodedPrivate = ECKeyEncoding.encodePrivateValue(ecPrivateKey.getS(), params);
            ECDSAImpl newImpl = null;
            try {
                newImpl = new ECDSAImpl(
                        curveName,
                        algorithm,
                        null,
                        encodedPrivate);
                if (userId != null) {
                    newImpl.setUserId(userId);
                }
                commitImpl(newImpl, true);
                newImpl = null;
            } catch (InvalidKeyException | RuntimeException e) {
                NativeResourceUtil.closeSuppressing(newImpl, e);
                throw e;
            } finally {
                Arrays.fill(encodedPrivate, (byte) 0);
            }
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize ECDSA", e);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        state.ensureReadyForUpdate("ECDSA");
        buffer = SignerBuffer.append(buffer, b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        state.ensureSigning("ECDSA");
        if (buffer == null) {
            throw new SignatureException("No data to sign");
        }
        try {
            return ecdsaImpl.signData(buffer);
        } catch (Exception e) {
            throw new SignatureException("Signing failed", e);
        } finally {
            clearBuffer();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        state.ensureVerification("ECDSA");
        if (buffer == null) {
            throw new SignatureException("No data to verify");
        }
        try {
            return ecdsaImpl.verifySignature(buffer, sigBytes);
        } catch (Exception e) {
            throw new SignatureException("Verification failed", e);
        } finally {
            clearBuffer();
        }
    }

    private void clearBuffer() {
        buffer = SignerBuffer.clear(buffer);
    }

    private void commitImpl(ECDSAImpl newImpl, boolean signing) throws InvalidKeyException {
        ecdsaImpl = NativeResourceUtil.replaceAfterClosing(ecdsaImpl, newImpl,
                failure -> new InvalidKeyException("Failed to close previous ECDSA context", failure));
        if (signing) {
            state.activateSigning(this::clearBuffer);
        } else {
            state.activateVerification(this::clearBuffer);
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) 
            throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    @Override
    protected Object engineGetParameter(String param) 
            throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params == null) {
            if (state.isInitialized() && ecdsaImpl != null) {
                ecdsaImpl.resetUserId();
            }
            clearUserId();
            return;
        }
        if (!(params instanceof SM2ParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only SM2ParameterSpec is supported");
        }
        if (!sm2Signature) {
            throw new InvalidAlgorithmParameterException("SM2ParameterSpec is only supported for SM3withSM2");
        }
        byte[] newUserId = ((SM2ParameterSpec)params).getId();
        boolean updated = false;
        try {
            if (state.isInitialized() && ecdsaImpl != null) {
                ecdsaImpl.setUserId(newUserId);
            }
            updated = true;
            clearUserId();
            userId = newUserId;
        } finally {
            if (!updated) {
                Arrays.fill(newUserId, (byte) 0);
            }
        }
    }

    private void clearUserId() {
        if (userId != null) {
            Arrays.fill(userId, (byte) 0);
            userId = null;
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private static String getCurveName(ECParameterSpec params) throws InvalidKeyException {
        if (params == null) {
            throw new InvalidKeyException("EC key parameters cannot be null");
        }
        try {
            return ECKeyEncoding.getCurveName(params);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Unsupported EC curve parameters", e);
        }
    }

    private void ensureCurveAllowed(String curveName) throws InvalidKeyException {
        if (sm2Signature) {
            if (!isSM2Curve(curveName)) {
                throw new InvalidKeyException("SM3withSM2 requires SM2 curve: " + curveName);
            }
        } else if (!ECCurveRegistry.isNistCurve(curveName)) {
            throw new InvalidKeyException("ECDSA signature requires NIST curve: " + curveName);
        }
    }

    private static boolean isSM2Curve(String curveName) {
        return ECCurveRegistry.isSM2Curve(curveName);
    }

    private int getHashAlgorithm(String algorithmName) {
        switch (algorithmName) {
            case "SM3":
                return CryptoConstants.HASH_ALG_SM3;
            case "SHA256":
                return CryptoConstants.HASH_ALG_SHA256;
            case "SHA384":
                return CryptoConstants.HASH_ALG_SHA384;
            case "SHA512":
                return CryptoConstants.HASH_ALG_SHA512;
            default:
                throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithmName);
        }
    }
}
