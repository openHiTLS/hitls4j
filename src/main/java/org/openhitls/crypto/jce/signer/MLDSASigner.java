package org.openhitls.crypto.jce.signer;

import org.openhitls.crypto.core.CryptoConstants;
import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.core.pqc.MLDSAImpl;
import org.openhitls.crypto.jce.interfaces.MLDSAPrivateKey;
import org.openhitls.crypto.jce.interfaces.MLDSAPublicKey;
import org.openhitls.crypto.jce.key.MLDSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.MLDSAPublicKeyImpl;
import org.openhitls.crypto.jce.spec.MLDSAParameterSpec;
import org.openhitls.crypto.jce.spec.MLDSANamedParamSpec;
import org.openhitls.crypto.jce.spec.MLDSASignatureParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import java.security.*;

public class MLDSASigner extends SignatureSpi {
    private MLDSAImpl mldsaImpl;
    private byte[] buffer;
    private final SignatureState state = new SignatureState();
    private final int hashAlgorithm;
    private MLDSASignatureParameterSpec signParams;

    public MLDSASigner(String algorithm) {
        this.hashAlgorithm = getHashAlgorithm(algorithm);
    }

    public static final class SM3withMLDSA extends MLDSASigner {
        public SM3withMLDSA(){
            super("SM3");
        }
    }

    public static final class SHA256withMLDSA extends MLDSASigner {
        public SHA256withMLDSA(){
            super("SHA256");
        }
    }

    public static final class SHA384withMLDSA extends MLDSASigner {
        public SHA384withMLDSA(){
            super("SHA384");
        }
    }

    public static final class SHA512withMLDSA extends MLDSASigner {
        public SHA512withMLDSA(){
            super("SHA512");
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof MLDSAPublicKey)) {
            throw new InvalidKeyException("Key must be an instance of MLDSAPublicKey");
        }
        try {
            MLDSAPublicKeyImpl mldsaPublicKey = (MLDSAPublicKeyImpl)publicKey;
            MLDSAParameterSpec params = mldsaPublicKey.getParams();

            if (!(params instanceof MLDSANamedParamSpec)) {
                throw new InvalidKeyException("Key parameters must be an instance of MLDSANamedParamSpec");
            }
            String parameterSetName = ((MLDSANamedParamSpec)params).getName();

            if (!parameterSetName.matches("ML-DSA-(44|65|87)")) {
                throw new InvalidKeyException("Unsupported ML-DSA parameter set:" + parameterSetName);
            }

            // Ensure signParams is not null, set default values
            if (signParams == null) {
                signParams = new MLDSASignatureParameterSpec(false, false, false, null);
            }

            byte[] publicKeyEncoded = mldsaPublicKey.getEncoded();
            MLDSAImpl newImpl = null;
            try {
                newImpl = new MLDSAImpl(parameterSetName, hashAlgorithm, publicKeyEncoded, null);
                commitImpl(newImpl, false);
                newImpl = null;
            } catch (InvalidKeyException | RuntimeException e) {
                NativeResourceUtil.closeSuppressing(newImpl, e);
                throw e;
            }
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize MLDSA: " + e.getMessage(), e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (!(privateKey instanceof MLDSAPrivateKey)) {
            throw new InvalidKeyException("Key must be an instance of MLDSAPrivateKey");
        }
        try {
            MLDSAPrivateKeyImpl mldsaPrivateKey = (MLDSAPrivateKeyImpl) privateKey;
            MLDSAParameterSpec params = mldsaPrivateKey.getParams();

            if (!(params instanceof MLDSANamedParamSpec)) {
                throw new InvalidKeyException("Key parameters must be an instance of MLDSANamedParamSpec");
            }
            String parameterSetName = ((MLDSANamedParamSpec)params).getName();

            if (!parameterSetName.matches("ML-DSA-(44|65|87)")) {
                throw new InvalidKeyException("Unsupported ML-DSA parameter set:" + parameterSetName);
            }

            // Ensure signParams is not null, set default values
            if (signParams == null) {
                signParams = new MLDSASignatureParameterSpec(false, false, false, null);
            }

            byte[] privateKeyEncoded = null;
            MLDSAImpl newImpl = null;
            try {
                privateKeyEncoded = mldsaPrivateKey.getEncoded();
                newImpl = new MLDSAImpl(parameterSetName, hashAlgorithm, null, privateKeyEncoded);
                commitImpl(newImpl, true);
                newImpl = null;
            } catch (InvalidKeyException | RuntimeException e) {
                NativeResourceUtil.closeSuppressing(newImpl, e);
                throw e;
            } finally {
                SensitiveDataUtil.clear(privateKeyEncoded);
            }
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize MLDSA: " + e.getMessage(), e);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        state.ensureReadyForUpdate("MLDSA");
        buffer = SignerBuffer.append(buffer, b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        state.ensureSigning("MLDSA");
        if (buffer == null) {
            throw new SignatureException("No data to sign");
        }
        try {
            return mldsaImpl.signData(buffer, signParams);
        } catch (Exception e) {
            throw new SignatureException("Sign failed: " + e.getMessage(), e);
        } finally {
            clearBuffer();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        state.ensureVerification("MLDSA");
        if (buffer == null) {
            throw new SignatureException("No data to verify");
        }
        try {
            return mldsaImpl.verifySignature(buffer, sigBytes, signParams);
        } catch (Exception e) {
            throw new SignatureException("Verify failed: " + e.getMessage(), e);
        } finally {
            clearBuffer();
        }
    }

    private void clearBuffer() {
        buffer = SignerBuffer.clear(buffer);
    }

    private void commitImpl(MLDSAImpl newImpl, boolean signing) throws InvalidKeyException {
        mldsaImpl = NativeResourceUtil.replaceAfterClosing(mldsaImpl, newImpl,
                failure -> new InvalidKeyException("Failed to close previous MLDSA context", failure));
        if (signing) {
            state.activateSigning(this::clearBuffer);
        } else {
            state.activateVerification(this::clearBuffer);
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("Has been deprecated");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params == null) {
            // Reset to default values if null is passed
            this.signParams = new MLDSASignatureParameterSpec(false, false, false, null);
        } else if (params instanceof MLDSASignatureParameterSpec) {
            this.signParams = (MLDSASignatureParameterSpec) params;
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported signatureParameter type");
        }
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("MLDSA not support get parameter");
    }


    private int getHashAlgorithm(String algorithm) {
        switch (algorithm) {
            case "SM3":
                return CryptoConstants.HASH_ALG_SM3;
            case "SHA256":
                return CryptoConstants.HASH_ALG_SHA256;
            case "SHA384":
                return CryptoConstants.HASH_ALG_SHA384;
            case "SHA512":
                return CryptoConstants.HASH_ALG_SHA512;
            default:
                throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm);
        }
    }

}
