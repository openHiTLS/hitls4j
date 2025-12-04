package org.openhitls.crypto.jce.signer;

import org.openhitls.crypto.core.CryptoConstants;
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
    private boolean forSigning;
    private final int hashAlgorithm;
    private MLDSASignatureParameterSpec signParams;

    public MLDSASigner(String algorithm) {
        this.hashAlgorithm = getHashAlgorithm(algorithm);
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
                signParams = new MLDSASignatureParameterSpec(false, false, false, false, null);
            }

            byte[] publicKeyEncoded = mldsaPublicKey.getEncoded();
            mldsaImpl = new MLDSAImpl(parameterSetName, hashAlgorithm, publicKeyEncoded, null);
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize MLDSA: " + e.getMessage(), e);
        }
        buffer = null;
        forSigning = false;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (!(privateKey instanceof MLDSAPrivateKey)) {
            throw new InvalidKeyException("Key must be an instance of MLDSAPublicKey");
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
                signParams = new MLDSASignatureParameterSpec(false, false, false, false, null);
            }

            byte[] privateKeyEncoded = mldsaPrivateKey.getEncoded();
            mldsaImpl = new MLDSAImpl(parameterSetName, hashAlgorithm, null, privateKeyEncoded);
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize MLDSA: " + e.getMessage(), e);
        }
        buffer = null;
        forSigning = true;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        try {
            if (buffer == null) {
                buffer = new byte[len];
                System.arraycopy(b, off, buffer, 0, len);
            } else {
                byte[] newBuffer = new byte[buffer.length + len];
                System.arraycopy(buffer, 0, newBuffer, 0, buffer.length);
                System.arraycopy(b, off, newBuffer, buffer.length, len);
                buffer = newBuffer;
            }
        } catch (Exception e) {
            throw new SignatureException("Update failed", e);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!forSigning) {
            throw new SignatureException("Not initialized for signature");
        }
        if (buffer == null) {
            throw new SignatureException("No data to sign");
        }
        try {
            return mldsaImpl.signData(buffer, signParams);
        } catch (Exception e) {
            throw new SignatureException("Sign failed: " + e.getMessage(), e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (forSigning) {
            throw new SignatureException("Not initialized for verification");
        }
        if (buffer == null) {
            throw new SignatureException("No data to verify");
        }
        try {
            return mldsaImpl.verifySignature(buffer, sigBytes, signParams);
        } catch (Exception e) {
            throw new SignatureException("Verify failed: " + e.getMessage(), e);
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
            this.signParams = new MLDSASignatureParameterSpec(false, false, false, false, null);
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
