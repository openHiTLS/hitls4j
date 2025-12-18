package org.openhitls.crypto.jce.signer;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.CryptoConstants;
import org.openhitls.crypto.core.pqc.SLHDSAImpl;
import org.openhitls.crypto.jce.key.SLHDSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.SLHDSAPublicKeyImpl;
import org.openhitls.crypto.jce.spec.SLHDSAParameterSpec;
import org.openhitls.crypto.jce.spec.SLHDSASignatureParameterSpec;

public class SLHDSASigner extends SignatureSpi{
    private SLHDSAImpl slhdsaImpl;
    private byte[] buffer;
    private boolean forSigning;
    private final int hashAlgorithm;
    private SLHDSASignatureParameterSpec signParams;

    public SLHDSASigner(String algorithm) {
        this.hashAlgorithm = getHashAlgorithm(algorithm);
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
            case "SHAKE128":
                return CryptoConstants.HASH_ALG_SHAKE128;
            case "SHAKE256":
                return CryptoConstants.HASH_ALG_SHAKE256;
            default:
                throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm);
        }
    }

    public static final class SM3withSLHDSA extends SLHDSASigner {
        public SM3withSLHDSA() {
            super("SM3");
        }
    }

    public static final class SHA256withSLHDSA extends SLHDSASigner {
        public SHA256withSLHDSA() {
            super("SHA256");
        }
    }

    public static final class SHA384withSLHDSA extends SLHDSASigner {
        public SHA384withSLHDSA() {
            super("SHA384");
        }
    }

    public static final class SHA512withSLHDSA extends SLHDSASigner {
        public SHA512withSLHDSA() {
            super("SHA512");
        }
    }

    public static final class SHAKE128withSLHDSA extends SLHDSASigner {
        public SHAKE128withSLHDSA() {
            super("SHAKE128");
        }
    }

    public static final class SHAKE256withSLHDSA extends SLHDSASigner {
        public SHAKE256withSLHDSA() {
            super("SHAKE256");
        }
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("SLHDSA not support get parameter");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof SLHDSAPrivateKeyImpl)) {
            throw new InvalidKeyException("Key must be an instance of SLHDSAPrivateKeyImpl");
        }
        try {
            SLHDSAParameterSpec params = ((SLHDSAPrivateKeyImpl)privateKey).getParams();
            String parameterSetName = params.getName();
            if (signParams == null) {
                signParams = new SLHDSASignatureParameterSpec(false, false, null, null);
            }
            slhdsaImpl = new SLHDSAImpl(parameterSetName, hashAlgorithm, null, ((SLHDSAPrivateKeyImpl)privateKey).getEncoded());
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize SLHDSA: " + e.getMessage(), e);
        }
        buffer = null;
        forSigning = true;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof SLHDSAPublicKeyImpl)) {
            throw new InvalidKeyException("Key must be an instance of SLHDSAPublicKeyImpl");
        }
        try {
            SLHDSAParameterSpec params = ((SLHDSAPublicKeyImpl)publicKey).getParams();
            String parameterSetName = params.getName();
            // Ensure signParams is not null, set default values
            if (signParams == null) {
                signParams = new SLHDSASignatureParameterSpec(false, false, null, null);
            }
            slhdsaImpl = new SLHDSAImpl(parameterSetName, hashAlgorithm, ((SLHDSAPublicKeyImpl)publicKey).getEncoded(), null);
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize SLHDSA: " + e.getMessage(), e);
        }
        buffer = null;
        forSigning = false;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("has been deprecated");
    }

    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params == null) {
            signParams = new SLHDSASignatureParameterSpec(false, false, null, null);
        } else if (params instanceof SLHDSASignatureParameterSpec) {
            signParams = (SLHDSASignatureParameterSpec)params;
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported signatureParameter type");
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!forSigning) {
            throw new SignatureException("Not initialized for signing");
        }
        if (buffer == null) {
            throw new SignatureException("No data to sign");
        }
        try {
            return slhdsaImpl.signData(buffer, signParams);
        } catch (Exception e) {
            throw new SignatureException("Sign failed: " + e.getMessage(), e);
        }
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
            throw new SignatureException("Update failed: " + e.getMessage(), e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (forSigning) {
            throw new SignatureException("Not initialized for verifiction");
        }
        if (buffer == null) {
            throw new SignatureException("No data to verify");
        }
        try {
            return slhdsaImpl.verifySignature(buffer, sigBytes, signParams);
        } catch (Exception e) {
            throw new SignatureException("Verify failed: " + e.getMessage(), e);
        }
    }
    
}
