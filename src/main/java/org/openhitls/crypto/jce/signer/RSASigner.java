package org.openhitls.crypto.jce.signer;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.asymmetric.RSAImpl;
import org.openhitls.crypto.jce.key.RSAKeyUtil;

public class RSASigner extends SignatureSpi {
    private final RSAImpl rsaImpl;
    private final String digestAlgorithm;
    private byte[] digestedMessage;
    private boolean isInitialized;
    private boolean forSigning;

    public RSASigner(String digestAlgorithm) {
        this.rsaImpl = new RSAImpl();
        this.digestAlgorithm = digestAlgorithm;
    }

    protected RSASigner(String digestAlgorithm, RSAPadding.PSSParameterSpec pssParams) {
        this(digestAlgorithm);
        this.rsaImpl.setPSSParameters(pssParams);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new InvalidKeyException("Key must be an instance of RSAPublicKey");
        }

        RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
        byte[] modulus = RSAKeyUtil.toUnsignedBytes(rsaKey.getModulus());
        BigInteger exponent = RSAKeyUtil.getPublicExponent(rsaKey);
        if (exponent == null) {
            throw new InvalidKeyException("RSA public exponent cannot be null");
        }
        byte[] publicExponent = RSAKeyUtil.toUnsignedBytes(exponent);

        rsaImpl.setKeys(modulus, null, publicExponent);
        rsaImpl.setDigestAlgorithm(digestAlgorithm);
        isInitialized = true;
        forSigning = false;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new InvalidKeyException("Key must be an instance of RSAPrivateKey");
        }

        RSAPrivateKey rsaKey = (RSAPrivateKey) privateKey;
        byte[] modulus = RSAKeyUtil.toUnsignedBytes(rsaKey.getModulus());
        byte[] privateExponent = RSAKeyUtil.toUnsignedBytes(rsaKey.getPrivateExponent());
        byte[] publicExponent = RSAKeyUtil.toUnsignedBytes(RSAKeyUtil.requirePublicExponent(rsaKey));

        rsaImpl.setKeys(modulus, privateExponent, publicExponent);
        rsaImpl.setDigestAlgorithm(digestAlgorithm);
        isInitialized = true;
        forSigning = true;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (!isInitialized) {
            throw new SignatureException("RSA signature not initialized");
        }

        if (b == null) {
            throw new SignatureException("Input buffer must not be null");
        }

        if (off < 0 || len < 0 || off + len > b.length) {
            throw new SignatureException("Invalid input buffer parameters");
        }

        byte[] input = new byte[len];
        System.arraycopy(b, off, input, 0, len);
        digestedMessage = input;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!isInitialized || !forSigning) {
            throw new SignatureException("RSA signature not initialized for signing");
        }

        if (digestedMessage == null) {
            throw new SignatureException("No data to sign");
        }

        try {
            return rsaImpl.sign(digestedMessage);
        } catch (Exception e) {
            throw new SignatureException("Failed to sign data", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (!isInitialized || forSigning) {
            throw new SignatureException("RSA signature not initialized for verification");
        }

        if (digestedMessage == null) {
            throw new SignatureException("No data to verify");
        }

        if (sigBytes == null) {
            throw new SignatureException("Signature bytes must not be null");
        }

        try {
            return rsaImpl.verify(digestedMessage, sigBytes);
        } catch (Exception e) {
            throw new SignatureException("Failed to verify signature", e);
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidParameterException {
        if (params instanceof RSAPadding.PSSParameterSpec) {
            rsaImpl.setPSSParameters((RSAPadding.PSSParameterSpec) params);
        } else {
            throw new InvalidParameterException("Only RSAPadding.PSSParameterSpec is supported");
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    public static final class SHA224withRSA extends RSASigner {
        public SHA224withRSA() {
            super("SHA224");
        }
    }

    public static final class SHA1withRSA extends RSASigner {
        public SHA1withRSA() {
            super("SHA1");
        }
    }

    public static final class SHA256withRSA extends RSASigner {
        public SHA256withRSA() {
            super("SHA256");
        }
    }

    public static final class SHA384withRSA extends RSASigner {
        public SHA384withRSA() {
            super("SHA384");
        }
    }

    public static final class SHA512withRSA extends RSASigner {
        public SHA512withRSA() {
            super("SHA512");
        }
    }

    public static final class SM3withRSA extends RSASigner {
        public SM3withRSA() {
            super("SM3");
        }
    }

    public static final class SHA224withRSAPSS extends RSASigner {
        public SHA224withRSAPSS() {
            super("SHA224", new RSAPadding.PSSParameterSpec("SHA224"));
        }
    }

    public static final class SHA256withRSAPSS extends RSASigner {
        public SHA256withRSAPSS() {
            super("SHA256", new RSAPadding.PSSParameterSpec("SHA256"));
        }
    }

    public static final class SHA384withRSAPSS extends RSASigner {
        public SHA384withRSAPSS() {
            super("SHA384", new RSAPadding.PSSParameterSpec("SHA384"));
        }
    }

    public static final class SHA512withRSAPSS extends RSASigner {
        public SHA512withRSAPSS() {
            super("SHA512", new RSAPadding.PSSParameterSpec("SHA512"));
        }
    }
}
