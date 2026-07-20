package org.openhitls.crypto.jce.signer;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Locale;

import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.asymmetric.RSAImpl;
import org.openhitls.crypto.jce.key.RSAKeyUtil;

public class RSASigner extends SignatureSpi {
    private RSAImpl rsaImpl;
    private final String digestAlgorithm;
    private final SignatureDigest signatureDigest;
    private final SignatureState state = new SignatureState();
    private RSAPadding.PSSParameterSpec pssParams;

    public RSASigner(String digestAlgorithm) {
        String canonicalDigestAlgorithm = requireSupportedDigestAlgorithm(digestAlgorithm);
        this.digestAlgorithm = canonicalDigestAlgorithm;
        this.rsaImpl = createRSAImpl();
        try {
            this.signatureDigest = new SignatureDigest(canonicalDigestAlgorithm, "RSA");
        } catch (RuntimeException | Error e) {
            NativeResourceUtil.closeSuppressing(rsaImpl, e);
            throw e;
        }
    }

    protected RSASigner(String digestAlgorithm, RSAPadding.PSSParameterSpec pssParams) {
        this(digestAlgorithm);
        this.pssParams = pssParams;
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

        RSAImpl newImpl = createRSAImpl();
        try {
            newImpl.setKeys(modulus, null, publicExponent);
            newImpl.setDigestAlgorithm(digestAlgorithm);
            commitImpl(newImpl, false);
            newImpl = null;
        } catch (InvalidKeyException e) {
            NativeResourceUtil.closeSuppressing(newImpl, e);
            throw e;
        } catch (RuntimeException e) {
            NativeResourceUtil.closeSuppressing(newImpl, e);
            throw new InvalidKeyException("Failed to initialize verification key", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new InvalidKeyException("Key must be an instance of RSAPrivateKey");
        }

        RSAPrivateKey rsaKey = (RSAPrivateKey) privateKey;
        byte[] privateExponent = null;
        byte[] primeP = null;
        byte[] primeQ = null;
        byte[] primeExponentP = null;
        byte[] primeExponentQ = null;
        byte[] crtCoefficient = null;
        RSAImpl newImpl = null;
        try {
            byte[] modulus = RSAKeyUtil.toUnsignedBytes(rsaKey.getModulus());
            privateExponent = RSAKeyUtil.toUnsignedBytes(rsaKey.getPrivateExponent());
            byte[] publicExponent = RSAKeyUtil.toUnsignedBytes(RSAKeyUtil.requirePublicExponent(rsaKey));

            newImpl = createRSAImpl();
            if (rsaKey instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) rsaKey;
                primeP = RSAKeyUtil.toUnsignedBytes(crtKey.getPrimeP());
                primeQ = RSAKeyUtil.toUnsignedBytes(crtKey.getPrimeQ());
                primeExponentP = RSAKeyUtil.toUnsignedBytes(crtKey.getPrimeExponentP());
                primeExponentQ = RSAKeyUtil.toUnsignedBytes(crtKey.getPrimeExponentQ());
                crtCoefficient = RSAKeyUtil.toUnsignedBytes(crtKey.getCrtCoefficient());
                newImpl.setCrtKeys(modulus, privateExponent, publicExponent,
                        primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
            } else {
                newImpl.setKeys(modulus, privateExponent, publicExponent);
            }
            newImpl.setDigestAlgorithm(digestAlgorithm);
            commitImpl(newImpl, true);
            newImpl = null;
        } catch (InvalidKeyException e) {
            NativeResourceUtil.closeSuppressing(newImpl, e);
            throw e;
        } catch (RuntimeException e) {
            NativeResourceUtil.closeSuppressing(newImpl, e);
            throw new InvalidKeyException("Failed to initialize signing key", e);
        } finally {
            clear(privateExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        state.ensureReadyForUpdate("RSA");
        signatureDigest.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        state.ensureSigning("RSA");
        byte[] digest = null;
        try {
            digest = signatureDigest.finishAndReset();
            return rsaImpl.signDigest(digest);
        } catch (Exception e) {
            throw new SignatureException("Failed to sign data", e);
        } finally {
            SignatureDigest.clear(digest);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        state.ensureVerification("RSA");

        if (sigBytes == null) {
            resetDigest();
            throw new SignatureException("Signature bytes must not be null");
        }

        byte[] digest = null;
        try {
            digest = signatureDigest.finishAndReset();
            return rsaImpl.verifyDigest(digest, sigBytes);
        } catch (Exception e) {
            throw new SignatureException("Failed to verify signature", e);
        } finally {
            SignatureDigest.clear(digest);
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidParameterException {
        if (params instanceof RSAPadding.PSSParameterSpec) {
            RSAPadding.PSSParameterSpec newParams = (RSAPadding.PSSParameterSpec) params;
            validatePSSHashAlgorithm(newParams);
            pssParams = newParams;
            rsaImpl.setPSSParameters(newParams);
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

    private RSAImpl createRSAImpl() {
        RSAImpl impl = new RSAImpl();
        try {
            if (pssParams != null) {
                impl.setPSSParameters(pssParams);
            }
            return impl;
        } catch (RuntimeException e) {
            NativeResourceUtil.closeSuppressing(impl, e);
            throw e;
        }
    }

    private void commitImpl(RSAImpl newImpl, boolean signing) throws InvalidKeyException {
        rsaImpl = SignatureState.replaceAfterReset(
                rsaImpl, newImpl, this::resetDigest, "RSA");
        if (signing) {
            state.activateSigning();
        } else {
            state.activateVerification();
        }
    }

    private void resetDigest() {
        signatureDigest.reset();
    }

    private static void clear(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) {
                Arrays.fill(value, (byte) 0);
            }
        }
    }

    private void validatePSSHashAlgorithm(RSAPadding.PSSParameterSpec params) {
        String expectedHash = canonicalDigestAlgorithm(digestAlgorithm);
        String requestedHash = canonicalDigestAlgorithm(params.getHashAlgorithm());
        if (!expectedHash.equals(requestedHash)) {
            throw new InvalidParameterException("PSS hash algorithm " + params.getHashAlgorithm()
                    + " does not match fixed signature digest " + expectedHash);
        }
    }

    private static String requireSupportedDigestAlgorithm(String algorithm) {
        String canonical = canonicalDigestAlgorithm(algorithm);
        if (canonical != null) {
            switch (canonical) {
                case "SHA-1":
                case "SHA-224":
                case "SHA-256":
                case "SHA-384":
                case "SHA-512":
                case "SM3":
                    return canonical;
                default:
                    break;
            }
        }
        throw new IllegalArgumentException("Unsupported RSA digest: " + algorithm);
    }

    private static String canonicalDigestAlgorithm(String algorithm) {
        if (algorithm == null) {
            return null;
        }
        String compactName = algorithm.replace("-", "").toUpperCase(Locale.ROOT);
        switch (compactName) {
            case "SHA1":
                return "SHA-1";
            case "SHA224":
                return "SHA-224";
            case "SHA256":
                return "SHA-256";
            case "SHA384":
                return "SHA-384";
            case "SHA512":
                return "SHA-512";
            default:
                return algorithm;
        }
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
