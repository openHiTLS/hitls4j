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
import java.util.Arrays;

import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.asymmetric.RSAImpl;
import org.openhitls.crypto.jce.key.RSAKeyUtil;

public class RSASigner extends SignatureSpi {
    private RSAImpl rsaImpl;
    private final String digestAlgorithm;
    private MessageBuffer messageBuffer;
    private final SignatureState state = new SignatureState();
    private RSAPadding.PSSParameterSpec pssParams;

    public RSASigner(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
        this.rsaImpl = createRSAImpl();
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
        RSAImpl newImpl = null;
        try {
            byte[] modulus = RSAKeyUtil.toUnsignedBytes(rsaKey.getModulus());
            privateExponent = RSAKeyUtil.toUnsignedBytes(rsaKey.getPrivateExponent());
            byte[] publicExponent = RSAKeyUtil.toUnsignedBytes(RSAKeyUtil.requirePublicExponent(rsaKey));

            newImpl = createRSAImpl();
            newImpl.setKeys(modulus, privateExponent, publicExponent);
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
            if (privateExponent != null) {
                Arrays.fill(privateExponent, (byte) 0);
            }
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        state.ensureReadyForUpdate("RSA");
        SignerBuffer.validateUpdateInput(b, off, len);
        messageBuffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        state.ensureSigning("RSA");
        byte[] message = null;
        try {
            message = messageBuffer.toByteArray();
            return rsaImpl.sign(message);
        } catch (Exception e) {
            throw new SignatureException("Failed to sign data", e);
        } finally {
            if (message != null) {
                Arrays.fill(message, (byte) 0);
            }
            clearMessageBuffer();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        state.ensureVerification("RSA");

        if (sigBytes == null) {
            clearMessageBuffer();
            throw new SignatureException("Signature bytes must not be null");
        }

        byte[] message = null;
        try {
            message = messageBuffer.toByteArray();
            return rsaImpl.verify(message, sigBytes);
        } catch (Exception e) {
            throw new SignatureException("Failed to verify signature", e);
        } finally {
            if (message != null) {
                Arrays.fill(message, (byte) 0);
            }
            clearMessageBuffer();
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidParameterException {
        if (params instanceof RSAPadding.PSSParameterSpec) {
            pssParams = (RSAPadding.PSSParameterSpec) params;
            rsaImpl.setPSSParameters(pssParams);
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

    private void clearMessageBuffer() {
        if (messageBuffer != null) {
            messageBuffer.clear();
        }
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
        rsaImpl = NativeResourceUtil.replaceAfterClosing(rsaImpl, newImpl,
                failure -> new InvalidKeyException("Failed to close previous RSA context", failure));
        if (signing) {
            state.activateSigning(this::resetMessageBuffer);
        } else {
            state.activateVerification(this::resetMessageBuffer);
        }
    }

    private void resetMessageBuffer() {
        clearMessageBuffer();
        messageBuffer = new MessageBuffer();
    }

    MessageBufferStatus messageBufferStatus() {
        return messageBuffer;
    }

    interface MessageBufferStatus {
        boolean isCleared();
    }

    private static final class MessageBuffer implements MessageBufferStatus {
        private static final int DEFAULT_CAPACITY = 32;

        private byte[] buffer = new byte[DEFAULT_CAPACITY];
        private int count;

        void write(byte[] input, int offset, int length) {
            ensureCapacity(count + length);
            System.arraycopy(input, offset, buffer, count, length);
            count += length;
        }

        byte[] toByteArray() {
            return SignerBuffer.copyOf(buffer, count);
        }

        void clear() {
            Arrays.fill(buffer, (byte) 0);
            count = 0;
        }

        @Override
        public boolean isCleared() {
            if (count != 0) {
                return false;
            }
            for (byte value : buffer) {
                if (value != 0) {
                    return false;
                }
            }
            return true;
        }

        private void ensureCapacity(int minCapacity) {
            if (minCapacity < 0) {
                throw new OutOfMemoryError("Required array size too large");
            }
            if (minCapacity <= buffer.length) {
                return;
            }

            int newCapacity = Math.max(buffer.length << 1, minCapacity);
            if (newCapacity < 0) {
                newCapacity = Integer.MAX_VALUE;
            }

            buffer = SignerBuffer.resize(buffer, newCapacity);
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
