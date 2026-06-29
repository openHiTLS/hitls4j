package org.openhitls.crypto.jce.signer;

import java.security.SignatureSpi;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.util.Arrays;
import org.openhitls.crypto.core.CryptoConstants;
import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.asymmetric.DSAImpl;

public class DSASigner extends SignatureSpi {
    private final int hashAlgorithm;
    private DSAImpl dsa;
    private byte[] buffer;
    private int bufferOffset;
    private final SignatureState state = new SignatureState();
    private static final int BUFFER_SIZE = 8192;

    public DSASigner() {
        this(CryptoConstants.HASH_ALG_SHA256);
    }

    protected DSASigner(int hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        buffer = new byte[BUFFER_SIZE];
        bufferOffset = 0;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof DSAPublicKey)) {
            throw new InvalidKeyException("Key must be a DSAPublicKey");
        }
        DSAPublicKey dsaKey = (DSAPublicKey) publicKey;
        
        DSAImpl newDsa = null;
        try {
            // Create a new DSA instance for each verification operation
            newDsa = createDSA();
            
            // Set DSA parameters
            DSAParameterSpec params = new DSAParameterSpec(
                dsaKey.getParams().getP(),
                dsaKey.getParams().getQ(),
                dsaKey.getParams().getG()
            );
            
            // Set the parameters
            newDsa.setParameters(params.getP().toByteArray(), params.getQ().toByteArray(), params.getG().toByteArray());
            
            // Convert public key to byte array
            byte[] y = dsaKey.getY().toByteArray();
            // Remove leading zero if present
            if (y[0] == 0) {
                byte[] tmp = new byte[y.length - 1];
                System.arraycopy(y, 1, tmp, 0, tmp.length);
                y = tmp;
            }
            
            // Set the public key
            newDsa.setKeys(y, null);
            commitDSA(newDsa, false);
            newDsa = null;
        } catch (Exception e) {
            NativeResourceUtil.closeSuppressing(newDsa, e);
            throw new InvalidKeyException("Failed to initialize verification key", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof DSAPrivateKey)) {
            throw new InvalidKeyException("Key must be a DSAPrivateKey");
        }
        DSAPrivateKey dsaKey = (DSAPrivateKey) privateKey;
        
        byte[] x = null;
        DSAImpl newDsa = null;
        try {
            // Create a new DSA instance for each signing operation
            newDsa = createDSA();
            
            // Set DSA parameters
            DSAParameterSpec params = new DSAParameterSpec(
                dsaKey.getParams().getP(),
                dsaKey.getParams().getQ(),
                dsaKey.getParams().getG()
            );
            
            // Set the parameters
            newDsa.setParameters(params.getP().toByteArray(), params.getQ().toByteArray(), params.getG().toByteArray());
            
            // Convert private key to byte array
            x = dsaKey.getX().toByteArray();
            // Remove leading zero if present
            if (x[0] == 0) {
                byte[] original = x;
                x = Arrays.copyOfRange(original, 1, original.length);
                Arrays.fill(original, (byte) 0);
            }
            
            // Set the private key
            newDsa.setKeys(null, x);
            commitDSA(newDsa, true);
            newDsa = null;
        } catch (Exception e) {
            NativeResourceUtil.closeSuppressing(newDsa, e);
            throw new InvalidKeyException("Failed to initialize signing key", e);
        } finally {
            if (x != null) {
                Arrays.fill(x, (byte) 0);
            }
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        state.ensureReadyForUpdate("DSA");
        if (bufferOffset >= BUFFER_SIZE) {
            throw new SignatureException("Buffer full");
        }
        buffer[bufferOffset++] = b;
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        state.ensureReadyForUpdate("DSA");
        SignerBuffer.validateUpdateInput(b, off, len);
        if (len > (BUFFER_SIZE - bufferOffset)) {
            throw new SignatureException("Buffer overflow");
        }
        System.arraycopy(b, off, buffer, bufferOffset, len);
        bufferOffset += len;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        state.ensureSigning("DSA");
        byte[] data = null;
        try {
            data = SignerBuffer.copyOf(buffer, bufferOffset);
            return dsa.sign(data);
        } catch (Exception e) {
            throw new SignatureException("Failed to generate signature", e);
        } finally {
            if (data != null) {
                Arrays.fill(data, (byte) 0);
            }
            clearBuffer();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        state.ensureVerification("DSA");
        byte[] data = null;
        try {
            data = SignerBuffer.copyOf(buffer, bufferOffset);
            return dsa.verify(data, sigBytes);
        } catch (Exception e) {
            throw new SignatureException("Failed to verify signature", e);
        } finally {
            if (data != null) {
                Arrays.fill(data, (byte) 0);
            }
            clearBuffer();
        }
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("engineGetParameter is not supported");
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("engineSetParameter is not supported");
    }

    private DSAImpl createDSA() {
        DSAImpl impl = new DSAImpl();
        try {
            impl.setHashAlgorithm(hashAlgorithm);
            return impl;
        } catch (RuntimeException e) {
            NativeResourceUtil.closeSuppressing(impl, e);
            throw e;
        }
    }

    private void commitDSA(DSAImpl newDsa, boolean signing) throws InvalidKeyException {
        dsa = NativeResourceUtil.replaceAfterClosing(dsa, newDsa,
                failure -> new InvalidKeyException("Failed to close previous DSA context", failure));
        if (signing) {
            state.activateSigning(this::clearBuffer);
        } else {
            state.activateVerification(this::clearBuffer);
        }
    }

    private void clearBuffer() {
        Arrays.fill(buffer, 0, bufferOffset, (byte) 0);
        bufferOffset = 0;
    }

    public static final class SHA1withDSA extends DSASigner {
        public SHA1withDSA() {
            super(CryptoConstants.HASH_ALG_SHA1);
        }
    }

    public static final class SHA224withDSA extends DSASigner {
        public SHA224withDSA() {
            super(CryptoConstants.HASH_ALG_SHA224);
        }
    }

    public static final class SHA256withDSA extends DSASigner {
        public SHA256withDSA() {
            super(CryptoConstants.HASH_ALG_SHA256);
        }
    }

    public static final class SHA384withDSA extends DSASigner {
        public SHA384withDSA() {
            super(CryptoConstants.HASH_ALG_SHA384);
        }
    }

    public static final class SHA512withDSA extends DSASigner {
        public SHA512withDSA() {
            super(CryptoConstants.HASH_ALG_SHA512);
        }
    }
} 
