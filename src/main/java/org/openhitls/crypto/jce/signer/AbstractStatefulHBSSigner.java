package org.openhitls.crypto.jce.signer;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.openhitls.crypto.core.pqc.StatefulHBSSignResult;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.state.HbsSignCommit;
import org.openhitls.crypto.jce.state.HbsStateRecord;
import org.openhitls.crypto.jce.state.HbsStateStore;
import org.openhitls.crypto.jce.spec.StatefulHBSParameterSpec;

public abstract class AbstractStatefulHBSSigner extends SignatureSpi {
    private AbstractStatefulHBSPrivateKey privateKey;
    private AbstractStatefulHBSPublicKey publicKey;
    private byte[] buffer;
    private int bufferPos;
    private boolean forSigning;

    protected abstract String algorithmName();

    protected abstract StatefulHBSSignResult sign(AbstractStatefulHBSPrivateKey privateKey, byte[] privateState, byte[] data)
            throws Exception;

    protected abstract boolean verify(AbstractStatefulHBSPublicKey publicKey, byte[] data, byte[] signature)
            throws Exception;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof AbstractStatefulHBSPublicKey)) {
            throw new InvalidKeyException("Key must be a stateful HBS public key");
        }
        AbstractStatefulHBSPublicKey hbsPublicKey = (AbstractStatefulHBSPublicKey) publicKey;
        if (!algorithmName().equals(hbsPublicKey.getAlgorithm())) {
            throw new InvalidKeyException("Key algorithm mismatch: " + hbsPublicKey.getAlgorithm());
        }
        this.publicKey = hbsPublicKey;
        this.privateKey = null;
        resetBuffer();
        this.forSigning = false;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (!(privateKey instanceof AbstractStatefulHBSPrivateKey)) {
            throw new InvalidKeyException("Key must be a stateful HBS private key");
        }
        AbstractStatefulHBSPrivateKey hbsPrivateKey = (AbstractStatefulHBSPrivateKey) privateKey;
        if (!algorithmName().equals(hbsPrivateKey.getAlgorithm())) {
            throw new InvalidKeyException("Key algorithm mismatch: " + hbsPrivateKey.getAlgorithm());
        }
        this.privateKey = hbsPrivateKey;
        this.publicKey = null;
        resetBuffer();
        this.forSigning = true;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (b == null) {
            throw new SignatureException("Input cannot be null");
        }
        if (off < 0 || len < 0 || off > b.length || len > b.length - off) {
            throw new SignatureException("Invalid input range");
        }
        if (len == 0) {
            return;
        }
        if (len > Integer.MAX_VALUE - bufferPos) {
            throw new SignatureException("Input is too large");
        }
        int needed = bufferPos + len;
        ensureCapacity(needed);
        System.arraycopy(b, off, buffer, bufferPos, len);
        bufferPos = needed;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!forSigning || privateKey == null) {
            throw new SignatureException("Not initialized for signing");
        }
        byte[] data = currentInput();
        synchronized (privateKey) {
            try {
                StatefulHBSSignResult result = signWithOptionalStore(privateKey, data);
                privateKey.updatePrivateData(result.getUpdatedPrivateKey());
                return result.getSignature();
            } catch (Exception e) {
                throw new SignatureException("Stateful HBS sign failed: " + e.getMessage(), e);
            } finally {
                resetBuffer();
            }
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (forSigning || publicKey == null) {
            throw new SignatureException("Not initialized for verification");
        }
        if (sigBytes == null) {
            resetBuffer();
            throw new SignatureException("Signature cannot be null");
        }
        byte[] data = currentInput();
        try {
            return verify(publicKey, data, sigBytes);
        } catch (Exception e) {
            throw new SignatureException("Stateful HBS verify failed: " + e.getMessage(), e);
        } finally {
            resetBuffer();
        }
    }

    private StatefulHBSSignResult signWithOptionalStore(AbstractStatefulHBSPrivateKey key, byte[] data)
            throws Exception {
        HbsStateStore stateStore = key.getStateStore();
        String keyId = key.getStateKeyId();
        if (stateStore == null || keyId == null) {
            if (stateStore == null && keyId == null && key.isUnsafeInMemorySigningEnabled()) {
                return sign(key, key.getPrivateData(), data);
            }
            throw new GeneralSecurityException(
                    "Stateful HBS signing requires a bound HbsStateStore or explicit unsafe in-memory mode");
        }

        HbsSignCommit commit = stateStore.withExclusiveSigningState(keyId, state -> {
            validateSigningState(key, state);
            StatefulHBSSignResult result;
            try {
                result = sign(key, state.getPrivateState(), data);
            } catch (Exception e) {
                throw new GeneralSecurityException("Native HBS signing failed", e);
            }
            HbsStateRecord updated = state.withPrivateState(result.getUpdatedPrivateKey(), -1L);
            return new HbsSignCommit(updated, result.getSignature());
        });
        return new StatefulHBSSignResult(commit.getSignature(), commit.getUpdatedState().getPrivateState());
    }

    private void validateSigningState(AbstractStatefulHBSPrivateKey key, HbsStateRecord state)
            throws GeneralSecurityException {
        if (!algorithmName().equals(state.getAlgorithm()) || !algorithmName().equals(key.getAlgorithm())) {
            throw new GeneralSecurityException("HBS state algorithm does not match signing key");
        }
        if (!(key.getParams() instanceof StatefulHBSParameterSpec)) {
            throw new GeneralSecurityException("HBS signing key has unsupported parameter type");
        }
        String expectedParameterSet = ((StatefulHBSParameterSpec) key.getParams()).getName();
        if (!expectedParameterSet.equals(state.getParameterSet())) {
            throw new GeneralSecurityException("HBS state parameter set does not match signing key");
        }
    }

    private byte[] currentInput() {
        return bufferPos == 0 ? new byte[0] : Arrays.copyOf(buffer, bufferPos);
    }

    private void ensureCapacity(int needed) throws SignatureException {
        if (buffer == null) {
            buffer = new byte[Math.max(256, needed)];
            return;
        }
        if (needed <= buffer.length) {
            return;
        }
        int newCapacity = buffer.length;
        while (newCapacity < needed) {
            if (newCapacity > Integer.MAX_VALUE / 2) {
                newCapacity = needed;
                break;
            }
            newCapacity *= 2;
        }
        buffer = Arrays.copyOf(buffer, newCapacity);
    }

    private void resetBuffer() {
        buffer = null;
        bufferPos = 0;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("String parameters are not supported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("Signature parameters are not supported");
        }
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("Parameters are not supported");
    }
}
