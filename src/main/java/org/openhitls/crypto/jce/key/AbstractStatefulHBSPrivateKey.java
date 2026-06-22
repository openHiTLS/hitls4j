package org.openhitls.crypto.jce.key;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.openhitls.crypto.jce.interfaces.StatefulHBSPrivateKey;
import org.openhitls.crypto.jce.state.HbsStateStore;

public abstract class AbstractStatefulHBSPrivateKey implements StatefulHBSPrivateKey {
    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final AlgorithmParameterSpec params;
    private byte[] encoded;
    private transient HbsStateStore stateStore;
    private transient String stateKeyId;
    private transient boolean unsafeInMemorySigningEnabled;

    protected AbstractStatefulHBSPrivateKey(String algorithm, AlgorithmParameterSpec params, byte[] encoded) {
        if (algorithm == null || params == null || encoded == null) {
            throw new NullPointerException("algorithm, params and encoded cannot be null");
        }
        this.algorithm = algorithm;
        this.params = params;
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public synchronized byte[] getEncoded() {
        return encoded.clone();
    }

    @Override
    public synchronized byte[] getPrivateData() {
        return encoded.clone();
    }

    public synchronized void updatePrivateData(byte[] updated) {
        if (updated == null) {
            throw new NullPointerException("updated cannot be null");
        }
        byte[] previous = this.encoded;
        this.encoded = updated.clone();
        Arrays.fill(previous, (byte) 0);
    }

    public synchronized void bindStateStore(HbsStateStore stateStore, String keyId) {
        if (stateStore == null || keyId == null) {
            throw new NullPointerException("stateStore and keyId cannot be null");
        }
        this.stateStore = stateStore;
        this.stateKeyId = keyId;
        this.unsafeInMemorySigningEnabled = false;
    }

    @Override
    public synchronized HbsStateStore getStateStore() {
        return stateStore;
    }

    @Override
    public synchronized String getStateKeyId() {
        return stateKeyId;
    }

    @Override
    public synchronized void enableUnsafeInMemorySigning() {
        this.unsafeInMemorySigningEnabled = true;
    }

    @Override
    public synchronized void disableUnsafeInMemorySigning() {
        this.unsafeInMemorySigningEnabled = false;
    }

    @Override
    public synchronized boolean isUnsafeInMemorySigningEnabled() {
        return unsafeInMemorySigningEnabled;
    }

    @Override
    public AlgorithmParameterSpec getParams() {
        return params;
    }
}
