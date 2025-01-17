package org.openhitls.crypto.core.mac;

import org.openhitls.crypto.NativeLoader;

public class HMAC {
    // Native method declarations
    private native void nativeInit(int algorithm, byte[] key);
    private native void nativeUpdate(byte[] data, int offset, int length);
    private native byte[] nativeDoFinal();
    private native void nativeReinit();
    private native int nativeGetMacLength();

    private long contextPtr; // Store C context pointer

    // Algorithm constants from crypt_algid.h
    public static final int HMAC_SM3 = 10511; // BSL_CID_HMAC_SM3 from crypt_algid.h

    public HMAC(int algorithm, byte[] key) {
        nativeInit(algorithm, key);
    }

    public void update(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        nativeUpdate(data, 0, data.length);
    }

    public void update(byte[] data, int offset, int length) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IllegalArgumentException("Invalid offset or length");
        }
        nativeUpdate(data, offset, length);
    }

    public byte[] doFinal() {
        return nativeDoFinal();
    }

    public void reinit() {
        nativeReinit();
    }

    public int getMacLength() {
        return nativeGetMacLength();
    }

    // Convenience method to compute HMAC in one call
    public static byte[] compute(int algorithm, byte[] key, byte[] data) {
        HMAC hmac = new HMAC(algorithm, key);
        hmac.update(data);
        return hmac.doFinal();
    }
} 
