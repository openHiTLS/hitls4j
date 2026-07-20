package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.jce.spec.HSSParameterSpec;

public class HSSImpl extends NativeResource {
    private final HSSParameterSpec params;

    public HSSImpl(HSSParameterSpec params) {
        super(CryptoNative.hssCreateContext(params.getLmsTypes(), params.getOtsTypes()), CryptoNative::hssFreeContext);
        this.params = params;
    }

    public boolean verify(byte[] publicKey, byte[] data, byte[] signature) {
        CryptoNative.hssSetPublicKey(nativeContext, publicKey);
        return CryptoNative.hssVerify(nativeContext, data, signature);
    }

    public HSSParameterSpec getParams() {
        return params;
    }
}
