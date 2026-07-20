package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.jce.spec.LMSParameterSpec;

public class LMSImpl extends NativeResource {
    private final LMSParameterSpec params;

    public LMSImpl(LMSParameterSpec params) {
        super(CryptoNative.lmsCreateContext(params.getLmsType(), params.getOtsType()), CryptoNative::lmsFreeContext);
        this.params = params;
    }

    public boolean verify(byte[] publicKey, byte[] data, byte[] signature) {
        CryptoNative.lmsSetPublicKey(nativeContext, publicKey);
        return CryptoNative.lmsVerify(nativeContext, data, signature);
    }

    public LMSParameterSpec getParams() {
        return params;
    }
}
