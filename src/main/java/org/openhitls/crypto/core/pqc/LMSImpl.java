package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoConstants;
import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.jce.spec.LMSParameterSpec;

public class LMSImpl extends NativeResource {
    private final LMSParameterSpec params;

    public LMSImpl(LMSParameterSpec params) {
        super(CryptoNative.lmsCreateContext(params.getLmsType(), params.getOtsType()), CryptoNative::lmsFreeContext);
        this.params = params;
    }

    public byte[][] generateKeyPair() {
        return CryptoNative.lmsGenerateKeyPair(nativeContext);
    }

    public StatefulHBSSignResult sign(byte[] privateKey, byte[] data) {
        CryptoNative.lmsSetPrivateKey(nativeContext, privateKey);
        byte[][] result = CryptoNative.lmsSignAndExportState(nativeContext, data, CryptoConstants.HASH_ALG_SHA256);
        return new StatefulHBSSignResult(result[0], result[1]);
    }

    public boolean verify(byte[] publicKey, byte[] data, byte[] signature) {
        CryptoNative.lmsSetPublicKey(nativeContext, publicKey);
        return CryptoNative.lmsVerify(nativeContext, data, signature, CryptoConstants.HASH_ALG_SHA256);
    }

    public LMSParameterSpec getParams() {
        return params;
    }
}
