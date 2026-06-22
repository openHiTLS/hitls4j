package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoConstants;
import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.jce.spec.HSSParameterSpec;

public class HSSImpl extends NativeResource {
    private final HSSParameterSpec params;

    public HSSImpl(HSSParameterSpec params) {
        super(CryptoNative.hssCreateContext(params.getLmsTypes(), params.getOtsTypes()), CryptoNative::hssFreeContext);
        this.params = params;
    }

    public byte[][] generateKeyPair() {
        return CryptoNative.hssGenerateKeyPair(nativeContext);
    }

    public StatefulHBSSignResult sign(byte[] privateKey, byte[] data) {
        CryptoNative.hssSetPrivateKey(nativeContext, privateKey);
        byte[][] result = CryptoNative.hssSignAndExportState(nativeContext, data, CryptoConstants.HASH_ALG_SHA256);
        return new StatefulHBSSignResult(result[0], result[1]);
    }

    public boolean verify(byte[] publicKey, byte[] data, byte[] signature) {
        CryptoNative.hssSetPublicKey(nativeContext, publicKey);
        return CryptoNative.hssVerify(nativeContext, data, signature, CryptoConstants.HASH_ALG_SHA256);
    }

    public HSSParameterSpec getParams() {
        return params;
    }
}
