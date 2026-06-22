package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.jce.spec.XMSSParameterSpec;

public class XMSSImpl extends NativeResource {
    private final XMSSParameterSpec params;

    public XMSSImpl(XMSSParameterSpec params) {
        super(CryptoNative.xmssCreateContext(params.getName()), CryptoNative::xmssFreeContext);
        this.params = params;
    }

    public byte[][] generateKeyPair() {
        return CryptoNative.xmssGenerateKeyPair(nativeContext);
    }

    public StatefulHBSSignResult sign(byte[] privateKey, byte[] data) {
        CryptoNative.xmssSetPrivateKey(nativeContext, privateKey);
        byte[][] result = CryptoNative.xmssSignAndExportState(nativeContext, data);
        return new StatefulHBSSignResult(result[0], result[1]);
    }

    public boolean verify(byte[] publicKey, byte[] data, byte[] signature) {
        CryptoNative.xmssSetPublicKey(nativeContext, publicKey);
        return CryptoNative.xmssVerify(nativeContext, data, signature);
    }

    public XMSSParameterSpec getParams() {
        return params;
    }
}
