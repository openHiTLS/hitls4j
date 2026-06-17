package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.jce.spec.XMSSMTParameterSpec;

public class XMSSMTImpl extends NativeResource {
    private final XMSSMTParameterSpec params;

    public XMSSMTImpl(XMSSMTParameterSpec params) {
        super(CryptoNative.xmssmtCreateContext(params.getName()), CryptoNative::xmssmtFreeContext);
        this.params = params;
    }

    public byte[][] generateKeyPair() {
        return CryptoNative.xmssmtGenerateKeyPair(nativeContext);
    }

    public StatefulHBSSignResult sign(byte[] privateKey, byte[] data) {
        CryptoNative.xmssmtSetPrivateKey(nativeContext, privateKey);
        byte[][] result = CryptoNative.xmssmtSignAndExportState(nativeContext, data);
        return new StatefulHBSSignResult(result[0], result[1]);
    }

    public boolean verify(byte[] publicKey, byte[] data, byte[] signature) {
        CryptoNative.xmssmtSetPublicKey(nativeContext, publicKey);
        return CryptoNative.xmssmtVerify(nativeContext, data, signature);
    }

    public XMSSMTParameterSpec getParams() {
        return params;
    }
}
