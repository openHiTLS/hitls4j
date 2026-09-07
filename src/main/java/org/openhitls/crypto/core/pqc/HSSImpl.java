/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 *
 * hitls4j is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

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
