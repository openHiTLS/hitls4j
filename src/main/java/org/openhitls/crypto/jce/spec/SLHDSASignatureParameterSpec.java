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

package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class SLHDSASignatureParameterSpec implements AlgorithmParameterSpec{
    private final boolean deterministic;
    private final boolean preHash;
    private final byte[] context;

    public SLHDSASignatureParameterSpec(boolean deterministic, boolean preHash, byte[] context) {
        this.deterministic = deterministic;
        this.preHash = preHash;
        this.context = context != null ? context.clone() : null;
    }

    public boolean isDeterministic(){
        return deterministic;
    }

    public boolean isPreHash() {
        return preHash;
    }

    public byte[] getContext() {
        return context != null ? context.clone() : null;
    }
}
