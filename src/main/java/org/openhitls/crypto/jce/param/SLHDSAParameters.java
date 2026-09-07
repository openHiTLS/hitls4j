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

package org.openhitls.crypto.jce.param;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.openhitls.crypto.jce.spec.SLHDSAParameterSpec;

public class SLHDSAParameters extends AlgorithmParametersSpi{
    private SLHDSAParameterSpec slhdsaParameterSpec;

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new NullPointerException("paramSpec is null");
        }

        if (SLHDSAParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (slhdsaParameterSpec == null) {
                throw new InvalidParameterSpecException("SLHDSAParameterSpec not initialized");
            }
            return (T)slhdsaParameterSpec;
        }

        throw new InvalidParameterSpecException("Unknow parameter spec: " + paramSpec.getName());
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec instanceof SLHDSAParameterSpec) {
            slhdsaParameterSpec = (SLHDSAParameterSpec)paramSpec;
        } else {
            throw new InvalidParameterSpecException("Spec is not SLHDSAParameterSpec");
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected String engineToString() {
        return "SLH-DSA parameters";
    }
    
}
