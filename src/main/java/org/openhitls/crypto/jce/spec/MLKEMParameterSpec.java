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

public class MLKEMParameterSpec implements AlgorithmParameterSpec {
    private final String name;
    public MLKEMParameterSpec(String name) {
        this.name = name;
    }

    public static final MLKEMParameterSpec MLKEM512 = new MLKEMParameterSpec("ML-KEM-512");
    public static final MLKEMParameterSpec MLKEM768 = new MLKEMParameterSpec("ML-KEM-768");
    public static final MLKEMParameterSpec MLKEM1024 = new MLKEMParameterSpec("ML-KEM-1024");

    public static MLKEMParameterSpec getParamByName(String name) {
        switch(name) {
            case "ML-KEM-512":
                return MLKEM512;
            case "ML-KEM-768":
                return MLKEM768;
            case "ML-KEM-1024":
                return MLKEM1024;
            default:
                throw new IllegalArgumentException("Unsupported parameter set: " + name);
        }
    }

    public String getName() {
        return name;
    }
}
