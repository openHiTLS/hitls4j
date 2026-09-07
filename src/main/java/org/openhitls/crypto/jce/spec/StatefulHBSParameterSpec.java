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

public abstract class StatefulHBSParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    protected StatefulHBSParameterSpec(String name) {
        if (name == null) {
            throw new NullPointerException("name cannot be null");
        }
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
