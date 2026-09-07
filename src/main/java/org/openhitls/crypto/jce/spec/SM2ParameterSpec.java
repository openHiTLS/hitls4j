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
import java.util.Arrays;

/**
 * Parameter spec for SM2 ID parameter
 */
public class SM2ParameterSpec implements AlgorithmParameterSpec {
    private byte[] id;

    /**
     * Base constructor.
     *
     * @param id the ID string associated with this usage of SM2.
     */
    public SM2ParameterSpec(byte[] id) {
        if (id == null) {
            throw new NullPointerException("id string cannot be null");
        }
        this.id = Arrays.copyOf(id, id.length);
    }

    /**
     * Return the ID value.
     *
     * @return the ID string.
     */
    public byte[] getId() {
        return Arrays.copyOf(id, id.length);
    }
}
