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

public class LMSParameterSpec extends StatefulHBSParameterSpec {
    private final String lmsType;
    private final String otsType;

    public LMSParameterSpec(String lmsType, String otsType) {
        super(canonical(lmsType, otsType));
        this.lmsType = normalizeLmsType(lmsType);
        this.otsType = normalizeOtsType(otsType);
    }

    private static String canonical(String lmsType, String otsType) {
        return normalizeLmsType(lmsType) + "/" + normalizeOtsType(otsType);
    }

    static String normalizeLmsType(String name) {
        if (name == null) {
            throw new NullPointerException("lmsType cannot be null");
        }
        String normalized = name.replace('-', '_');
        if (!normalized.startsWith("CRYPT_")) {
            normalized = "CRYPT_" + normalized;
        }
        if (!normalized.matches("^CRYPT_LMS_SHA256_M32_H(5|10|15|20|25)$")) {
            throw new IllegalArgumentException("Unsupported LMS tree type: " + name);
        }
        return normalized;
    }

    static String normalizeOtsType(String name) {
        if (name == null) {
            throw new NullPointerException("otsType cannot be null");
        }
        String normalized = name.replace('-', '_');
        if (!normalized.startsWith("CRYPT_")) {
            normalized = "CRYPT_" + normalized;
        }
        if (!normalized.matches("^CRYPT_LMOTS_SHA256_N32_W(1|2|4|8)$")) {
            throw new IllegalArgumentException("Unsupported LM-OTS type: " + name);
        }
        return normalized;
    }

    public String getLmsType() {
        return lmsType;
    }

    public String getOtsType() {
        return otsType;
    }
}
