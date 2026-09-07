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

public class XMSSParameterSpec extends StatefulHBSParameterSpec {
    public XMSSParameterSpec(String name) {
        super(normalize(name));
    }

    public static String normalize(String name) {
        if (name == null) {
            throw new NullPointerException("name cannot be null");
        }
        String normalized = name.replace('-', '_');
        if (!normalized.startsWith("CRYPT_")) {
            normalized = "CRYPT_" + normalized;
        }
        if (!isSupportedParameterSet(normalized)) {
            throw new IllegalArgumentException("Unsupported XMSS parameter set: " + name);
        }
        return normalized;
    }

    private static boolean isSupportedParameterSet(String normalized) {
        String prefix = "CRYPT_XMSS_";
        if (!normalized.startsWith(prefix)) {
            return false;
        }
        String[] parts = normalized.substring(prefix.length()).split("_");
        if (parts.length != 3 || !isOneOf(parts[1], "10", "16", "20")) {
            return false;
        }
        if ("SHA2".equals(parts[0])) {
            return isOneOf(parts[2], "192", "256", "512");
        }
        if ("SHAKE".equals(parts[0])) {
            return isOneOf(parts[2], "256", "512");
        }
        if ("SHAKE256".equals(parts[0])) {
            return isOneOf(parts[2], "192", "256");
        }
        return false;
    }

    private static boolean isOneOf(String value, String... candidates) {
        for (String candidate : candidates) {
            if (candidate.equals(value)) {
                return true;
            }
        }
        return false;
    }
}
