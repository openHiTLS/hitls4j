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

package org.openhitls.crypto.jce.provider;

public final class NativeLoaderClasspathProbe {
    private NativeLoaderClasspathProbe() {
    }

    public static void main(String[] args) {
        if (System.getProperty("openhitls.native.path") != null) {
            throw new IllegalStateException("openhitls.native.path must not be set for classpath fallback probe");
        }
        NativeLoader.load();
    }
}
