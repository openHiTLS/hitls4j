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

package org.openhitls.crypto;

import org.junit.BeforeClass;
import java.io.File;
import java.security.Security;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class BaseTest {
    @BeforeClass
    public static void loadNativeLibraries() {
        if (isBlank(System.getProperty("openhitls.native.path"))) {
            File nativeDir = new File(System.getProperty("user.dir"), "target/native");
            if (nativeDir.isDirectory()) {
                System.setProperty("openhitls.native.path", nativeDir.getAbsolutePath());
            }
        }

        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
