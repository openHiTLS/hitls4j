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
