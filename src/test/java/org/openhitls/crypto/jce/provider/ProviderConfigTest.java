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

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ProviderConfigTest {
    private static final String MAIN_CLASS = ProviderConfigDirectCall.class.getName();

    @Test(expected = IllegalArgumentException.class)
    public void testLoadProviderRejectsNullPathBeforeNativeLoad() {
        ProviderConfig.loadProvider(null, "SDFProv");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testLoadProviderRejectsNullNameBeforeNativeLoad() {
        ProviderConfig.loadProvider("/tmp", null, null);
    }

    @Test
    public void testProviderConfigLoadsNativeBeforeDirectNativeCall() throws Exception {
        String classPath = System.getProperty("java.class.path");
        String nativePath = System.getProperty("openhitls.native.path");

        List<String> command = new ArrayList<>();
        command.add(new File(System.getProperty("java.home"), "bin/java").getAbsolutePath());
        if (nativePath != null && !nativePath.trim().isEmpty()) {
            command.add("-Dopenhitls.native.path=" + nativePath);
        }
        command.add("-cp");
        command.add(classPath);
        command.add(MAIN_CLASS);

        Process process = new ProcessBuilder(command)
            .redirectErrorStream(true)
            .start();
        StringBuilder output = new StringBuilder();
        Thread outputReader = startOutputReader(process.getInputStream(), output);

        assertTrue("ProviderConfig direct-call process timed out. Output:\n" + output,
            process.waitFor(30, TimeUnit.SECONDS));
        outputReader.join(TimeUnit.SECONDS.toMillis(5));
        assertEquals("ProviderConfig direct-call process should exit successfully. Output:\n" + output,
            0, process.exitValue());
    }

    private static Thread startOutputReader(final InputStream input, final StringBuilder output) {
        Thread reader = new Thread(new Runnable() {
            @Override
            public void run() {
                byte[] buffer = new byte[1024];
                int len;
                try {
                    while ((len = input.read(buffer)) != -1) {
                        output.append(new String(buffer, 0, len));
                    }
                } catch (IOException e) {
                    output.append("\nFailed to read child process output: ").append(e);
                }
            }
        }, "provider-config-test-output-reader");
        reader.setDaemon(true);
        reader.start();
        return reader;
    }

    public static final class ProviderConfigDirectCall {
        private ProviderConfigDirectCall() {
        }

        public static void main(String[] args) throws IOException {
            ProviderConfig.unloadProvider();
        }
    }
}
