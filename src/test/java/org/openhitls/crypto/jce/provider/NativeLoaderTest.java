package org.openhitls.crypto.jce.provider;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Test;

public class NativeLoaderTest {
    @Test
    public void testLoadsFromPackagedClasspathNativeDirectory() throws Exception {
        Path emptyLibraryPath = Files.createTempDirectory("hitls4j-empty-library-path-");
        Process process = new ProcessBuilder(
                javaExecutable(),
                "-Djava.library.path=" + emptyLibraryPath.toAbsolutePath(),
                "-cp", System.getProperty("java.class.path"),
                NativeLoaderClasspathProbe.class.getName())
                .redirectErrorStream(true)
                .start();

        String output = readFully(process.getInputStream());
        assertEquals(output, 0, process.waitFor());
    }

    private static String javaExecutable() {
        String executable = isWindows() ? "java.exe" : "java";
        return new File(new File(System.getProperty("java.home"), "bin"), executable).getAbsolutePath();
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static String readFully(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = input.read(buffer)) != -1) {
            output.write(buffer, 0, read);
        }
        return new String(output.toByteArray(), StandardCharsets.UTF_8);
    }
}
