package org.openhitls.crypto.jce.provider;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class NativeLoader {
    private static boolean loaded = false;
    
    public static synchronized void load() {
        if (loaded) {
            return;
        }
        
        // Load from system library path
        try {
            System.loadLibrary("hitls_crypto_jni");
        } catch (UnsatisfiedLinkError e) {
            // Fallback to loading from JAR
            loadFromJar();
        }
        
        loaded = true;
    }
    
    private static void loadFromJar() {
        try {
            String libName = "libhitls_crypto_jni.so";
            String libPath = "/META-INF/native/linux-x86_64/" + libName;
            
            try (InputStream in = NativeLoader.class.getResourceAsStream(libPath)) {
                if (in == null) {
                    throw new UnsatisfiedLinkError("Native library not found in JAR: " + libPath);
                }
                
                Path tempDir = Files.createTempDirectory("hitls4j-native");
                tempDir.toFile().deleteOnExit();
                File tempFile = new File(tempDir.toFile(), libName);
                tempFile.deleteOnExit();
                
                Files.copy(in, tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                System.load(tempFile.getAbsolutePath());
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load native library", e);
        }
    }
}