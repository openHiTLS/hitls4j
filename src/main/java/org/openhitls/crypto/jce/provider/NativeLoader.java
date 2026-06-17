package org.openhitls.crypto.jce.provider;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

public class NativeLoader {
    private static final String JNI_LIBRARY = "libhitls_crypto_jni.so";
    private static final String[] OPENHITLS_LIBRARIES = {
        "libhitls_bsl.so",
        "libhitls_crypto.so",
        "libhitls_auth.so",
        "libhitls_pki.so",
        "libhitls_tls.so"
    };
    private static final Set<PosixFilePermission> OWNER_ONLY_PERMISSIONS =
            PosixFilePermissions.fromString("rwx------");

    private static boolean loaded = false;
    
    public static synchronized void load() {
        if (loaded) {
            return;
        }

        if (hasConfiguredPath()) {
            loadFromConfiguredPath();
            loaded = true;
            return;
        }

        UnsatisfiedLinkError failure = null;

        try {
            System.loadLibrary("hitls_crypto_jni");
            loaded = true;
            return;
        } catch (UnsatisfiedLinkError e) {
            failure = e;
        }

        try {
            loadFromJar();
        } catch (UnsatisfiedLinkError e) {
            if (failure != null) {
                e.addSuppressed(failure);
            }
            throw e;
        }

        loaded = true;
    }

    private static boolean hasConfiguredPath() {
        return hasText(System.getProperty("openhitls.native.path"));
    }

    private static void loadFromConfiguredPath() {
        String nativePath = System.getProperty("openhitls.native.path");
        loadFromDirectory(new File(nativePath.trim()));
    }

    private static boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private static void loadFromDirectory(File directory) {
        validateDirectoryLoadSet(directory);
        loadOpenHiTLSLibrariesUnchecked(directory);
        System.load(new File(directory, JNI_LIBRARY).getAbsolutePath());
    }

    private static void validateDirectoryLoadSet(File directory) {
        if (!directory.isDirectory()) {
            throw new UnsatisfiedLinkError("Native library directory not found: " + directory.getAbsolutePath());
        }
        for (String library : OPENHITLS_LIBRARIES) {
            requireLibraryFile(directory, library);
        }
        requireLibraryFile(directory, JNI_LIBRARY);
    }

    private static void requireLibraryFile(File directory, String library) {
        File libraryFile = new File(directory, library);
        if (!libraryFile.isFile()) {
            throw new UnsatisfiedLinkError("Native library not found: " + libraryFile.getAbsolutePath());
        }
    }

    private static void loadOpenHiTLSLibrariesUnchecked(File directory) {
        for (String library : OPENHITLS_LIBRARIES) {
            System.load(new File(directory, library).getAbsolutePath());
        }
    }

    private static void loadFromJar() {
        try {
            Path tempDir = createPrivateTempDirectory();
            tempDir.toFile().deleteOnExit();

            String[] libNames = {
                "libhitls_bsl.so",
                "libhitls_crypto.so",
                "libhitls_auth.so",
                "libhitls_pki.so",
                "libhitls_tls.so",
                "libhitls_crypto_jni.so"
            };

            File jniFile = null;

            for (String libName : libNames) {
                File tempFile = extractLibrary(libName, tempDir);
                if ("libhitls_crypto_jni.so".equals(libName)) {
                    jniFile = tempFile;
                } else {
                    System.load(tempFile.getAbsolutePath());
                }
            }

            if (jniFile == null) {
                throw new UnsatisfiedLinkError("Native JNI library not found in JAR");
            }

            loadJniLibrary(tempDir);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load native library", e);
        }
    }

    private static Path createPrivateTempDirectory() throws IOException {
        try {
            return Files.createTempDirectory("hitls4j-native-",
                    PosixFilePermissions.asFileAttribute(OWNER_ONLY_PERMISSIONS));
        } catch (UnsupportedOperationException e) {
            Path tempDir = Files.createTempDirectory("hitls4j-native-");
            setOwnerOnlyPermissions(tempDir);
            return tempDir;
        }
    }

    private static void loadJniLibrary(Path directory) {
        System.load(directory.resolve(JNI_LIBRARY).toAbsolutePath().toString());
    }

    private static File extractLibrary(String libName, Path tempDir) throws IOException {
        String libPath = "/META-INF/native/" + libName;

        try (InputStream in = NativeLoader.class.getResourceAsStream(libPath)) {
            if (in == null) {
                throw new UnsatisfiedLinkError("Native library not found in JAR: " + libPath);
            }

            File tempFile = tempDir.resolve(libName).toFile();
            tempFile.deleteOnExit();
            Path tempPath = tempFile.toPath();
            Files.copy(in, tempPath, StandardCopyOption.REPLACE_EXISTING);
            setOwnerOnlyPermissions(tempPath);
            return tempFile;
        }
    }

    private static void setOwnerOnlyPermissions(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY_PERMISSIONS);
            return;
        } catch (UnsupportedOperationException e) {
        } catch (IOException e) {
            throw e;
        } catch (SecurityException e) {
            throw new IOException("Failed to set permissions on native library path: " + path, e);
        }

        File file = path.toFile();
        if (!file.setReadable(false, false)
                || !file.setWritable(false, false)
                || !file.setExecutable(false, false)
                || !file.setReadable(true, true)
                || !file.setWritable(true, true)
                || !file.setExecutable(true, true)) {
            throw new IOException("Failed to set owner-only permissions on native library path: " + path);
        }
    }
}
