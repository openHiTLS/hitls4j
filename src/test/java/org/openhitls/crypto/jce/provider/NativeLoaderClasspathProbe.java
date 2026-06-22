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
