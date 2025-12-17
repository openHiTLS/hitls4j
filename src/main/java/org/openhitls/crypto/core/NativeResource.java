package org.openhitls.crypto.core;

public abstract class NativeResource {
    protected final long nativeContext;
    protected final FreeCallback freeCallback;

    @FunctionalInterface
    protected interface FreeCallback {
        void freeNativeContext(long nativeContext);
    }

    protected NativeResource(long nativeContext, FreeCallback freeCallback) {
        this.nativeContext = nativeContext;
        this.freeCallback = freeCallback;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (nativeContext != 0 && freeCallback != null) {
                freeCallback.freeNativeContext(nativeContext);
            }
        } finally {
            super.finalize();
        }
    }
}