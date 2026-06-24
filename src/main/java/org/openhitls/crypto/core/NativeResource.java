package org.openhitls.crypto.core;

public abstract class NativeResource implements AutoCloseable {
    protected final long nativeContext;
    protected final FreeCallback freeCallback;
    private boolean closed;

    @FunctionalInterface
    protected interface FreeCallback {
        void freeNativeContext(long nativeContext);
    }

    protected NativeResource(long nativeContext, FreeCallback freeCallback) {
        this.nativeContext = nativeContext;
        this.freeCallback = freeCallback;
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        if (nativeContext != 0 && freeCallback != null) {
            freeCallback.freeNativeContext(nativeContext);
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
}
