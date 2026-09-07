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
