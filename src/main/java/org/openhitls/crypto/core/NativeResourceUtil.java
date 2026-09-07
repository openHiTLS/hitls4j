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

import java.util.function.Function;

public final class NativeResourceUtil {
    private NativeResourceUtil() {
    }

    public static RuntimeException closeAndCapture(NativeResource resource) {
        if (resource == null) {
            return null;
        }
        try {
            resource.close();
            return null;
        } catch (RuntimeException closeFailure) {
            return closeFailure;
        }
    }

    public static void closeSuppressing(NativeResource resource, Throwable primaryFailure) {
        RuntimeException closeFailure = closeAndCapture(resource);
        if (closeFailure != null) {
            primaryFailure.addSuppressed(closeFailure);
        }
    }

    /**
     * Closes the current resource before publishing a replacement.
     * If closing fails, the replacement remains owned by the caller.
     */
    public static <T extends NativeResource, E extends Exception> T replaceAfterClosing(
            T current, T replacement, Function<RuntimeException, E> exceptionFactory) throws E {
        RuntimeException closeFailure = closeAndCapture(current);
        if (closeFailure != null) {
            throw exceptionFactory.apply(closeFailure);
        }
        return replacement;
    }
}
