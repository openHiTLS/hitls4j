package org.openhitls.crypto.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

public class NativeResourceUtilTest {
    @Test
    public void testReplaceAfterClosingReturnsReplacementWhenPreviousCloses() {
        AtomicInteger previousCloseCount = new AtomicInteger();
        AtomicInteger replacementCloseCount = new AtomicInteger();
        TestResource previous = new TestResource(previousCloseCount);
        TestResource replacement = new TestResource(replacementCloseCount);

        TestResource result = NativeResourceUtil.replaceAfterClosing(previous, replacement, failure -> failure);

        assertSame(replacement, result);
        assertEquals(1, previousCloseCount.get());
        assertEquals(0, replacementCloseCount.get());
    }

    @Test
    public void testReplaceAfterClosingLeavesReplacementOwnedByCallerOnCloseFailure() {
        RuntimeException previousFailure = new RuntimeException("previous close failed");
        AtomicInteger replacementCloseCount = new AtomicInteger();
        TestResource previous = new TestResource(previousFailure);
        TestResource replacement = new TestResource(replacementCloseCount);

        try {
            NativeResourceUtil.replaceAfterClosing(previous, replacement,
                    failure -> new IllegalStateException("replace failed", failure));
            fail("Expected replacement to fail when previous close fails");
        } catch (IllegalStateException expected) {
            assertSame(previousFailure, expected.getCause());
        }

        assertEquals(0, replacementCloseCount.get());
        NativeResourceUtil.closeSuppressing(replacement, new RuntimeException("primary"));
        assertEquals(1, replacementCloseCount.get());
    }

    @Test
    public void testCloseFailureDoesNotRetryNativeFree() {
        RuntimeException closeFailure = new RuntimeException("close failed");
        AtomicInteger closeCount = new AtomicInteger();
        TestResource resource = new TestResource(closeCount, closeFailure);

        try {
            resource.close();
            fail("Expected close failure");
        } catch (RuntimeException expected) {
            assertSame(closeFailure, expected);
        }

        resource.close();
        assertEquals(1, closeCount.get());
    }

    private static final class TestResource extends NativeResource {
        private TestResource(AtomicInteger closeCount) {
            super(1L, ignored -> closeCount.incrementAndGet());
        }

        private TestResource(RuntimeException closeFailure) {
            super(1L, ignored -> {
                throw closeFailure;
            });
        }

        private TestResource(AtomicInteger closeCount, RuntimeException closeFailure) {
            super(1L, ignored -> {
                closeCount.incrementAndGet();
                throw closeFailure;
            });
        }
    }
}
