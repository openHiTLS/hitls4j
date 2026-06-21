package org.openhitls.crypto.jce.provider;

/**
 * Configuration class for loading openHiTLS providers.
 *
 * <p>openHiTLS supports a provider framework that allows plugging in custom
 * cryptographic implementations (e.g., hardware accelerators, HSM drivers,
 * FIPS-compliant modules). This class provides Java API to load and unload
 * openHiTLS providers.</p>
 *
 * <p>When no provider is loaded, HiTLS4J uses the default openHiTLS implementation.
 * After loading a provider, all subsequent cryptographic operations will be
 * delegated to the loaded provider. Provider selection is process-wide: only one
 * external provider may be active, and loading another provider while one is
 * active fails.</p>
 *
 * <h3>Usage Example:</h3>
 * <pre>{@code
 * // Load a custom provider
 * ProviderConfig.loadProvider("/usr/lib/hitls/providers", "custom_hsm");
 *
 * // Operations use the loaded provider for algorithms it exposes
 * MessageDigest md = MessageDigest.getInstance("SM3", "HITLS4J");
 * byte[] digest = md.digest(new byte[] {1, 2, 3});
 *
 * // Application shutdown only, after all provider-backed objects have been finalized:
 * // ProviderConfig.unloadProvider();
 * }</pre>
 */
public class ProviderConfig {
    private static native void loadProviderNative(String providerPath, String providerName, String attrName);
    private static native void unloadProviderNative();

    private static void ensureNativeLoaded() {
        NativeLoader.load();
    }

    /**
     * Load an openHiTLS provider.
     *
     * <p>This is a process-wide operation. It fails if an external provider is
     * already loaded.</p>
     *
     * @param providerPath the directory containing the provider shared library
     * @param providerName the provider name (without lib prefix or .so suffix)
     * @throws IllegalArgumentException if providerPath or providerName is null
     * @throws IllegalStateException if the provider fails to load
     */
    public static synchronized void loadProvider(String providerPath, String providerName) {
        loadProvider(providerPath, providerName, null);
    }

    /**
     * Load an openHiTLS provider with attribute filtering.
     *
     * <p>This is a process-wide operation. It fails if an external provider is
     * already loaded.</p>
     *
     * @param providerPath the directory containing the provider shared library
     * @param providerName the provider name (without lib prefix or .so suffix)
     * @param attrName     attribute string for matching provider capabilities
     *                     (e.g., "provider=custom,fips=yes"), or null to match providerName
     * @throws IllegalArgumentException if providerPath or providerName is null
     * @throws IllegalStateException if the provider fails to load
     */
    public static synchronized void loadProvider(String providerPath, String providerName, String attrName) {
        if (providerPath == null || providerName == null) {
            throw new IllegalArgumentException("Provider path and name must not be null");
        }
        ensureNativeLoaded();
        loadProviderNative(providerPath, providerName, attrName);
    }

    /**
     * Unload the currently loaded openHiTLS provider.
     *
     * <p>After unloading, all new cryptographic operations will revert to using
     * the default openHiTLS implementation.</p>
     *
     * <p>This method releases the native provider library context. Call it only
     * when no cryptographic objects created under the loaded provider are live,
     * in use, or awaiting finalization. Java reachability alone is not enough:
     * pending finalizers may still need the provider context to release their
     * native resources.</p>
     */
    public static synchronized void unloadProvider() {
        ensureNativeLoaded();
        unloadProviderNative();
    }
}
