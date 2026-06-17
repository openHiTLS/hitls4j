# HiTLS4J

HiTLS4J is a Java Cryptography Extension (JCE) provider that wraps the native openHiTLS cryptographic library. It provides a complete implementation of the JCE API, allowing Java applications to use the cryptographic algorithms provided by openHiTLS through standard Java security interfaces.

## Overview

HiTLS4J integrates the openHiTLS cryptographic library with Java applications through JNI (Java Native Interface). It implements a JCE provider that can be registered with the Java Security framework, enabling the use of various cryptographic algorithms through standard Java APIs.

## Features

HiTLS4J provides the following cryptographic functionalities:

### Symmetric Ciphers
- **AES**: Supports ECB, CBC, CTR, and GCM modes with various padding options
- **SM4**: Supports ECB, CBC, CTR, GCM, CFB, OFB, and XTS modes with various padding options

### Asymmetric Ciphers
- **RSA**: Encryption/decryption with PKCS#1 padding
- **SM2**: Chinese standard for elliptic curve-based asymmetric encryption

### Message Digests
- **SHA Family**: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- **SHA3 Family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- **SM3**: Chinese cryptographic hash function

### Message Authentication Codes (MACs)
- **HMAC**: With all supported hash algorithms (SHA family, SHA3 family, SM3)

### Digital Signatures
- **RSA**: With SHA-224, SHA-256, SHA-384, SHA-512, and SM3 hash algorithms
- **RSA-PSS**: Probabilistic Signature Scheme with various hash algorithms
- **DSA**: Digital Signature Algorithm with various hash algorithms
- **ECDSA**: Elliptic Curve Digital Signature Algorithm
- **SM2**: Chinese standard for elliptic curve-based digital signatures

### Key Generation
- **RSA**: Key pair generation
- **DSA**: Key pair generation
- **EC**: Key pair generation for various curves (secp256r1, secp384r1, secp521r1, sm2p256v1)
- **Symmetric Keys**: Generation for AES and SM4

### Provider Integration
- **External openHiTLS providers**: HiTLS4J can load an external openHiTLS provider for algorithms exposed by that provider

## Requirements

- Java 8 or higher
- Maven 3.x
- openHiTLS headers and shared libraries built on the system
- GCC compiler for building the JNI component

## Installation

### Prerequisites

1. Install the openHiTLS library on your system
2. Set the `JAVA_HOME` environment variable to your JDK installation
3. Ensure GCC is available in your PATH

### Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/hitls4j.git
   cd hitls4j
   ```

2. Configure the openHiTLS root directory for Maven:
   ```
   export OPENHITLS_ROOT=/path/to/openhitls
   ```

   You can also pass `-Dopenhitls.root=/path/to/openhitls` to Maven, or add
   `-Dopenhitls.root=/path/to/openhitls` to `.mvn/maven.config`.
   This setting is used at build time to find openHiTLS headers and libraries.

3. Build the project:
   ```
   mvn clean package
   ```

The default build only requires openHiTLS. It builds `libhitls_crypto_jni.so`,
copies the required `libhitls_*.so` files into `target/native`, and packages
those native libraries under `META-INF/native` in the JAR. It does not copy or
package external provider libraries.

You can also pass the openHiTLS root directly:

```
mvn clean package -Dopenhitls.root=/path/to/openhitls
```

### Native Library Loading

At runtime, `OPENHITLS_ROOT` and `openhitls.root` are not treated as native
library directories and are not used to locate hitls4j's JNI library.

When running from a local build, pass the complete native output directory:

```
java -Dopenhitls.native.path=target/native ...
```

The directory configured by `openhitls.native.path` must contain both
`libhitls_crypto_jni.so` and the required openHiTLS shared libraries.
If no native path is configured, HiTLS4J falls back to packaged native libraries.
Packaged native libraries are stored directly under `META-INF/native`; each JAR
contains one native build and does not select an architecture-specific
subdirectory at runtime.

### Using External Providers From the JAR

For a normal application, the HiTLS4J JAR provides the Java JCE provider and the
JNI bridge. External openHiTLS providers are loaded separately from a provider
directory on the target machine.

If you use the JAR produced by `mvn package`, the required HiTLS4J/openHiTLS
native libraries are packaged in the JAR and are extracted automatically. If you
run from an unpackaged local build instead, pass `openhitls.native.path` as
described above.

Load the external openHiTLS provider once during application startup, before
creating HiTLS4J cryptographic objects:

```java
import java.security.MessageDigest;
import java.security.Security;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.provider.ProviderConfig;

public final class ProviderExample {
    public static void main(String[] args) throws Exception {
        // Directory containing lib<providerName>.so.
        String providerPath = "/path/to/openhitls/providers";
        String providerName = "custom_hsm";

        ProviderConfig.loadProvider(providerPath, providerName);
        Security.addProvider(new HiTls4jProvider());

        // Use algorithms exposed by the loaded provider.
        MessageDigest md = MessageDigest.getInstance("SM3", HiTls4jProvider.PROVIDER_NAME);
        byte[] digest = md.digest(new byte[] {1, 2, 3});
    }
}
```

Run the application with the HiTLS4J JAR on the classpath:

```
java -cp hitls4j-1.0.jar:your-app.jar com.example.ProviderExample
```

The provider path passed to `ProviderConfig.loadProvider(...)` is the directory
that contains the external provider shared library. For provider name
`custom_hsm`, openHiTLS loads `libcustom_hsm.so` from that directory.

Some external providers need their own configuration, such as hardware SDK
libraries or backend shared libraries. Configure those dependencies according to
the external provider's own rules before starting the JVM. HiTLS4J does not
define provider-specific parameters; `ProviderConfig.loadProvider(...)` only
loads the openHiTLS provider and selects it for later HiTLS4J operations.

Provider lifecycle restrictions:

- Treat `ProviderConfig.loadProvider(...)` and `unloadProvider()` as
  process-wide provider selection operations.
- Only one external provider may be active at a time. Calling
  `loadProvider(...)` while a provider is already loaded fails; provider
  replacement/switching is not supported.
- `unloadProvider()` releases the loaded native provider library context and
  returns new HiTLS4J operations to the default openHiTLS implementation.
- Do not call load or unload concurrently with HiTLS4J cryptographic context
  creation or operations.
- Load and unload external providers only at application quiescent points, before
  worker threads create cryptographic objects and after all cryptographic
  objects created under the loaded provider have been finalized.
- Do not call `unloadProvider()` while any cryptographic object created under the
  loaded provider is live, in use, or awaiting finalization. Pending finalizers
  may still need the provider library context to release native resources.

Use one consistent openHiTLS build across HiTLS4J, the external provider, and
its provider-specific dependencies where possible. Mixing shared libraries built
against different openHiTLS trees can cause provider loading or symbol
resolution failures.

## Usage

### Registering the Provider

```java
import java.security.Security;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

// Register the provider
Security.addProvider(new HiTls4jProvider());
```

### Using Symmetric Encryption (SM4)

```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

// Create 128-bit SM4 key
byte[] keyBytes = new byte[16];
new java.security.SecureRandom().nextBytes(keyBytes);

SecretKeySpec key = new SecretKeySpec(keyBytes, "SM4");

// ECB mode with NoPadding
Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", HiTls4jProvider.PROVIDER_NAME);
cipher.init(Cipher.ENCRYPT_MODE, key);

// Data must be block-aligned (16 bytes for SM4) when using NoPadding
byte[] plaintext = new byte[32]; // 2 blocks
new java.security.SecureRandom().nextBytes(plaintext);

byte[] ciphertext = cipher.doFinal(plaintext);

// Decrypt
cipher.init(Cipher.DECRYPT_MODE, key);
byte[] decrypted = cipher.doFinal(ciphertext);
```

### Using Symmetric Encryption (AES)

```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

// Create key and IV
byte[] keyBytes = new byte[16]; // 128-bit key
byte[] ivBytes = new byte[16];  // 16-byte IV
// ... initialize key and IV with secure random data

// Create key specification
SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
IvParameterSpec iv = new IvParameterSpec(ivBytes);

// Create and initialize cipher
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", HiTls4jProvider.PROVIDER_NAME);
cipher.init(Cipher.ENCRYPT_MODE, key, iv);

// Encrypt data
byte[] plaintext = "Hello, world!".getBytes();
byte[] ciphertext = cipher.doFinal(plaintext);

// Decrypt data
cipher.init(Cipher.DECRYPT_MODE, key, iv);
byte[] decrypted = cipher.doFinal(ciphertext);
```

### Using Message Digest (SHA-256)

```java
import java.security.MessageDigest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

// Create message digest
MessageDigest md = MessageDigest.getInstance("SHA-256", HiTls4jProvider.PROVIDER_NAME);

// Compute hash
byte[] data = "Hello, world!".getBytes();
byte[] hash = md.digest(data);
```

### Using HMAC

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

// Create key
byte[] keyBytes = new byte[32]; // 256-bit key
// ... initialize key with secure random data
SecretKeySpec key = new SecretKeySpec(keyBytes, "HMACSHA256");

// Create and initialize HMAC
Mac mac = Mac.getInstance("HMACSHA256", HiTls4jProvider.PROVIDER_NAME);
mac.init(key);

// Compute HMAC
byte[] data = "Hello, world!".getBytes();
byte[] hmac = mac.doFinal(data);
```

### Using RSA Signatures

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

// Generate key pair
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
keyGen.initialize(2048);
KeyPair keyPair = keyGen.generateKeyPair();

// Create and initialize signature
Signature signature = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
signature.initSign(keyPair.getPrivate());

// Sign data
byte[] data = "Hello, world!".getBytes();
signature.update(data);
byte[] signatureBytes = signature.sign();

// Verify signature
signature.initVerify(keyPair.getPublic());
signature.update(data);
boolean valid = signature.verify(signatureBytes);
```

### RSA Key Encoding and Decoding

RSA key import and export are part of the HiTLS4J provider contract. RSA public
keys support X.509 `SubjectPublicKeyInfo` encoding, and RSA private keys use
PKCS#8 encoding. Encoded RSA keys are accepted through standard JCE key
specifications such as `X509EncodedKeySpec`, `PKCS8EncodedKeySpec`,
`RSAPublicKeySpec`, and `RSAPrivateKeySpec`.

RSA public key DER operations and RSA private key PKCS#8 encoding use the
openHiTLS key codec APIs (`CRYPT_EAL_EncodeBuffKey` and
`CRYPT_EAL_DecodeBuffKey`). RSA private keys with `n`, `e`, and `d` but without
CRT parameters are PKCS#8 encodable and decodable. Minimal private keys imported
from `RSAPrivateKeySpec` with only `n` and `d` keep the public exponent unknown;
HiTLS4J does not synthesize 65537 for those keys, does not advertise a PKCS#8
encoding for them, and rejects private-key operations that require `e`. HiTLS4J
does not require vendor-specific JDK providers, such as `SunRsaSign`, for RSA
key parsing or re-encoding.

### Using ECDSA Signatures

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

// Generate key pair
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
keyGen.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair keyPair = keyGen.generateKeyPair();

// Create and initialize signature
Signature signature = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
signature.initSign(keyPair.getPrivate());

// Sign data
byte[] data = "Hello, world!".getBytes();
signature.update(data);
byte[] signatureBytes = signature.sign();

// Verify signature
signature.initVerify(keyPair.getPublic());
signature.update(data);
boolean valid = signature.verify(signatureBytes);
```

### Using MLDSA
```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import org.openhitls.crypto.jce.spec.MLDSAGenParameterSpec;
import org.openhitls.crypto.jce.HiTls4jProvider;
import static org.junit.jupiter.api.Assertions.assertTrue;

// Generate key pair
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", HiTls4jProvider.PROVIDER_NAME);
keyGen.initialize(new MLDSAGenParameterSpec("ML-DSA-44"), new SecureRandom());
KeyPair keyPair = keyGen.generateKeyPair();

// Sign data
byte[] data = "Hello, world!".getBytes();
Signature signer = Signature.getInstance("SHA256withMLDSA", HiTls4jProvider.PROVIDER_NAME);
signer.initSign(keyPair.getPrivate());
signer.update(data);
byte[] signature = signer.sign();

// Verify signature
signer.initVerify(keyPair.getPublic());
signer.update(data);
boolean verified = signer.verify(signature);
```

### Using MLKEM

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.KeyAgreement;
import org.openhitls.crypto.jce.spec.MLKEMGenParameterSpec;
import org.openhitls.crypto.jce.spec.MLKEMCiphertextKey;
import org.openhitls.crypto.jce.HiTls4jProvider;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

// Generate key pair
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
keyGen.initialize(new MLKEMGenParameterSpec("ML-KEM-512"), new SecureRandom());
KeyPair keyPair = keyGen.generateKeyPair();

// Encapsulation side
KeyAgreement kaSender = KeyAgreement.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
kaSender.init(keyPair.getPublic());
byte[] ciphertext = kaSender.doPhase(null, true).getEncoded();
byte[] senderSharedKey = kaSender.generateSecret();

// Decapsulation side
KeyAgreement kaReceiver = KeyAgreement.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
kaReceiver.init(keyPair.getPrivate());
kaReceiver.doPhase(new MLKEMCiphertextKey(ciphertext), true);
byte[] receiverSharedKey = kaReceiver.generateSecret();
```

## Supported Algorithms

### Cipher Algorithms
- `AES` (with modes: ECB, CBC, CTR, GCM)
- `SM4` (with modes: ECB, CBC, CTR, GCM, CFB, OFB, XTS)
- `RSA`
- `SM2`

### Message Digest Algorithms
- `SHA-1`
- `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`
- `SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512`
- `SM3`

### MAC Algorithms
- `HMACSHA1`
- `HMACSHA224`, `HMACSHA256`, `HMACSHA384`, `HMACSHA512`
- `HMACSHA3-224`, `HMACSHA3-256`, `HMACSHA3-384`, `HMACSHA3-512`
- `HMACSM3`

### Signature Algorithms
- `SHA1withRSA`, `SHA224withRSA`, `SHA256withRSA`, `SHA384withRSA`, `SHA512withRSA`, `SM3withRSA`
- RSA aliases: `SHA1withRSAEncryption`, `SHA224withRSAEncryption`, `SHA256withRSAEncryption`, `SHA384withRSAEncryption`, `SHA512withRSAEncryption`
- RSA OID aliases: `1.2.840.113549.1.1.5`, `1.2.840.113549.1.1.14`, `1.2.840.113549.1.1.11`, `1.2.840.113549.1.1.12`, `1.2.840.113549.1.1.13`
- `SHA224withRSA/PSS`, `SHA256withRSA/PSS`, `SHA384withRSA/PSS`, `SHA512withRSA/PSS`
- `SM3withRSA/PSS` is not supported because the native RSA-PSS parameter path rejects SM3.
- `SHA256withECDSA`, `SHA384withECDSA`, `SHA512withECDSA`
- `SM3withSM2`

### Key Generation Algorithms
- `RSA`
- `DSA`
- `EC` (with curves: secp256r1, secp384r1, secp521r1, sm2p256v1)
- `AES`
- `SM4`

### PQC Algorithms
- `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`
- `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`
- `SLH-DSA-SHA2-128s`, `SLH-DSA-SHA2-128f`, `SLH-DSA-SHA2-192s`, `SLH-DSA-SHA2-192f`, `SLH-DSA-SHA2-256s`, `SLH-DSA-SHA2-256f`
- `SLH-DSA-SHAKE-128s`, `SLH-DSA-SHAKE-128f`, `SLH-DSA-SHAKE-192s`, `SLH-DSA-SHAKE-192f`, `SLH-DSA-SHAKE-256s`, `SLH-DSA-SHAKE-256f`
- `FrodoKEM-640-SHAKE`, `FrodoKEM-640-AES`, `FrodoKEM-976-SHAKE`, `FrodoKEM-976-AES`, `FrodoKEM-1344-SHAKE`, `FrodoKEM-1344-AES`
- `McEliece-6688128`, `McEliece-6688128f`, `McEliece-6688128pc`, `McEliece-6688128pcf`
- `McEliece-6960119`, `McEliece-6960119f`, `McEliece-6960119pc`, `McEliece-6960119pcf`
- `McEliece-8192128`, `McEliece-8192128f`, `McEliece-8192128pc`, `McEliece-8192128pcf`

## License

This project is licensed under the terms of the license included in the repository.

## Acknowledgments

- This project is based on the openHiTLS cryptographic library
- Thanks to all contributors who have helped with the development of this project
