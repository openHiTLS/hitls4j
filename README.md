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

## Requirements

- Java 17 or higher
- openHiTLS library installed on the system
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

2. Configure the openHiTLS root directory in `pom.xml`:
   ```xml
   <properties>
       <openhitls.root>/path/to/openhitls</openhitls.root>
   </properties>
   ```

3. Build the project:
   ```
   mvn clean package
   ```

## Usage

### Registering the Provider

```java
import java.security.Security;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

// Register the provider
Security.addProvider(new HiTls4jProvider());
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
- `SHA224withRSA`, `SHA256withRSA`, `SHA384withRSA`, `SHA512withRSA`, `SM3withRSA`
- `SHA224withRSA/PSS`, `SHA256withRSA/PSS`, `SHA384withRSA/PSS`, `SHA512withRSA/PSS`, `SM3withRSA/PSS`
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

## License

This project is licensed under the terms of the license included in the repository.

## Acknowledgments

- This project is based on the openHiTLS cryptographic library
- Thanks to all contributors who have helped with the development of this project