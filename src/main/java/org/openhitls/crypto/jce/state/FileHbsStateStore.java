package org.openhitls.crypto.jce.state;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class FileHbsStateStore implements HbsStateStore {
    private static final String MAGIC = "HITLS4J-HBS-STATE";
    private static final int FORMAT_VERSION = 1;
    private static final int CHECKSUM_LEN = 32;
    private static final int MAX_STATE_FIELD_LEN = 16 * 1024 * 1024;
    private static final long MAX_STATE_FILE_LEN = CHECKSUM_LEN + (2L * MAX_STATE_FIELD_LEN) + (3L * 65535L) + 1024L;
    private static final ConcurrentHashMap<Path, Object> JVM_LOCKS = new ConcurrentHashMap<>();

    private final Path directory;
    private final byte[] integrityKey;

    public FileHbsStateStore(Path directory) {
        this(directory, null);
    }

    public FileHbsStateStore(Path directory, byte[] integrityKey) {
        if (directory == null) {
            throw new NullPointerException("directory cannot be null");
        }
        if (integrityKey != null && integrityKey.length == 0) {
            throw new IllegalArgumentException("integrityKey cannot be empty");
        }
        this.directory = directory;
        this.integrityKey = integrityKey == null ? null : integrityKey.clone();
    }

    @Override
    public HbsStateRecord load(String keyId) throws IOException, GeneralSecurityException {
        String normalizedKeyId = safeKeyId(keyId);
        HbsStateRecord record = readRecord(statePath(normalizedKeyId));
        if (!sameKeyId(normalizedKeyId, record.getKeyId())) {
            throw new GeneralSecurityException("HBS state keyId mismatch");
        }
        return record;
    }

    @Override
    public void save(HbsStateRecord record) throws IOException, GeneralSecurityException {
        Files.createDirectories(directory);
        Path path = statePath(record.getKeyId());
        Path lockPath = lockPath(record.getKeyId());
        synchronized (jvmLock(lockPath)) {
            try (FileChannel lockChannel = FileChannel.open(lockPath,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock ignored = lockChannel.lock()) {
                ensureMonotonicVersion(path, record);
                writeRecordAtomically(path, record);
            }
        }
    }

    @Override
    public HbsSignCommit withExclusiveSigningState(String keyId, HbsStateTransaction transaction)
            throws IOException, GeneralSecurityException {
        Files.createDirectories(directory);
        String normalizedKeyId = safeKeyId(keyId);
        Path lockPath = lockPath(keyId);
        synchronized (jvmLock(lockPath)) {
            try (FileChannel lockChannel = FileChannel.open(lockPath,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock ignored = lockChannel.lock()) {
                HbsStateRecord current = load(normalizedKeyId);
                HbsSignCommit commit = transaction.apply(current);
                if (!sameKeyId(normalizedKeyId, commit.getUpdatedState().getKeyId())) {
                    throw new GeneralSecurityException("HBS state transaction changed keyId");
                }
                if (commit.getUpdatedState().getVersion() <= current.getVersion()) {
                    throw new GeneralSecurityException("Refusing to roll back HBS state");
                }
                writeRecordAtomically(statePath(normalizedKeyId), commit.getUpdatedState());
                return commit;
            }
        }
    }

    private Path lockPath(String keyId) {
        return directory.resolve(safeKeyId(keyId) + ".lock");
    }

    private Path statePath(String keyId) {
        return directory.resolve(safeKeyId(keyId) + ".state");
    }

    private static Object jvmLock(Path lockPath) {
        return JVM_LOCKS.computeIfAbsent(lockPath.toAbsolutePath().normalize(), ignored -> new Object());
    }

    private static String safeKeyId(String keyId) {
        if (keyId == null || !keyId.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("Invalid HBS keyId");
        }
        return keyId.toLowerCase(java.util.Locale.ROOT);
    }

    private static boolean sameKeyId(String expectedKeyId, String actualKeyId) throws GeneralSecurityException {
        try {
            return expectedKeyId.equals(safeKeyId(actualKeyId));
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid HBS state keyId", e);
        }
    }

    private HbsStateRecord readRecord(Path path) throws IOException, GeneralSecurityException {
        if (!Files.exists(path)) {
            throw new FileNotFoundException("HBS state file not found: " + path);
        }
        long fileLen = Files.size(path);
        if (fileLen < CHECKSUM_LEN || fileLen > MAX_STATE_FILE_LEN) {
            throw new GeneralSecurityException("Invalid HBS state file length: " + fileLen);
        }
        byte[] file = Files.readAllBytes(path);
        byte[] body = Arrays.copyOf(file, file.length - CHECKSUM_LEN);
        byte[] checksum = Arrays.copyOfRange(file, file.length - CHECKSUM_LEN, file.length);
        if (!MessageDigest.isEqual(authTag(body), checksum)) {
            throw new GeneralSecurityException("HBS state authentication tag mismatch");
        }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(body));
        String magic = in.readUTF();
        int version = in.readInt();
        if (!MAGIC.equals(magic) || version != FORMAT_VERSION) {
            throw new GeneralSecurityException("Unsupported HBS state format");
        }
        String algorithm = in.readUTF();
        String parameterSet = in.readUTF();
        String keyId = in.readUTF();
        long remaining = in.readLong();
        long stateVersion = in.readLong();
        byte[] publicKey = readBytes(in);
        byte[] privateState = readBytes(in);
        if (in.available() != 0) {
            throw new GeneralSecurityException("HBS state file contains trailing data");
        }
        return new HbsStateRecord(keyId, algorithm, parameterSet, publicKey, privateState, remaining, stateVersion);
    }

    private void writeRecordAtomically(Path path, HbsStateRecord record)
            throws IOException, GeneralSecurityException {
        byte[] file = encodeRecord(record);
        Path tmp = Files.createTempFile(path.getParent(), "." + path.getFileName().toString(), ".tmp");
        boolean moved = false;
        try {
            try (FileChannel channel = FileChannel.open(tmp,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(file);
                while (buffer.hasRemaining()) {
                    int written = channel.write(buffer);
                    if (written <= 0) {
                        throw new IOException("Short write while persisting HBS state");
                    }
                }
                channel.force(true);
            }
            try {
                Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                throw new IOException("Atomic move required for HBS state persistence", e);
            }
            moved = true;
            fsyncDirectory(path.getParent());
        } finally {
            if (!moved) {
                Files.deleteIfExists(tmp);
            }
        }
    }

    private byte[] encodeRecord(HbsStateRecord record) throws IOException, GeneralSecurityException {
        ByteArrayOutputStream bodyBytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bodyBytes);
        out.writeUTF(MAGIC);
        out.writeInt(FORMAT_VERSION);
        out.writeUTF(record.getAlgorithm());
        out.writeUTF(record.getParameterSet());
        out.writeUTF(record.getKeyId());
        out.writeLong(record.getRemainingSignatures());
        out.writeLong(record.getVersion());
        writeBytes(out, record.getPublicKey());
        writeBytes(out, record.getPrivateState());
        out.flush();

        byte[] body = bodyBytes.toByteArray();
        byte[] checksum = authTag(body);
        ByteArrayOutputStream fileBytes = new ByteArrayOutputStream(body.length + checksum.length);
        fileBytes.write(body);
        fileBytes.write(checksum);
        return fileBytes.toByteArray();
    }

    private void ensureMonotonicVersion(Path path, HbsStateRecord candidate)
            throws IOException, GeneralSecurityException {
        if (!Files.exists(path)) {
            return;
        }
        HbsStateRecord current = readRecord(path);
        if (!sameKeyId(safeKeyId(candidate.getKeyId()), current.getKeyId())) {
            throw new GeneralSecurityException("HBS state keyId mismatch");
        }
        if (candidate.getVersion() <= current.getVersion()) {
            throw new GeneralSecurityException("Refusing to roll back HBS state");
        }
    }

    private static byte[] readBytes(DataInputStream in) throws IOException, GeneralSecurityException {
        int len = in.readInt();
        if (len < 0 || len > MAX_STATE_FIELD_LEN) {
            throw new GeneralSecurityException("Invalid HBS state field length: " + len);
        }
        byte[] data = new byte[len];
        in.readFully(data);
        return data;
    }

    private static void writeBytes(DataOutputStream out, byte[] data) throws IOException {
        out.writeInt(data.length);
        out.write(data);
    }

    private static byte[] sha256(byte[] data) throws GeneralSecurityException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralSecurityException("SHA-256 is not available", e);
        }
    }

    private byte[] authTag(byte[] data) throws GeneralSecurityException {
        if (integrityKey == null) {
            return sha256(data);
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(integrityKey, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("HmacSHA256 is not available", e);
        }
    }

    private static void fsyncDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException ignored) {
            // Directory fsync is best-effort because it is not supported on every filesystem.
        }
    }
}
