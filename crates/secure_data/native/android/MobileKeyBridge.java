package com.sunlit.securedata.mobile;

import android.content.Context;
import android.app.KeyguardManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.UserNotAuthenticatedException;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import java.util.Base64;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Arrays;

/** Android platform bridge for the sealed Rust adapter. No KEK export API. */
public final class MobileKeyBridge {
    public enum Failure {
        INVALID_INPUT, INVALID_RESPONSE, CUSTODY_REJECTED, MISSING, LOCKED,
        INVALIDATED, UNAVAILABLE, INCOMPLETE, AUTHENTICATION_FAILED
    }
    public enum Level { SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX }
    public enum Policy { SOFTWARE_ALLOWED, HARDWARE_REQUIRED, STRONGBOX_REQUIRED }
    public static final class KeyFailure extends Exception {
        public final Failure kind;
        public KeyFailure(Failure kind) { super(kind.name()); this.kind = kind; }
    }
    public static final class Wrapped {
        public final String alias, version;
        public final byte[] frame;
        public final Level level;
        Wrapped(String alias, String version, byte[] frame, Level level) {
            this.alias=alias; this.version=version; this.frame=frame; this.level=level;
        }
    }
    /** Clear native transient bytes after their synchronous handoff to Rust Zeroizing. */
    public static final class Unwrapped implements AutoCloseable {
        public final String alias, version;
        public final Level level;
        private byte[] data;
        Unwrapped(String alias, String version, byte[] data, Level level) {
            this.alias=alias; this.version=version; this.data=data; this.level=level;
        }
        public byte[] borrowedBytes() throws KeyFailure {
            if (data == null) throw new KeyFailure(Failure.INVALID_RESPONSE);
            return data;
        }
        @Override public void close() {
            if (data != null) { Arrays.fill(data, (byte)0); data=null; }
        }
    }
    private final Context context;
    private final String namespace, currentVersion;
    private final Policy policy;

    public MobileKeyBridge(Context context, String namespace, String currentVersion, Policy policy) throws KeyFailure {
        if (context == null || policy == null || !identifier(namespace,64) || !identifier(currentVersion,64)) throw new KeyFailure(Failure.INVALID_INPUT);
        this.context=context.getApplicationContext(); this.namespace=namespace;this.currentVersion=currentVersion;this.policy=policy;
    }
    private static boolean identifier(String value,int limit) {
        if (value==null || value.isEmpty() || value.length()>limit) return false;
        for (int i=0;i<value.length();i++) if (value.charAt(i)<0x21 || value.charAt(i)>0x7e) return false;
        return true;
    }
    private static byte[] aad(String alias,String version) {
        byte[] a=alias.getBytes(StandardCharsets.US_ASCII),v=version.getBytes(StandardCharsets.US_ASCII);
        return ByteBuffer.allocate(8+a.length+v.length).putInt(a.length).put(a).putInt(v.length).put(v).array();
    }
    private String keyName(String alias,String version) {
        return "SunlitSDv1:"+namespace+":"+Base64.getUrlEncoder().withoutPadding().encodeToString(aad(alias,version));
    }
    private void requireUnlocked() throws KeyFailure {
        KeyguardManager guard=(KeyguardManager)context.getSystemService(Context.KEYGUARD_SERVICE);
        if (guard==null) throw new KeyFailure(Failure.UNAVAILABLE);
        if (guard.isDeviceLocked()) throw new KeyFailure(Failure.LOCKED);
    }
    private Level level(SecretKey key) throws Exception {
        byte[] unexpected=key.getEncoded();
        if (unexpected!=null) {
            Arrays.fill(unexpected,(byte)0);throw new KeyFailure(Failure.INVALID_RESPONSE);
        }
        KeyInfo info=(KeyInfo)SecretKeyFactory.getInstance(key.getAlgorithm(),"AndroidKeyStore").getKeySpec(key,KeyInfo.class);
        Level observed;
        switch (info.getSecurityLevel()) {
            case KeyProperties.SECURITY_LEVEL_SOFTWARE: observed=Level.SOFTWARE;break;
            case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: observed=Level.TRUSTED_ENVIRONMENT;break;
            case KeyProperties.SECURITY_LEVEL_STRONGBOX: observed=Level.STRONGBOX;break;
            default: throw new KeyFailure(Failure.CUSTODY_REJECTED);
        }
        if (policy==Policy.HARDWARE_REQUIRED && observed==Level.SOFTWARE || policy==Policy.STRONGBOX_REQUIRED && observed!=Level.STRONGBOX) throw new KeyFailure(Failure.CUSTODY_REJECTED);
        return observed;
    }
    private SecretKey key(String alias,String version,boolean create) throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
        String name=keyName(alias,version);
        SecretKey key=(SecretKey)store.getKey(name,null);
        if (key==null && create) {
            KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
            KeyGenParameterSpec.Builder specification=new KeyGenParameterSpec.Builder(name,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).setUnlockedDeviceRequired(true);
            if (policy==Policy.STRONGBOX_REQUIRED) specification.setIsStrongBoxBacked(true);
            generator.init(specification.build());key=generator.generateKey();
        }
        if (key==null) throw new KeyFailure(Failure.MISSING);
        return key;
    }
    private File operationLock() { return new File(context.getNoBackupFilesDir(),"sunlit-native-operation.lock"); }
    private static KeyFailure mapped(Exception error) {
        if (error instanceof KeyFailure) return (KeyFailure)error;
        if (error instanceof AEADBadTagException) return new KeyFailure(Failure.AUTHENTICATION_FAILED);
        if (error instanceof UserNotAuthenticatedException) return new KeyFailure(Failure.LOCKED);
        if (error instanceof KeyPermanentlyInvalidatedException || error instanceof UnrecoverableKeyException) return new KeyFailure(Failure.INVALIDATED);
        return new KeyFailure(Failure.UNAVAILABLE);
    }
    private static void deadline(long started) throws KeyFailure {
        if (System.nanoTime()-started>2_000_000_000L) throw new KeyFailure(Failure.UNAVAILABLE);
    }
    public Wrapped wrap(String alias, byte[] dataKey) throws KeyFailure {
        if (!identifier(alias,128) || dataKey==null || dataKey.length!=32) throw new KeyFailure(Failure.INVALID_INPUT);
        long started=System.nanoTime();
        try {
            byte[] frame;Level observed;
            try (RandomAccessFile file=new RandomAccessFile(operationLock(),"rw");FileChannel channel=file.getChannel();FileLock lock=channel.tryLock()) {
                if (lock==null) throw new KeyFailure(Failure.UNAVAILABLE);
                requireUnlocked();SecretKey key=key(alias,currentVersion,true);
                observed=level(key);
                Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key);
                cipher.updateAAD(aad(alias,currentVersion));
                byte[] ciphertext=cipher.doFinal(dataKey),iv=cipher.getIV();
                if (iv.length!=12 || ciphertext.length!=48) throw new KeyFailure(Failure.INVALID_RESPONSE);
                frame=ByteBuffer.allocate(61).put((byte)1).put(iv).put(ciphertext).array();
            }
            deadline(started);return new Wrapped(alias,currentVersion,frame,observed);
        } catch (Exception error) { throw mapped(error); }
    }
    public Unwrapped unwrap(String alias, String version, byte[] frame) throws KeyFailure {
        if (!identifier(alias,128) || !identifier(version,64) || frame==null || frame.length!=61 || frame[0]!=1) throw new KeyFailure(Failure.INVALID_INPUT);
        long started=System.nanoTime();byte[] data=null;
        try {
            Level observed;
            try (RandomAccessFile file=new RandomAccessFile(operationLock(),"rw");FileChannel channel=file.getChannel();FileLock lock=channel.tryLock()) {
                if (lock==null) throw new KeyFailure(Failure.UNAVAILABLE);
                requireUnlocked();SecretKey key=key(alias,version,false);observed=level(key);
                Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,frame,1,12));
                cipher.updateAAD(aad(alias,version));data=cipher.doFinal(frame,13,48);
                if (data.length!=32) throw new KeyFailure(Failure.INVALID_RESPONSE);
            }
            // Resource-close failures still reach finally with plaintext owned.
            deadline(started);Unwrapped response=new Unwrapped(alias,version,data,observed);data=null;return response;
        } catch (Exception error) { throw mapped(error); }
        finally { if (data!=null) Arrays.fill(data,(byte)0); }
    }
}
