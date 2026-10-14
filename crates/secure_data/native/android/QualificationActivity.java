package com.sunlit.securedata.mobile;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.os.Bundle;
import android.content.SharedPreferences;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.UUID;
import org.json.JSONObject;

/** Generated qualification app only. Persistence contains ciphertext/metadata, never DEKs. */
public final class QualificationActivity extends Activity {
    public static final class Runner extends Instrumentation {
        private static Runner active;
        private String phase;
        @Override public void onCreate(Bundle arguments) {
            active=this;phase=arguments.getString("phase");start();
        }
        @Override public void onStart() {
            Intent intent=new Intent(getTargetContext(),QualificationActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);intent.putExtra("phase",phase);
            getTargetContext().startActivity(intent);
        }
    }
    private static boolean failPersistence;
    private boolean commit(SharedPreferences.Editor editor) {
        return !failPersistence && editor.commit();
    }
    // Used only by the generated fault-injected qualification build. The runner
    // instruments a copy in its output directory; the production bridge has no
    // fault hooks. Never persist or log the generated plaintext buffer.
    private static byte[] observedUnwrap;
    private static boolean failClose;
    public static FileLock qualificationLock(FileLock actual) {
        if (!failClose || actual==null) return actual;
        return new FileLock(actual.channel(),actual.position(),actual.size(),actual.isShared()) {
            @Override public boolean isValid() { return actual.isValid(); }
            @Override public void release() throws IOException {
                actual.release();throw new IOException("GENERATED_CLOSE_FAILURE");
            }
        };
    }
    public static byte[] qualificationObserve(byte[] value) { observedUnwrap=value;return value; }
    private SharedPreferences prefs;
    private File persisted() { return new File(getNoBackupFilesDir(),"encrypted-fixture.json"); }
    private String namespace() throws Exception {
        String namespace=prefs.getString("namespace",null);
        if (namespace==null || !namespace.startsWith("qualification-")) throw new Exception("MISSING_FIXTURE");
        UUID.fromString(namespace.substring("qualification-".length()));
        return namespace;
    }
    private int deleteFixtureKeys(String namespace) throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
        int deleted=0;
        for (Enumeration<String> names=store.aliases();names.hasMoreElements();) {
            String name=names.nextElement();
            if (name.startsWith("SunlitSDv1:"+namespace+":")) { store.deleteEntry(name);deleted++; }
        }
        return deleted;
    }
    private void rejection(MobileKeyBridge bridge,String alias,String version,byte[] frame,MobileKeyBridge.Failure kind) throws Exception {
        try (MobileKeyBridge.Unwrapped unexpected=bridge.unwrap(alias,version,frame)) {
            throw new Exception("REJECTION_FAILED");
        } catch (MobileKeyBridge.KeyFailure expected) {
            if (expected.kind!=kind) throw new Exception("WRONG_FIXED_ERROR");
        }
    }
    private JSONObject qualify(String phase) throws Exception {
        JSONObject result=new JSONObject();result.put("phase",phase);
        if (phase.equals("persistence_failure")) {
            failPersistence=true;
            try {
                qualify("seed");
                throw new Exception("PERSISTENCE_FAILURE_NOT_REJECTED");
            } catch (IOException expected) {
                KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
                for (Enumeration<String> names=store.aliases();names.hasMoreElements();) {
                    if (names.nextElement().startsWith("SunlitSDv1:qualification-")) throw new Exception("ORPHAN_FIXTURE_KEY");
                }
                result.put("failedNamespacePersistence","noKeyCreated");
            } finally { failPersistence=false; }
        } else if (phase.equals("seed")) {
            String old=prefs.getString("namespace",null);
            if (old!=null) deleteFixtureKeys(namespace());
            String namespace="qualification-"+UUID.randomUUID();
            if (!commit(prefs.edit().putString("namespace",namespace))) throw new IOException("FIXTURE_PERSISTENCE_FAILED");
            MobileKeyBridge bridge=new MobileKeyBridge(this,namespace,"v1",MobileKeyBridge.Policy.SOFTWARE_ALLOWED);
            byte[] key=new byte[32];new SecureRandom().nextBytes(key);
            try {
                MobileKeyBridge.Wrapped wrapped=bridge.wrap("generated-key",key);
                JSONObject stored=new JSONObject();stored.put("alias",wrapped.alias);stored.put("version",wrapped.version);
                stored.put("frame",Base64.getEncoder().encodeToString(wrapped.frame));
                stored.put("digest",Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(key)));
                try (FileOutputStream file=new FileOutputStream(persisted())) { file.write(stored.toString().getBytes(StandardCharsets.UTF_8)); }
                result.put("reportedLevel",wrapped.level.name());
            } finally { Arrays.fill(key,(byte)0); }
        } else if (phase.equals("cleanup")) {
            if (prefs.getString("namespace",null)!=null) result.put("deleted",deleteFixtureKeys(namespace()));
            Files.deleteIfExists(persisted().toPath());
            if (!commit(prefs.edit().clear())) throw new IOException("FIXTURE_PERSISTENCE_FAILED");
        } else {
            JSONObject stored=new JSONObject(new String(Files.readAllBytes(persisted().toPath()),StandardCharsets.UTF_8));
            String alias=stored.getString("alias"),version=stored.getString("version");
            byte[] frame=Base64.getDecoder().decode(stored.getString("frame"));
            MobileKeyBridge bridge=new MobileKeyBridge(this,namespace(),"v1",MobileKeyBridge.Policy.SOFTWARE_ALLOWED);
            if (phase.equals("recover")) {
                MobileKeyBridge.Unwrapped unwrapped=bridge.unwrap(alias,version,frame);
                byte[] borrowed=unwrapped.borrowedBytes();
                try {
                    byte[] digest=MessageDigest.getInstance("SHA-256").digest(borrowed);
                    if (!MessageDigest.isEqual(digest,Base64.getDecoder().decode(stored.getString("digest")))) throw new Exception("RECOVERY_FAILED");
                    result.put("reportedLevel",unwrapped.level.name());
                } finally { unwrapped.close(); }
                for (byte value:borrowed) if (value!=0) throw new Exception("NATIVE_CLEAR_FAILED");
            } else if (phase.equals("close_failure")) {
                failClose=true;
                try {
                    rejection(bridge,alias,version,frame,MobileKeyBridge.Failure.UNAVAILABLE);
                    if (observedUnwrap==null || observedUnwrap.length!=32) throw new Exception("FAULT_NOT_EXERCISED");
                    for (byte value:observedUnwrap) if (value!=0) throw new Exception("CLOSE_FAILURE_CLEAR_FAILED");
                } finally {
                    failClose=false;
                    if (observedUnwrap!=null) Arrays.fill(observedUnwrap,(byte)0);
                    observedUnwrap=null;
                }
                result.put("resourceCloseFailure","plaintextCleared");
            } else if (phase.equals("tamper")) {
                byte[] changed=frame.clone();changed[changed.length-1]^=1;
                rejection(bridge,alias,version,changed,MobileKeyBridge.Failure.AUTHENTICATION_FAILED);
                rejection(bridge,"wrong-alias",version,frame,MobileKeyBridge.Failure.MISSING);
                rejection(bridge,alias,"wrong-version",frame,MobileKeyBridge.Failure.MISSING);
                try (MobileKeyBridge.Unwrapped observed=bridge.unwrap(alias,version,frame)) {
                    if (observed.level==MobileKeyBridge.Level.SOFTWARE) {
                        rejection(new MobileKeyBridge(this,namespace(),"v1",MobileKeyBridge.Policy.HARDWARE_REQUIRED),alias,version,frame,MobileKeyBridge.Failure.CUSTODY_REJECTED);
                        rejection(new MobileKeyBridge(this,namespace(),"v1",MobileKeyBridge.Policy.STRONGBOX_REQUIRED),alias,version,frame,MobileKeyBridge.Failure.CUSTODY_REJECTED);
                    }
                }
                result.put("tamperAliasVersionAndPolicy","rejected");
            } else if (phase.equals("invalidate")) {
                if (deleteFixtureKeys(namespace())!=1) throw new Exception("FIXTURE_KEY_INVENTORY_MISMATCH");
            } else if (phase.equals("recover_deleted")) {
                rejection(bridge,alias,version,frame,MobileKeyBridge.Failure.MISSING);
                KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
                for (Enumeration<String> names=store.aliases();names.hasMoreElements();) {
                    if (names.nextElement().startsWith("SunlitSDv1:"+namespace()+":")) throw new Exception("KEY_RECREATED");
                }
            } else throw new Exception("UNKNOWN_PHASE");
        }
        result.put("status","pass");return result;
    }
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);prefs=getSharedPreferences("generated-qualification",MODE_PRIVATE);
        JSONObject result;
        try { result=qualify(getIntent().getStringExtra("phase")); }
        catch (MobileKeyBridge.KeyFailure error) { result=new JSONObject();try { result.put("status","fail");result.put("kind",error.kind.name()); } catch (Exception ignored) {} }
        catch (Exception error) { result=new JSONObject();try { result.put("status","fail");result.put("kind","QUALIFICATION_ASSERTION"); } catch (Exception ignored) {} }
        try (FileOutputStream output=openFileOutput("qualification-result.json",MODE_PRIVATE)) {
            output.write(result.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {}
        finish();
        if (Runner.active!=null) Runner.active.finish(Activity.RESULT_OK,new Bundle());
    }
}
