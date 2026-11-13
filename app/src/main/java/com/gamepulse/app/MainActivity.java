package com.gamepulse.app;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.view.HapticFeedbackConstants;
import android.view.Window;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MainActivity extends Activity {
    private static final String KEY_ALIAS = "gamepulse_secure_key";
    private WebView web;
    private boolean pageReady = false;
    private String pendingOAuth = null;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService pool = Executors.newFixedThreadPool(6);
    private SharedPreferences securePrefs;

    @SuppressLint({"SetJavaScriptEnabled", "AddJavascriptInterface"})
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Window w = getWindow();
        w.setStatusBarColor(Color.parseColor("#070b14"));
        w.setNavigationBarColor(Color.parseColor("#070b14"));
        securePrefs = getSharedPreferences("gp_secure", MODE_PRIVATE);

        web = new WebView(this);
        web.setBackgroundColor(Color.parseColor("#070b14"));
        web.setOverScrollMode(WebView.OVER_SCROLL_NEVER);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(true);
        s.setTextZoom(100);
        web.addJavascriptInterface(new Bridge(), "Native");
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
                Uri u = req.getUrl();
                if ("file".equals(u.getScheme())) return false;
                openExternal(u.toString());
                return true;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                pageReady = true;
                if (pendingOAuth != null) {
                    deliverOAuth(pendingOAuth);
                    pendingOAuth = null;
                }
            }
        });
        setContentView(web);
        web.loadUrl("file:///android_asset/index.html");
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    /** Roblox sends the user back to gamepulse://oauth?code=...&state=... after they sign in. */
    private void handleIntent(Intent intent) {
        if (intent == null || intent.getData() == null) return;
        Uri d = intent.getData();
        if (!"gamepulse".equals(d.getScheme())) return;
        String url = d.toString();
        if (pageReady) deliverOAuth(url);
        else pendingOAuth = url;
    }

    private void deliverOAuth(String url) {
        web.evaluateJavascript("window.__oauth && window.__oauth(" + JSONObject.quote(url) + ")", null);
    }

    private void openExternal(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception ignored) { }
    }

    /** The app may only talk to Roblox's own HTTPS APIs. */
    private static boolean allowed(String url) {
        try {
            URL u = new URL(url);
            return "https".equals(u.getProtocol()) && u.getHost().endsWith(".roblox.com");
        } catch (Exception e) {
            return false;
        }
    }

    // ---------- encrypted storage (Android Keystore, AES-256-GCM) ----------
    private SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(KEY_ALIAS)) {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            kg.init(new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build());
            kg.generateKey();
        }
        return ((KeyStore.SecretKeyEntry) ks.getEntry(KEY_ALIAS, null)).getSecretKey();
    }

    private String encrypt(String plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key());
        byte[] iv = c.getIV();
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(iv, Base64.NO_WRAP) + ":" + Base64.encodeToString(ct, Base64.NO_WRAP);
    }

    private String decrypt(String stored) throws Exception {
        String[] p = stored.split(":", 2);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, Base64.decode(p[0], Base64.NO_WRAP)));
        return new String(c.doFinal(Base64.decode(p[1], Base64.NO_WRAP)), StandardCharsets.UTF_8);
    }

    private static String b64url(byte[] b) {
        return Base64.encodeToString(b, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    private class Bridge {
        @JavascriptInterface
        public void request(final String id, final String method, final String url, final String body, final String headersJson) {
            pool.execute(() -> {
                int status = 0;
                String text = "";
                if (allowed(url)) {
                    HttpURLConnection c = null;
                    try {
                        c = (HttpURLConnection) new URL(url).openConnection();
                        c.setConnectTimeout(15000);
                        c.setReadTimeout(30000);
                        c.setRequestMethod("POST".equals(method) ? "POST" : "GET");
                        c.setRequestProperty("Accept", "application/json");
                        c.setRequestProperty("User-Agent", "GamePulse/2.0 (Android)");
                        if (headersJson != null && !headersJson.isEmpty()) {
                            JSONObject h = new JSONObject(headersJson);
                            Iterator<String> it = h.keys();
                            while (it.hasNext()) {
                                String k = it.next();
                                c.setRequestProperty(k, h.getString(k));
                            }
                        }
                        if ("POST".equals(method)) {
                            c.setDoOutput(true);
                            if (c.getRequestProperty("Content-Type") == null) c.setRequestProperty("Content-Type", "application/json");
                            try (OutputStream os = c.getOutputStream()) {
                                os.write((body == null ? "" : body).getBytes(StandardCharsets.UTF_8));
                            }
                        }
                        status = c.getResponseCode();
                        InputStream in = status >= 400 ? c.getErrorStream() : c.getInputStream();
                        if (in != null) {
                            ByteArrayOutputStream bo = new ByteArrayOutputStream();
                            byte[] buf = new byte[8192];
                            int n;
                            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
                            in.close();
                            text = bo.toString("UTF-8");
                        }
                    } catch (Exception e) {
                        status = 0;
                        text = "";
                    } finally {
                        if (c != null) c.disconnect();
                    }
                } else {
                    status = 403;
                }
                final String js = "window.__nativeCb(" + JSONObject.quote(id) + "," + status + "," + JSONObject.quote(text) + ")";
                main.post(() -> web.evaluateJavascript(js, null));
            });
        }

        @JavascriptInterface
        public void openUrl(final String url) {
            if (url != null && url.startsWith("https://")) main.post(() -> openExternal(url));
        }

        @JavascriptInterface
        public String secureGet(String k) {
            try {
                String v = securePrefs.getString(k, null);
                return v == null ? null : decrypt(v);
            } catch (Exception e) {
                return null;
            }
        }

        @JavascriptInterface
        public void secureSet(String k, String v) {
            try {
                if (v == null || v.isEmpty()) securePrefs.edit().remove(k).apply();
                else securePrefs.edit().putString(k, encrypt(v)).apply();
            } catch (Exception ignored) { }
        }

        /** PKCE verifier + S256 challenge for Roblox OAuth. */
        @JavascriptInterface
        public String pkce() {
            try {
                byte[] r = new byte[48];
                new SecureRandom().nextBytes(r);
                String verifier = b64url(r);
                byte[] dig = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
                JSONObject o = new JSONObject();
                o.put("verifier", verifier);
                o.put("challenge", b64url(dig));
                return o.toString();
            } catch (Exception e) {
                return "{}";
            }
        }

        @JavascriptInterface
        public String sha256(String s) {
            try {
                byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                for (byte b : d) sb.append(String.format("%02x", b));
                return sb.toString();
            } catch (Exception e) {
                return "";
            }
        }

        @JavascriptInterface
        public void haptic() {
            main.post(() -> web.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP));
        }

        @JavascriptInterface
        public void setBack(boolean handles) { }
    }

    @Override
    public void onBackPressed() {
        web.evaluateJavascript("window.__back ? window.__back() : false", value -> {
            if (!"true".equals(value)) finish();
        });
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (web != null) web.evaluateJavascript("window.__pause && window.__pause()", null);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (web != null && pageReady) web.evaluateJavascript("window.__resume && window.__resume()", null);
    }

    @Override
    protected void onDestroy() {
        pool.shutdownNow();
        super.onDestroy();
    }
}
