package com.dennis_brink.android.mypincode;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {

    public String decrypt(String text) {
        try {

            // Base64 decode
            byte[] decoded = Base64.getUrlDecoder().decode(text);

            // Extract IV
            byte[] iv = new byte[Config.IV_LENGTH];
            System.arraycopy(decoded, 0, iv, 0, Config.IV_LENGTH);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Extract encrypted message
            byte[] encrypted = new byte[decoded.length - Config.IV_LENGTH];
            System.arraycopy(decoded, Config.IV_LENGTH, encrypted, 0, encrypted.length);

            // Create key and cipher
            Key aesKey = new SecretKeySpec(getSecurityKey().getBytes(), Config.ALGORITHM);
            Cipher cipher = Cipher.getInstance(Config.TRANSFORMATION);

            // Decrypt the text
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            return new String(cipher.doFinal(encrypted));

        }catch (Exception e){
            Log.d(Config.TAG, "Encryption.decrypt() - Exception: " + e.getMessage());
            return ""; // in case of an exception return an empty string
        }
    }

    public String encrypt(String text){
        try {

            // Create key and cipher
            Key aesKey = new SecretKeySpec(getSecurityKey().getBytes(), Config.ALGORITHM);
            Cipher cipher = Cipher.getInstance(Config.TRANSFORMATION);

            // Generate random IV
            byte[] iv = new byte[Config.IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // encrypt the text
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] encrypted = cipher.doFinal(text.getBytes());

            // Prepend IV to the encrypted message
            byte[] encryptedWithIv = new byte[Config.IV_LENGTH + encrypted.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, Config.IV_LENGTH);
            System.arraycopy(encrypted, 0, encryptedWithIv, Config.IV_LENGTH, encrypted.length);

            // Base64 encode
            return Base64.getUrlEncoder().encodeToString(encryptedWithIv);
        }
        catch(Exception e){
            Log.d(Config.TAG, "Encryption.encrypt() - Exception: " + e.getLocalizedMessage());
            return ""; // in case of an exception return an empty string
        }
    }

    private String getSecurityKey() {
        try {
            SecurePreferences securePreferences = new SecurePreferences(ThisApplication.getAppContext());
            if (securePreferences.loadKey(Config.PREF_KEY) == null) {
                securePreferences.generateAndSaveKey(Config.PREF_KEY); // no key, then create one
            }
            String returnKey = securePreferences.loadKey(Config.PREF_KEY);
            Log.d(Config.TAG, "Encryption.getSecurityKey() - key: " + returnKey);
            return returnKey;
        } catch (Exception e){
            Log.d(Config.TAG, "Encryption.getSecurityKey() - Exception: " + e.getMessage());
            return "";
        }
    }

    private static class SecurePreferences  {
        private final SharedPreferences sharedPreferences;
        private static final int KEY_LENGTH = 16;
        private static final SecureRandom RANDOM = new SecureRandom();

        public SecurePreferences(Context context) {
            sharedPreferences = context.getSharedPreferences(Config.PREF_NAME, Context.MODE_PRIVATE);
        }

        // Generate and save a new 128 bits AES key
        public void generateAndSaveKey(String keyAlias) {
            try {
                StringBuilder key = new StringBuilder(KEY_LENGTH);
                for (int i = 0; i < KEY_LENGTH; i++) {
                    // Generate a random ASCII character between 33 (!) and 126 (~) to cover most special characters.
                    char randomChar = (char) (RANDOM.nextInt(94) + 33);
                    key.append(randomChar);
                }
                saveKey(keyAlias, key.toString()); // Save the key
            } catch (Exception e) {
                Log.d(Config.TAG, "Encryption.SecurePreferences.generateAndSaveKey() - Exception: " + e.getMessage());
            }
        }

        // Save a key
        private void saveKey(String keyAlias, String keyValue) {
            SharedPreferences.Editor editor = sharedPreferences.edit();
            String obfuscatedValue = new StringBuilder(keyValue).reverse().toString(); // Simple obfuscation example, rot13 each character
            editor.putString(keyAlias, obfuscatedValue);
            editor.apply(); // save value to shared preference
        }

        // Retrieve a key
        public String loadKey(String keyAlias) {
            String obfuscatedValue = sharedPreferences.getString(keyAlias, null);
            return obfuscatedValue != null ? new StringBuilder(obfuscatedValue).reverse().toString() : null;
        }

    }

    // Static nested class to hold constants
    private static class Config {
        public static final int IV_LENGTH = 16; // Block size for AES is 16 bytes
        public static final String PREF_KEY = "encryptionKey";
        public static final String PREF_NAME = "prefs";
        public static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
        public static final String ALGORITHM = "AES";
        public static final String TAG = "DENNIS_B";

    }

}