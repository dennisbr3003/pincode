package com.dennis_brink.android.mypincode;

import android.os.Build;

import androidx.annotation.RequiresApi;

import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {

    @RequiresApi(api = Build.VERSION_CODES.O)
    public String decrypt(String text) {
        try {

            text = new String(Base64.getUrlDecoder().decode(text.getBytes()));
            String key = "Bar12345Bar12345"; // 128 bit key

            // Create key and cipher
            Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");

            byte[] bb = new byte[text.length()];
            for (int i=0; i<text.length(); i++) {
                bb[i] = (byte) text.charAt(i);
            }

            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            return new String(cipher.doFinal(bb));

        }catch (Exception e){
            e.printStackTrace();
        }
        return "";
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public String encrypt(String text){
        try {
            String key = "Bar12345Bar12345"; // 128 bit key

            // Create key and cipher
            Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");

            // encrypt the text
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encrypted = cipher.doFinal(text.getBytes());

            StringBuilder sb = new StringBuilder();
            for (byte b : encrypted) {
                sb.append((char) b);
            }

            // Base64 url-encode the encrypted String so it's usable in JSONs and URLS
            return Base64.getUrlEncoder().encodeToString(sb.toString().getBytes());
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return "";
    }

}