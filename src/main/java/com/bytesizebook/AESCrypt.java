package com.bytesizebook;

import com.google.gson.JsonObject;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedWriter;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.lang.*;

public class AESCrypt {

    public AESCrypt() {
    }

    // String plaintext -> Base64-encoded String ciphertext
    public String encrypt(String key, String plaintext) {
//        plaintext = String.format("%s_%d", plaintext, new Date().getTime());
        try {
            // Generate a random 16-byte initialization vector
            byte initVector[] = new byte[16];
            (new Random()).nextBytes(initVector);
            IvParameterSpec iv = new IvParameterSpec(initVector);

            // prep the key
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            // prep the AES Cipher
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            // Encode the plaintext as array of Bytes
            byte[] cipherbytes = cipher.doFinal(plaintext.getBytes());

            // Build the output message initVector + cipherbytes -> base64
            byte[] messagebytes = new byte[initVector.length + cipherbytes.length];

            System.arraycopy(initVector, 0, messagebytes, 0, 16);
            System.arraycopy(cipherbytes, 0, messagebytes, 16, cipherbytes.length);

            // Return the cipherbytes as a Base64-encoded string
            return Base64.getEncoder().encodeToString(messagebytes);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    // Base64-encoded String ciphertext -> String plaintext
    public String decrypt(String key, String ciphertext) {
        try {
            byte[] cipherbytes = Base64.getDecoder().decode(ciphertext);

            byte[] initVector = Arrays.copyOfRange(cipherbytes,0,16);

            byte[] messagebytes = Arrays.copyOfRange(cipherbytes,16,cipherbytes.length);

            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            // Convert the ciphertext Base64-encoded String back to bytes, and
            // then decrypt
            byte[] byte_array = cipher.doFinal(messagebytes);

            // Return plaintext as String
            return new String(byte_array, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public int getResponseCode(String key, String urlRaw, HashMap<String, String> headers) throws Exception{
        URL url = new URL(urlRaw);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        setHeaders(con, key, headers);

        return con.getResponseCode();
    }

    public void setHeaders(HttpURLConnection con, String key, HashMap<String, String> headers) {
        for (Map.Entry<String, String> pair : headers.entrySet()) {
            JsonObject header = new JsonObject();
            header.addProperty("value", pair.getValue());
            header.addProperty("timestamp", new Date().getTime());

            String encrypted = encrypt(key, header.toString());
            con.setRequestProperty(pair.getKey(), encrypted);
        }
    }

    public int send(String key, String urlRaw, HashMap<String, String> headers, List<NameValuePair> params) throws Exception{
        URL url = new URL(urlRaw);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        setHeaders(con, key, headers);
        con.setDoInput(true);
        con.setDoOutput(true);


        OutputStream os = con.getOutputStream();
        BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(os, "UTF-8"));
        writer.write(getQuery(params));
        writer.flush();
        writer.close();
        os.close();

        return con.getResponseCode();
    }

    private String getQuery(List<NameValuePair> params) throws UnsupportedEncodingException{
        StringBuilder result = new StringBuilder();
        boolean first = true;

        for (NameValuePair pair : params)
        {
            if (first)
                first = false;
            else
                result.append("&");

            result.append(URLEncoder.encode(pair.getName(), "UTF-8"));
            result.append("=");
            result.append(URLEncoder.encode(pair.getValue(), "UTF-8"));
        }

        return result.toString();
    }


    public static void main(String[] args) throws Exception {
//        String key = "authentication12";
//
//        //test authentication
//        String url = "http://localhost:5001/authenticate";
//        HashMap<String, String> headers = new HashMap<>();
//        headers.put("first_header_name", "asdnalksdnaasdnalksdnaasd");
//        headers.put("second_header_name", "34234ewrtw352345");
//
//        int status = new AESCrypt().getResponseCode(key, url, headers);
//        System.out.println(status);


        //crud
//        String crud_token = "moso_doc_ai_auth";
//        HashMap<String, String> crud_headers = new HashMap<>();
//        crud_headers.put("crud_token", crud_token);
//
//
//        String url = "http://localhost:5001/add";
////        String url = "http://localhost:5001/delete";
//
//
//        List<NameValuePair> params = new ArrayList<NameValuePair>();
//        params.add(new BasicNameValuePair("first_header_name", "asdnalksdnaasdnalksdnaasd"));
//        params.add(new BasicNameValuePair("second_header_name", "34234ewrtw352345"));
//
//        int add_status = send(key, url, crud_headers, params);
//        System.out.println(add_status);

    }
}