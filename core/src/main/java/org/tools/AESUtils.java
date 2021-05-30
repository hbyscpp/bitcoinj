package org.tools;

import java.io.UnsupportedEncodingException;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.util.encoders.Base64;

public class AESUtils {

    private static boolean isInit = false;
    private static Object lock = new Object();
    private static final String ALGORITHM = "AES";

    private static void init() {
        if (isInit)
            return;
        synchronized (lock) {
            if (isInit)
                return;
            Security.addProvider(new BouncyCastleProvider());
            isInit = true;
        }
    }

    public static String encrypt(String content, String password) {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(password.getBytes());
            kgen.init(128, random);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            byte[] byteContent = content.getBytes("utf-8");
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(byteContent);
            return Base64.toBase64String(result); // 加密
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e){
            throw  new RuntimeException(e);
        }
        return null;
    }
    public static String decrypt(String content, String password) {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(password.getBytes("utf-8"));
            kgen.init(128,random);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(Base64.decode(content));
            return new String(result,"utf-8"); // 加密
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String content = "test";
        String password = "12345678";
        //加密
        System.out.println("加密前：" + content);
        String encryptResult = encrypt(content, password);
        //解密
        String decryptResult = decrypt(encryptResult,password);
        System.out.println("解密后：" + new String(decryptResult));
    }
}