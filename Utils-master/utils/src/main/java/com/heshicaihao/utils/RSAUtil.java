package com.heshicaihao.utils;

/**
 * Created by lenovo on 2017/11/22.
 */


import android.content.Context;
import android.text.TextUtils;
import android.util.Base64;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 * Created by zhangkai on 2017/10/18.
 */

public class RSAUtil {

//    private static final Base64 base64 = new Base64();

    /**
     * 公钥
     */

    private static final String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGgm16Jdv10M0wT55AzYJjn2pQfmYnBNmSLYs23NnjjEmxs/RnqbkbCzyjM+P/qELSsKbsT0/X6BPW3EFoo2yKoe3gu+s3k25/SHsCkdVb6KoE1wJrY1iSwNHYmSriDUC+84Sh8BSMQd/637CGsCxxsKSq+ryeQB+7PzkvuWKQvQIDAQAB";


    /**
     * 通过公钥对字符串进行加密
     *
     * @param data 需要被加密的内容
     * @return 加密后的内容
     */

    public static String encrypt(Context conntext, String data) {
        try {
            loadPublicKey(conntext,publicKey);

            if (TextUtils.isEmpty(data)) {

                throw new Exception(conntext.getString(R.string.rsa_tips_01));

            }

            if (TextUtils.isEmpty(publicKey)) {

                throw new Exception(conntext.getString(R.string.rsa_tips_02));

            }

            byte[] dd = encrypt(conntext,loadPublicKey(conntext,publicKey), data.getBytes());

            return Base64.encodeToString(dd,0);
//            return base64.encodeToString(dd);
        } catch (Exception ex) {
            ex.printStackTrace();
            return "";
        }

    }


    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr 公钥数据字符串
     */

    private static RSAPublicKey loadPublicKey(Context conntext,String publicKeyStr) throws Exception {

        try {

//            BASE64Decoder base64Decoder = new BASE64Decoder();

            byte[] buffer = Base64.decode(publicKeyStr,0);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception(conntext.getString(R.string.rsa_tips_03));
        } catch (InvalidKeySpecException e) {
            throw new Exception(conntext.getString(R.string.rsa_tips_04));
        }
        catch (NullPointerException e) {

            throw new Exception(conntext.getString(R.string.rsa_tips_05));

        }

    }


    /**
     * 加密过程
     *
     * @param publicKey     公钥
     * @param plainTextData 明文数据
     * @return
     */

    private static byte[] encrypt(Context conntext,RSAPublicKey publicKey, byte[] plainTextData) throws Exception {

        if (publicKey == null) {
            throw new Exception(conntext.getString(R.string.rsa_tips_06));
        }
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plainTextData);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception(conntext.getString(R.string.rsa_tips_07));
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            throw new Exception(conntext.getString(R.string.rsa_tips_08));
        } catch (IllegalBlockSizeException e) {
            throw new Exception(conntext.getString(R.string.rsa_tips_09));
        } catch (BadPaddingException e) {
            throw new Exception(conntext.getString(R.string.rsa_tips_10));

        }

        return null;

    }
}