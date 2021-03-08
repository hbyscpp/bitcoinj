package org.tools.ecies;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import sun.security.ec.ECKeyFactory;


public class ECIESUtil {

    public static final String ALGORITHM = "ECIES";
    public static final String TRANSFORMATION = "ECIESwithDESede/NONE/PKCS7Padding";
    public static final String PROVIDER = "BC";

    static{
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static void encryData(byte[] msg,byte[] pubkey) throws Exception {

        KeyPairGenerator    g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(256, new SecureRandom());
        byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
        byte[] encoding   = Hex.decode("303132333435363738393a3b3c3d3e3f");
        IESParameterSpec params = new IESParameterSpec(derivation,encoding,128);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(), spec.getN());
        java.security.spec.ECPoint point = org.bouncycastle.jce.ECPointUtil.decodePoint(curvedParams.getCurve(), pubkey);
        java.security.spec.ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, curvedParams);
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);

    }



    public static void main(String[] args) throws Exception {


    }

}