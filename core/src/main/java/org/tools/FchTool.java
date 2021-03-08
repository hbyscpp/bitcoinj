package org.tools;

import org.bitcoinj.core.*;
import org.bitcoinj.crypto.LazyECPoint;
import org.bitcoinj.crypto.SchnorrSignature;
import org.bitcoinj.fch.FchMainNetwork;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.signers.LocalSchnorrTransactionSigner;
import org.bitcoinj.signers.LocalTransactionSigner;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.digest.SHA512;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.*;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.tools.ecies.AESGCMBlockCipher;
import org.tools.ecies.EccHelper;
import org.tools.ecies.IESCipherGCM;
import org.tools.ecies.IESEngineGCM;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;

import javax.crypto.Cipher;
/**
 * 工具类
 */
public class FchTool {

    static{
        fixKeyLength();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    }
    public static void fixKeyLength() {
        String errorString = "Failed manually overriding key-length permissions.";
        int newMaxKeyLength;
        try {
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
                Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
                Constructor con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissionCollection = con.newInstance();
                Field f = c.getDeclaredField("all_allowed");
                f.setAccessible(true);
                f.setBoolean(allPermissionCollection, true);

                c = Class.forName("javax.crypto.CryptoPermissions");
                con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissions = con.newInstance();
                f = c.getDeclaredField("perms");
                f.setAccessible(true);
                ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

                c = Class.forName("javax.crypto.JceSecurityManager");
                f = c.getDeclaredField("defaultPolicy");
                f.setAccessible(true);
                Field mf = Field.class.getDeclaredField("modifiers");
                mf.setAccessible(true);
                mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
                f.set(null, allPermissions);

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            }
        } catch (Exception e) {
            throw new RuntimeException(errorString, e);
        }
        if (newMaxKeyLength < 256)
            throw new RuntimeException(errorString); // hack failed
    }

    /**
     * 创建签名
     *
     * @param inputs
     * @param outputs
     * @param opReturn
     * @param returnAddr
     * @param fee
     * @return
     */
    public static String createTransactionSign(List<TxInput> inputs, List<TxOutput> outputs, String opReturn, String returnAddr, long fee) {

        Transaction transaction = new Transaction(FchMainNetwork.MAINNETWORK);

        long totalMoney = 0;
        long totalOutput = 0;
        List<UTXO> utxos = new ArrayList<>();
        List<ECKey> ecKeys = new ArrayList<>();
        for (TxOutput output : outputs) {
            totalOutput += output.getAmount();
            transaction.addOutput(Coin.valueOf(output.getAmount()), Address.fromBase58(FchMainNetwork.MAINNETWORK, output.getAddress()));
        }
        for (int i = 0; i < inputs.size(); ++i) {
            TxInput input = inputs.get(i);
            totalMoney += input.getAmount();
            NetworkParameters params = FchMainNetwork.MAINNETWORK;
            byte[] bytesWif = Base58.decodeChecked(input.getPrivateKey());
            byte[] privateKeyBytes = new byte[32];
            System.arraycopy(bytesWif, 1, privateKeyBytes, 0, 32);
            ECKey eckey = ECKey.fromPrivate(privateKeyBytes);
            ecKeys.add(eckey);
            UTXO utxo = new UTXO(Sha256Hash.wrap(input.getTxId()), input.getIndex(), Coin.valueOf(input.getAmount()), 0, false, ScriptBuilder.createP2PKHOutputScript(eckey));
            TransactionOutPoint outPoint = new TransactionOutPoint(FchMainNetwork.MAINNETWORK, utxo.getIndex(), utxo.getHash());
            transaction.addSignedInput(outPoint, utxo.getScript(), eckey, Transaction.SigHash.ALL, true);

        }
        if ((totalOutput + fee) > totalMoney) {
            throw new RuntimeException("input is not enought");
        }


        if (opReturn != null && !"".equals(opReturn)) {
            try {
                Script opreturnScript = ScriptBuilder.createOpReturnScript(opReturn.getBytes("UTF-8"));
                transaction.addOutput(Coin.ZERO, opreturnScript);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        if (returnAddr != null) {
            transaction.addOutput(Coin.valueOf(totalMoney - totalOutput - fee), Address.fromBase58(FchMainNetwork.MAINNETWORK, returnAddr));
        }


        for (int i = 0; i < inputs.size(); ++i) {
            TxInput input = inputs.get(i);
            ECKey eckey = ecKeys.get(i);
            Script script = ScriptBuilder.createP2PKHOutputScript(eckey);
            SchnorrSignature signature = transaction.calculateSchnorrSignature(i, eckey, script.getProgram(), Coin.valueOf(input.getAmount()), Transaction.SigHash.ALL, false);
            Script schnorr = ScriptBuilder.createSchnorrInputScript(signature, eckey);
            //TransactionInput txInput=new TransactionInput(FchMainNetwork.MAINNETWORK,transaction,schnorr.getProgram());
            transaction.getInput(i).setScriptSig(schnorr);
            //transaction.addInput(new Sha256Hash(Utils.HEX.decode(input.getTxId()),input.getIndex(),new Script()));
        }


        byte[] signResult = transaction.bitcoinSerialize();
        String signStr = Utils.HEX.encode(signResult);
        return signStr;
    }

    /**
     * 随机私钥
     *
     * @param secret
     * @return
     */
    public static IdInfo createRandomIdInfo(String secret) {

        return IdInfo.genRandomIdInfo();
    }

    /**
     * 公钥转地址
     * @param pukey
     * @return
     */
    public static String pubkeyToAddr(String pukey){

        ECKey eckey=ECKey.fromPublicOnly(Utils.HEX.decode(pukey));
        return eckey.toAddress(FchMainNetwork.MAINNETWORK).toString();

    }

    /**
     * 通过wif创建私钥
     *
     * @param wifKey
     * @return
     */
    public static IdInfo createIdInfoFromWIFPrivateKey(String wifKey) {

        return new IdInfo(wifKey);
    }

    /**
     * 消息签名
     *
     * @param msg
     * @param wifkey
     * @return
     */
    public static String signFullMsg(String msg, String wifkey) {

        IdInfo idInfo = new IdInfo(wifkey);
        return idInfo.signFullMessage(msg);
    }

    /**
     * 签名验证
     *
     * @param msg
     * @return
     */
    public static boolean verifyFullMsg(String msg) {
        String args[] = msg.split("----");
        try {
            ECKey key = ECKey.signedMessageToKey(args[0], args[2]);
            Address targetAddr = key.toAddress(FchMainNetwork.MAINNETWORK);
            return args[1].equals(targetAddr.toString());
        } catch (Exception e) {
            return false;
        }
    }

    public static String msgHash(String msg) {
        try {
            byte[] data = msg.getBytes("UTF-8");
            return Utils.HEX.encode(Sha256Hash.hash(data));
        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }

    public static String msgFileHash(String path) {
        try {
            File f = new File(path);
            return Utils.HEX.encode(Sha256Hash.of(f).getBytes());
        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }

    public static String encryptData(String plaintext,String pubkey) throws Exception {
        byte[] compressPubkey=Utils.HEX.decode(pubkey);
        return encrypt(plaintext,compressPubkey,"secp256k1");
    }

    public static String decryptData(String plaintext,String privatekey) throws Exception {
        NetworkParameters params = FchMainNetwork.MAINNETWORK;
        byte[] bytesWif = Base58.decodeChecked(privatekey);
        byte[] privateKeyBytes = new byte[32];
        System.arraycopy(bytesWif, 1, privateKeyBytes, 0, 32);
        ECKey eckey = ECKey.fromPrivate(privateKeyBytes);
        return decrypt(plaintext,eckey.getPrivKey());
    }
    private static String encrypt(String plaintext, byte[] publicKeyBytes, String curveName) throws Exception {

        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN());
        java.security.spec.ECPoint point = org.bouncycastle.jce.ECPointUtil.decodePoint(curvedParams.getCurve(), publicKeyBytes);
        java.security.spec.ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, curvedParams);
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);

        byte[] inputBytes = plaintext.getBytes();
        ECKey ecKey=new ECKey();
        byte[] iv= calcIv(ecKey,decodePoint(curvedParams.getCurve(),publicKeyBytes));
        byte[] ivs=new byte[16];
        System.arraycopy(iv,0,ivs,0,16);
        org.bouncycastle.jce.spec.IESParameterSpec params = new IESParameterSpec(null, null, 128, 128,  Hex.decode("000102030405060708090a0b0c0d0e0f"));
        Cipher cipher = Cipher.getInstance("ECIESwithAES-CBC");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey,params,new SecureRandom());
        byte[] cipherResult = cipher.doFinal(inputBytes,0,inputBytes.length);
        return Base64.toBase64String(cipherResult);
    }

    private static byte[] calcIv(ECKey current, org.bouncycastle.math.ec.ECPoint point){

        org.bouncycastle.math.ec.ECPoint newpoint=point.multiply(current.getPrivKey());
        byte[] buffer=newpoint.getRawXCoord().getEncoded();
        Digest digest=new SHA512Digest();
        digest.update(buffer,0,buffer.length);
        byte[] r=new byte[digest.getDigestSize()];
        digest.doFinal(r,0);
        return r;
    }

    private static byte[] calcEnIv(byte[] cipher,BigInteger privateKey) throws NoSuchAlgorithmException {

         ECKey eckey;
         byte[] pukey=null;
         switch (cipher[0]){
             case 4:
                 pukey=new byte[65];
                 System.arraycopy(cipher,0,pukey,0,65);
                 eckey=ECKey.fromPublicOnly(pukey);
                 break;
             case 3:
             case 2:
                 pukey=new byte[33];
                 System.arraycopy(cipher,0,pukey,0,33);
                 eckey=ECKey.fromPublicOnly(pukey);
                 break;
             default:
                 throw new RuntimeException("invalid");

         }
        byte[] publicKeyBytes=eckey.getPubKey();
        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(), spec.getN());
        org.bouncycastle.math.ec.ECPoint point = decodePoint(curvedParams.getCurve(), publicKeyBytes);
        ECKey current=ECKey.fromPrivate(privateKey);
        return calcIv(current,point);
    }

    public static org.bouncycastle.math.ec.ECPoint decodePoint(
            EllipticCurve curve,
            byte[] encoded)
    {
        ECCurve c = null;

        if (curve.getField() instanceof ECFieldFp)
        {
            c = new ECCurve.Fp(
                    ((ECFieldFp)curve.getField()).getP(), curve.getA(), curve.getB());
        }
        else
        {
            int k[] = ((ECFieldF2m)curve.getField()).getMidTermsOfReductionPolynomial();

            if (k.length == 3)
            {
                c = new ECCurve.F2m(
                        ((ECFieldF2m)curve.getField()).getM(), k[2], k[1], k[0], curve.getA(), curve.getB());
            }
            else
            {
                c = new ECCurve.F2m(
                        ((ECFieldF2m)curve.getField()).getM(), k[0], curve.getA(), curve.getB());
            }
        }

        return c.decodePoint(encoded);
    }


    private static String decrypt(String ciphertext, BigInteger privateKeyBytes) throws Exception {

        ECParameterSpec paramSpec=ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPrivateKeySpec privateSpec=new ECPrivateKeySpec(privateKeyBytes,paramSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.interfaces.ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateSpec);

        byte[] inputBytes = Base64.decode(ciphertext);
        byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
        byte[] encoding   = Hex.decode("303132333435363738393a3b3c3d3e3f");
        byte[] iv= calcEnIv(inputBytes,privateKeyBytes);
        System.out.println(iv[0]);
        IESParameterSpec params = new IESParameterSpec(null, null, 128, 128,  Hex.decode("000102030405060708090a0b0c0d0e0f"));
        Cipher cipher = Cipher.getInstance("ECIESwithAES-CBC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey,params);

        byte[] cipherResult = cipher.doFinal(inputBytes, 0, inputBytes.length);
        return new String(cipherResult);

    }

    public static long calcMinFee(int inputsize, int outputsize, String openreturn, String opreturnAddr, long fee) {

        List<TxInput> txInputs = new ArrayList<>();
        for (int i = 0; i < inputsize; ++i) {

            TxInput input = new TxInput();
            input.setPrivateKey("KxhPaZzFT1S48C4mmZsBiAvxyAEE1E5zcnFKD93Zc69ENpchjxra");
            input.setIndex(0);
            input.setTxId("4a6bef758ae46c4610e5970e75d87effb8630eb3c8d2401008b78fc73f86d41e");
            input.setAmount(20000000);
            txInputs.add(input);
        }
        List<TxOutput> txOutputs = new ArrayList<>();
        for (int i = 0; i < outputsize; ++i) {

            TxOutput output = new TxOutput();
            output.setAddress("FBmgfrbzRiJNTPnjgknRxqVU2CmKQFnKM4");
            output.setAmount(1);
            txOutputs.add(output);
        }
        String sig = createTransactionSign(txInputs, txOutputs, openreturn, opreturnAddr, 1000000);
        byte[] sigBytes = Utils.HEX.decode(sig);
        return sigBytes.length;
    }

}
