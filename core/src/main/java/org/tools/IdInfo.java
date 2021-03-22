package org.tools;

import org.bitcoinj.core.*;
import org.bitcoinj.fch.FchMainNetwork;
import org.bitcoinj.params.MainNetParams;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;

import java.security.SignatureException;


public class IdInfo {

    private String privatekey;

    private String pubkey;

    private String address;

    private ECKey ecKey;

    public IdInfo(String privatekey) {
        NetworkParameters params = FchMainNetwork.MAINNETWORK;
        byte[] bytesWif = Base58.decodeChecked(privatekey);
        byte[] privateKeyBytes = new byte[32];
        System.arraycopy(bytesWif, 1, privateKeyBytes, 0, 32);
        ECKey eckey = ECKey.fromPrivate(privateKeyBytes);
        init(eckey, CoinType.FCH);
    }

    public IdInfo(ECKey ecKey) {
        init(ecKey, CoinType.FCH);
    }


    private void init(ECKey ecKey, CoinType cointype) {
        this.ecKey = ecKey;
        this.privatekey = ecKey.getPrivateKeyAsWiF(FchMainNetwork.MAINNETWORK);
        this.address = ecKey.toAddress(FchMainNetwork.MAINNETWORK).toString();
        this.pubkey = Utils.HEX.encode(ecKey.getPubKey());

    }

    public String getPrivatekey() {
        return privatekey;
    }

    public String getPubkey() {
        return pubkey;
    }

    public String signMsg(String msg) {
        return ecKey.signMessage(msg);
    }

    public String signFullMessage(String msg) {
        return msg + "----" + address + "----" + signMsg(msg);
    }


    public ECKey getECKey(){
        return ecKey;
    }


    public String getAddress() {
        return address;
    }

    public static IdInfo genRandomIdInfo() {
        ECKey ecKey = new ECKey();
        return new IdInfo(ecKey);
    }
}
