package org.tools;

import com.google.gson.Gson;
import org.bitcoinj.utils.JSONHelper;

import java.nio.charset.Charset;
import java.util.List;

public class FchProtocol {

    public static enum CidOpType{

        Create,Update,Delete
    };

    private static Charset UTF_8=Charset.forName("utf-8");

    private static Gson gson=new Gson();

    public static class Protocol{

    private String type;

    private int sn;

    private int version;

    private String name;

    private String hash;

    private Object data;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }



        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getHash() {
            return hash;
        }

        public void setHash(String hash) {
            this.hash = hash;
        }

        public Object getData() {
            return data;
        }

        public void setData(Object data) {
            this.data = data;
        }

        public int getSn() {
            return sn;
        }

        public void setSn(int sn) {
            this.sn = sn;
        }

        public int getVersion() {
            return version;
        }

        public void setVersion(int version) {
            this.version = version;
        }
    }

    private static class CidData{

        private String name;

        private String operation;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getOperation() {
            return operation;
        }

        public void setOperation(String operation) {
            this.operation = operation;
        }
    }
    /**
     *
     * @return
     */
    public static String createCidProtocol(String cid,CidOpType type){

        Protocol protocol=new Protocol();
        protocol.setHash("");
        protocol.setName("CID");
        protocol.setType("FEIP");
        protocol.setSn(3);
        protocol.setVersion(4);
        CidData cidData=new CidData();

        if(type==CidOpType.Create || type==CidOpType.Update){

            if(cid==null || cid.getBytes(UTF_8).length>32){
                throw  new IllegalArgumentException("cid is null or too long");
            }
            cidData.setName(cid);
            cidData.setOperation("register");
        }
        if(type==CidOpType.Delete){

            if(cid==null || cid.getBytes(UTF_8).length>32) {
                throw new IllegalArgumentException("cid is null or too long");
            }
            cidData.setOperation("unregister");
        }
        return gson.toJson(cidData);
    }
}
