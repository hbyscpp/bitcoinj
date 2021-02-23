package org.bitcoinj.examples;

import org.tools.FchTool;
import org.tools.TxInput;
import org.tools.TxOutput;

import java.util.ArrayList;
import java.util.List;

public class FchToolExample {
    public static void main(String[] args)  {
        //generateIdInfo();L1WkwqiJgkPoYdjrs7tcikRj5hjwFebiTUChvxwubuSohpAaDzjP
        // IdInfo id = new IdInfo("L1WkwqiJgkPoYdjrs7tcikRj5hjwFebiTUChvxwubuSohpAaDzjP");
        // System.out.println(id.getAddress());
        // String sign = id.signFullMessage("helloworld");
        // System.out.println(sign);
        // System.out.println(id.verifyFullMsg("helloworld----F7i2w8LL5Y1nZXJgneJdwCxdYMPH67kiUp----IDJ9c72QO6TYjXxomzMRN4Woq4/EqExXSzYG838FV6iiOHsIgu6hLD72kp4cTC7ggCm2kMPH9eIs9OHSJFbAwbs="));
        List<TxInput> inputs=new ArrayList<>();
        TxInput input1=new TxInput();
        input1.setAmount(1001*100000000L);
        input1.setTxId("4759c9ba221a1010f6a4fb8c3d4b08a74e6bac3889557adc323125d02be1e0d0");
        input1.setIndex(0);
        input1.setPrivateKey("KxhPaZzFT1S48C4mmZsBiAvxyAEE1E5zcnFKD93Zc69ENpchjxra");

        TxInput input2=new TxInput();
        input2.setAmount(999*100000000L);
        input2.setTxId("39f3fe01f02879f4fde21819a6429c2991d1fbe0e0a5ef2c513f9b14b208a6ce");
        input2.setIndex(1);
        input2.setPrivateKey("KxhPaZzFT1S48C4mmZsBiAvxyAEE1E5zcnFKD93Zc69ENpchjxra");

        TxInput input3=new TxInput();
        input3.setAmount(100*100000000L);
        input3.setTxId("666019aa83f27962da890bb31fc6694c727cb787a2dd524a8d0286e73eb326b2");
        input3.setIndex(0);
        input3.setPrivateKey("KxhPaZzFT1S48C4mmZsBiAvxyAEE1E5zcnFKD93Zc69ENpchjxra");


        TxInput input4=new TxInput();
        input4.setAmount(49*100000000L);
        input4.setTxId("aceaff130862025534863f8358988a436add669688c2d76a0d30b09b9590cc19");
        input4.setIndex(1);
        input4.setPrivateKey("KxhPaZzFT1S48C4mmZsBiAvxyAEE1E5zcnFKD93Zc69ENpchjxra");


        TxInput input5=new TxInput();
        input5.setAmount(1*100000000L);
        input5.setTxId("5a71e26d5cafc125d6c562db61f4e734702b1ebc9a012c09adad7d8bd9927151");
        input5.setIndex(0);
        input5.setPrivateKey("KxhPaZzFT1S48C4mmZsBiAvxyAEE1E5zcnFKD93Zc69ENpchjxra");

        TxInput input6=new TxInput();
        input6.setAmount(25*100000000L);
        input6.setTxId("4a6bef758ae46c4610e5970e75d87effb8630eb3c8d2401008b78fc73f86d41e");
        input6.setIndex(0);
        input6.setPrivateKey("L52LeAjvxeDgPeN2p4ouku7pHLrnbZCX6SH6F5wuqdC1AftywpWR");

        inputs.add(input1);
        inputs.add(input2);
        inputs.add(input3);
        inputs.add(input4);
        inputs.add(input5);
        TxOutput output1=new TxOutput();
        output1.setAmount(123*100000000L);
        output1.setAddress("FBmgfrbzRiJNTPnjgknRxqVU2CmKQFnKM4");
        TxOutput output2=new TxOutput();
        output2.setAmount(2000*100000000L);
        output2.setAddress("FBmgfrbzRiJNTPnjgknRxqVU2CmKQFnKM4");

        TxOutput output3=new TxOutput();
        output3.setAmount(3*100000000L);
        output3.setAddress("F8TWjdrQ4vFjB772iWeyw4gQnjaKzy7QVb");

        List<TxOutput> outputs=new ArrayList<>();
        outputs.add(output1);
        outputs.add(output2);

        String returnAddr="FBmgfrbzRiJNTPnjgknRxqVU2CmKQFnKM4";

        long fee=100000000L;

        System.out.println(FchTool.createTransactionSign(inputs,outputs,"您好",returnAddr,fee));

        System.out.println(FchTool.msgHash("年"));
        //System.out.println(FchTool.msgFileHash("/home/seaky/4.txt"));


    }
}
