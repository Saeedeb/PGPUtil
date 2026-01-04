package com.example.pgputilexample;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.InputStream;

public class PGPFileInspector {

    public static void main(String[] args) throws Exception {
        String inputFile = "src/main/resources/PEC_581672062_TNXAD_v01_14040617_005.acq.rsp"; // اسم فایلت


        try (InputStream in = new FileInputStream(inputFile);
             InputStream decoder = PGPUtil.getDecoderStream(in)) {

            PGPObjectFactory pgpFact = new PGPObjectFactory(decoder, new JcaKeyFingerprintCalculator());

            Object obj;
            while ((obj = pgpFact.nextObject()) != null) {
                System.out.println("Found object: " + obj.getClass().getName());

                if (obj instanceof PGPEncryptedDataList) {
                    System.out.println(" → This is encrypted data list");
                } else if (obj instanceof PGPCompressedData) {
                    System.out.println(" → This is compressed data");
                } else if (obj instanceof PGPLiteralData) {
                    System.out.println(" → This is literal data (actual file)");
                } else if (obj instanceof PGPSignatureList) {
                    System.out.println(" → This contains signatures");
                }
            }
        }
    }
}
