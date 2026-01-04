package com.example.pgputilexample;


import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.*;
import java.security.Security;
import java.util.Iterator;

public class PGPFileDecryptor2 {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String encryptedFile =  "src/main/resources/PEC_581672062_TNXAD_v01_14040617_005.acq.rsp"; // فایل رمزگذاری‌شده
        String privateKeyPath = "src/main/resources/keys/pec-privateKey.asc"; // کلید خصوصی شما
        String passphrase = "123456789"; // پسورد کلید خصوصی
        String outputFile = "src/main/resources/decrypted.txt"; // خروجی

        decryptFile(encryptedFile, outputFile, privateKeyPath, passphrase);
    }



    public static void decryptFile(String inputFile, String outputFile,
                                   String privateKeyFile, String passphrase) throws Exception {

        InputStream keyIn = new FileInputStream(privateKeyFile);
        InputStream in = new FileInputStream(inputFile);
        if (inputFile.endsWith(".asc")) {
            in = new ArmoredInputStream(in);
        }

        PGPObjectFactory pgpF = new PGPObjectFactory(
                PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());

        Object o = null;
        PGPEncryptedDataList enc = null;

        while ((o = pgpF.nextObject()) != null) {
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
                break;
            }
        }

        if (enc == null) {
            throw new IllegalArgumentException("Encrypted data not found in file.");
        }

        Iterator<?> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            PGPSecretKey secretKey = pgpSec.getSecretKey(pbe.getKeyID());
            if (secretKey != null) {
                PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder()
                        .setProvider("BC")
                        .build(passphrase.toCharArray());
                sKey = secretKey.extractPrivateKey(decryptor);
            }
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
        Object message = plainFact.nextObject();

        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;
            InputStream unc = ld.getInputStream();
            FileOutputStream out = new FileOutputStream(outputFile);
            byte[] buf = new byte[1024];
            int len;
            while ((len = unc.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
            out.close();
            System.out.println("File decrypted successfully to: " + outputFile);
        } else {
            throw new PGPException("Message is not a simple encrypted file.");
        }

        if (pbe.isIntegrityProtected() && !pbe.verify()) {
            System.err.println("Warning: message failed integrity check!");
        }

        in.close();
        keyIn.close();
    }
}