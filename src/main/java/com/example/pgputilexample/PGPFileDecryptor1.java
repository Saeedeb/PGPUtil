package com.example.pgputilexample;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.*;
import java.security.Security;
import java.util.Iterator;

public class PGPFileDecryptor1 {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String encryptedFile = "src/main/resources/PEC_581672062_TNXAD_v01_14040617_005.acq.rsp";   // فایل رمزگذاری شده
        String privateKeyFile = "src/main/resources/keys/pec-privateKey.asc";    // کلید خصوصی
        String outputFile = "src/main/resources/decrypted.txt";      // فایل خروجی
        String passphrase = "123456789";    // پسورد کلید خصوصی

        decryptFile(encryptedFile, privateKeyFile, outputFile, passphrase);
    }

    public static void decryptFile(String encryptedFile, String privateKeyFile,
                                   String outputFile, String passphrase) throws Exception {

        try (InputStream encryptedData = new BufferedInputStream(new FileInputStream(encryptedFile));
             InputStream keyIn = new BufferedInputStream(new FileInputStream(privateKeyFile));
             OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {

            InputStream decoderStream = PGPUtil.getDecoderStream(encryptedData);
            JcaPGPObjectFactory pgpFactory   = new JcaPGPObjectFactory(decoderStream);

            Object object = pgpFactory.nextObject();
            PGPEncryptedDataList enc;

            if (object instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) object;
            } else {
                enc = (PGPEncryptedDataList) pgpFactory.nextObject();
            }

            // کلید خصوصی رو پیدا کن
            PGPPrivateKey privateKey = null;
            PGPPublicKeyEncryptedData encryptedDataObj = null;

            Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            while (privateKey == null && it.hasNext()) {
                encryptedDataObj = (PGPPublicKeyEncryptedData) it.next();
                privateKey = findPrivateKey(pgpSec, encryptedDataObj.getKeyID(), passphrase.toCharArray());
            }

            if (privateKey == null) {
                throw new IllegalArgumentException("Private key for decryption not found.");
            }

            InputStream clear = encryptedDataObj.getDataStream(
                    new JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider("BC").build(privateKey));

            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) message;
                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedData.getDataStream());
                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData literalData = (PGPLiteralData) message;
                InputStream unc = literalData.getInputStream();
                int ch;
                while ((ch = unc.read()) >= 0) {
                    out.write(ch);
                }
            } else {
                throw new PGPException("Message is not a simple encrypted file.");
            }

            if (encryptedDataObj.isIntegrityProtected() && !encryptedDataObj.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        }
    }

    private static PGPPrivateKey findPrivateKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException {
        PGPSecretKey secretKey = pgpSec.getSecretKey(keyID);
        if (secretKey == null) {
            return null;
        }
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder()
                .setProvider("BC").build(pass);
        return secretKey.extractPrivateKey(decryptor);
    }
}
