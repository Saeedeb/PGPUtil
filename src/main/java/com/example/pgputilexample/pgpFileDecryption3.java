package com.example.pgputilexample;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class pgpFileDecryption3 {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String encryptedFile =  "src/main/resources/PEC_581672062_TNXAD_v01_14040826_004.acq.rsp"; // فایل رمزگذاری‌شده
        String privateKeyPath = "src/main/resources/keys/pec-privateKey.asc"; // کلید خصوصی شما
        String passphrase = "123456789"; // پسورد کلید خصوصی
        String outputFile = "src/main/resources/pure004.txt"; // خروجی


        decryptFile(encryptedFile, privateKeyPath, passphrase, outputFile);
        System.out.println("Decryption completed!");
    }

    public static void decryptFile(String inputFilePath, String keyFilePath, String passphrase, String outputFilePath) throws Exception {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFilePath));
        PGPSecretKey secretKey = readSecretKey(keyIn);
        keyIn.close();

        PGPPrivateKey privateKey = secretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder()
                        .setProvider("BC")
                        .build(passphrase.toCharArray())
        );

        InputStream fileIn = new BufferedInputStream(new FileInputStream(inputFilePath));
        InputStream in = PGPUtil.getDecoderStream(fileIn);

        PGPObjectFactory pgpFactory = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        Object obj;
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath));

        while ((obj = pgpFactory.nextObject()) != null) {
            if (obj instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList encList = (PGPEncryptedDataList) obj;
                Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects();
                while (it.hasNext()) {
                    PGPPublicKeyEncryptedData pked = (PGPPublicKeyEncryptedData) it.next();
                    if (pked.getKeyID() == secretKey.getKeyID()) {
                        InputStream clear = pked.getDataStream(
                                new JcePublicKeyDataDecryptorFactoryBuilder()
                                        .setProvider("BC")
                                        .build(privateKey)
                        );

                        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
                        Object message;
                        while ((message = plainFact.nextObject()) != null) {
                            if (message instanceof PGPCompressedData) {
                                PGPCompressedData cData = (PGPCompressedData) message;
                                PGPObjectFactory pgpFact2 = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());
                                Object msg2;
                                while ((msg2 = pgpFact2.nextObject()) != null) {
                                    if (msg2 instanceof PGPLiteralData) {
                                        PGPLiteralData ld = (PGPLiteralData) msg2;
                                        InputStream unc = ld.getInputStream();
                                        byte[] buffer = new byte[4096];
                                        int len;
                                        while ((len = unc.read(buffer)) > 0) {
                                            out.write(buffer, 0, len);
                                        }
                                    }
                                }
                            } else if (message instanceof PGPLiteralData) {
                                PGPLiteralData ld = (PGPLiteralData) message;
                                InputStream unc = ld.getInputStream();
                                byte[] buffer = new byte[4096];
                                int len;
                                while ((len = unc.read(buffer)) > 0) {
                                    out.write(buffer, 0, len);
                                }
                            }
                        }

                        if (pked.isIntegrityProtected()) {
                            if (!pked.verify()) {
                                System.err.println("Warning: message failed integrity check");
                            }
                        }
                    }
                }
            }
        }
        out.close();
        fileIn.close();
    }

    private static PGPSecretKey readSecretKey(InputStream keyIn) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn),
                new JcaKeyFingerprintCalculator()
        );

        Iterator<PGPSecretKeyRing> keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = keyRingIter.next();
            Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = keyIter.next();
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }
}
