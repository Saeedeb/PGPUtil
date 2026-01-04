package com.example.pgputilexample;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.Security;
import java.util.Iterator;

public class PGPDecryptor4 {


    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * تابع اصلی رمزگشایی و تأیید امضا.
     */
    public static void decryptAndVerifyFile(
            String inputFilePath,
            String secretKeyFilePath,
            String passphrase,
            String outputFilePath,
            String senderPublicKeyFilePath) throws IOException, PGPException, Exception {

        // --- ۱. بارگذاری کلیدها ---
        PGPSecretKey secretKey;
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream(secretKeyFilePath))) {
            secretKey = readSecretKey(keyIn);
        }

        PGPPrivateKey privateKey = secretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray())
        );

        // بارگذاری کلید عمومی فرستنده (برای تأیید امضا)
        PGPPublicKeyRingCollection publicKeys;
        try (InputStream pubKeyIn = new BufferedInputStream(new FileInputStream(senderPublicKeyFilePath))) {
            publicKeys = readPublicKeyRing(pubKeyIn);
        }

        // --- ۲. پردازش فایل رمزنگاری شده ---
        PGPOnePassSignatureList opsList = null;
        PGPSignatureList sigList = null;

        try (
                InputStream fileIn = new BufferedInputStream(new FileInputStream(inputFilePath));
                InputStream in = PGPUtil.getDecoderStream(fileIn); // هندل کردن Armored
                OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath))
        ) {
            PGPObjectFactory pgpFactory = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
            Object obj;

            // حلقه اصلی برای پیمایش بسته‌های PGP (EncryptedDataList)
            while ((obj = pgpFactory.nextObject()) != null) {
                if (obj instanceof PGPEncryptedDataList) {
                    PGPEncryptedDataList encList = (PGPEncryptedDataList) obj;

                    // پیدا کردن داده رمزنگاری شده برای کلید ما
                    PGPPublicKeyEncryptedData pked = findPublicKeyEncryptedData(encList, secretKey.getKeyID());

                    if (pked != null) {
                        // رمزگشایی کلید جلسه (Session Key)
                        InputStream clear = pked.getDataStream(

                                new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey)
                        );

                        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
                        Object message;

                        // --- حلقه پردازش محتوای رمزگشایی شده (Compressed/Literal/Signature) ---
                        while ((message = plainFact.nextObject()) != null) {

                            if (message instanceof PGPCompressedData) {
                                // A. مدیریت داده فشرده (که شامل امضا است)
                                PGPCompressedData cData = (PGPCompressedData) message;
                                PGPObjectFactory pgpFact2 = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());
                                Object msg2;

                                // حلقه داخلی برای خواندن بسته‌های داخل جریان فشرده
                                while ((msg2 = pgpFact2.nextObject()) != null) {

                                    if (msg2 instanceof PGPOnePassSignatureList) {
                                        // A.1. امضای یک‌گذر (که در داخل فشرده‌سازی قرار دارد)
                                        opsList = (PGPOnePassSignatureList) msg2;
                                        initializeSignatures(opsList, publicKeys);

                                    } else if (msg2 instanceof PGPLiteralData) {
                                        // A.2. داده‌ی اصلی
                                        handleDataPacket(msg2, out, opsList);

                                    } else if (msg2 instanceof PGPSignatureList) {
                                        // A.3. امضای نهایی (که در داخل فشرده‌سازی قرار دارد)
                                        sigList = (PGPSignatureList) msg2;
                                        System.out.println("✅ بسته‌ی امضای نهایی در جریان فشرده‌سازی یافت شد.");

                                    } else {
                                        System.err.println("⚠️ بسته‌ی ناشناخته داخل CompressedData: " + msg2.getClass().getName());
                                    }
                                }
                            }

                            // B. مدیریت داده ادبی (Literal Data - در صورت عدم فشرده‌سازی)
                            else if (message instanceof PGPLiteralData) {
                                // اگر فایل فشرده‌سازی نشده باشد و امضا شده باشد، منطق بالا باید اینجا تکرار شود
                                handleDataPacket(message, out, opsList);
                            }
                            // C. مدیریت امضای یک‌گذر یا نهایی در صورت عدم فشرده‌سازی
                            // در این ساختار، چون همیشه از فشرده‌سازی استفاده می‌کنید، نیازی به اضافه کردن منطق اینجا نیست.

                        }

                        // --- ۳. تأیید نهایی امضا و Integrity ---
                        finalizeVerification(opsList, sigList);
                        checkIntegrity(pked);

                    } else {
                        throw new PGPException("Error: Encrypted data not found for the provided secret key.");
                    }
                }
            }
        }
    }

    // ۱. خواندن کلید خصوصی
    private static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());


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

    // ۲. خواندن کلید عمومی
    public static PGPPublicKeyRingCollection readPublicKeyRing(InputStream inputStream)
            throws IOException, PGPException {
        InputStream decoderStream = PGPUtil.getDecoderStream(inputStream);
        return new PGPPublicKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
    }

    // ۳. پیدا کردن کلید عمومی
    private static PGPPublicKey findPublicKey(PGPPublicKeyRingCollection pgpPublicKeyRingCollection, long keyID)
            throws PGPException {
        // متد getPublicKey به صورت خودکار در تمام Key Rings جستجو می‌کند.
        return pgpPublicKeyRingCollection.getPublicKey(keyID);
    }

    private static PGPPublicKeyEncryptedData findPublicKeyEncryptedData(PGPEncryptedDataList encList, long keyID) {
        Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects();
        while (it.hasNext()) {
            PGPEncryptedData pked = it.next();
            if (pked instanceof PGPPublicKeyEncryptedData && ((PGPPublicKeyEncryptedData) pked).getKeyID() == keyID) {
                return (PGPPublicKeyEncryptedData) pked;
            }
        }
        return null;
    }

    // ۴. مقداردهی اولیه امضای یک‌گذر
    private static void initializeSignatures(PGPOnePassSignatureList opsList, PGPPublicKeyRingCollection publicKeys)
            throws PGPException {

        for (int i = 0; i < opsList.size(); i++) {
            PGPOnePassSignature ops = opsList.get(i);
            PGPPublicKey signingKey = findPublicKey(publicKeys, ops.getKeyID());

            if (signingKey != null) {
                ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signingKey);
                System.out.println("✅ امضای یک‌گذر یافت شد. کلید فرستنده: " + Long.toHexString(signingKey.getKeyID()));
            } else {
                System.err.println("⚠️ کلید عمومی فرستنده با ID: " + Long.toHexString(ops.getKeyID()) + " برای تأیید امضا یافت نشد.");
            }
        }
    }

    // ۵. خواندن داده و آپدیت امضا
    private static void handleDataPacket(Object packet, OutputStream out, PGPOnePassSignatureList opsList)
            throws IOException {
        if (packet instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) packet;
            try (InputStream unc = ld.getInputStream()) {
                byte[] buffer = new byte[4096];
                int len;
                while ((len = unc.read(buffer)) > 0) {
                    out.write(buffer, 0, len);

                    if (opsList != null) {
                        for (int i = 0; i < opsList.size(); i++) {
                            opsList.get(i).update(buffer, 0, len);
                        }
                    }
                }
            }
        }
    }


    private static void finalizeVerification(PGPOnePassSignatureList opsList, PGPSignatureList sigList)
            throws PGPException {
        if (opsList != null && sigList != null && opsList.size() > 0 && sigList.size() > 0) {
            boolean verified = true;
            for (int i = 0; i < opsList.size(); i++) {
                if (!opsList.get(i).verify(sigList.get(i))) {
                    System.err.println("❌ خطای تأیید امضای نهایی! داده‌ها پس از امضا دستکاری شده‌اند.");
                    verified = false;
                }
            }
            if (verified) {
                System.out.println("✅ تأیید امضای دیجیتال موفقیت‌آمیز بود.");
            }
        } else if (opsList == null && sigList == null) {
            System.out.println("ℹ️ فایل فاقد امضای دیجیتال است.");
        } else {
            System.err.println("⚠️ مشکل در ساختار امضا. بسته‌های امضا ناقص هستند.");
        }
    }


    private static void checkIntegrity(PGPPublicKeyEncryptedData pked) throws PGPException, IOException {
        if (pked.isIntegrityProtected()) {

            if (!pked.verify()) {
                System.err.println("❌ خطای بررسی یکپارچگی داده (MDC)! داده‌ها ممکن است دستکاری شده باشند.");
            } else {
                System.out.println("✅ بررسی یکپارچگی داده (MDC) موفقیت‌آمیز بود.");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        String encryptedFile =  "src/main/resources/PEC_581672062_TNXAD_v01_14040902_002.acq.rsp";
        String privateKeyPath = "src/main/resources/keys/pec-privateKey.asc";
        String publicShaparakKey = "src/main/resources/keys/shaparak-publicKey.asc";
        String publicKey = "src/main/resources/keys/PecVasFileKey_public.asc";

        String passphrase = "123456789";
        String outputFile = "src/main/resources/pure005.txt";


        decryptAndVerifyFile(encryptedFile, privateKeyPath, passphrase, outputFile, publicShaparakKey);
    }
}