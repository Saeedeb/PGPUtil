package com.example.pgputilexample;

import java.io.FileInputStream;

public class FileHexDump {
    public static void main(String[] args) throws Exception {
        String inputFile = "src/main/resources/PEC_581672062_TNXAD_v01_14040617_005.acq.rsp"; // فایل شما
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] buffer = new byte[32];
            int read = fis.read(buffer);
            System.out.println("First " + read + " bytes in HEX:");
            for (int i = 0; i < read; i++) {
                System.out.printf("%02X ", buffer[i]);
            }
            System.out.println();
        }
    }
}