/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.hash;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;

/**
 *
 * @author Ender
 */
public class HashCalculator {

    public static String MD5 = "MD5";
    public static String SHA1 = "SHA1";
    public static String SHA256 = "SHA-256";
    public static String SHA512 = "SHA-512";

    public byte[] checksum(String file, String algorithm) {
        File input = new File(file);
        try (InputStream in = new FileInputStream(input)) {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] block = new byte[4096];
            int length;
            while ((length = in.read(block)) > 0) {
                digest.update(block, 0, length);
            }
            return digest.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
