/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.x509;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ender
 */
public class X509Manager {

    public String detectX509(File f) {
        byte[] keyBytes;

        try {
            keyBytes = Files.readAllBytes(Paths.get(f.getAbsolutePath()));
            String privateKey = new String(keyBytes, "UTF-8");
            System.out.println(privateKey);
            PrivateKeyReader fde = new PrivateKeyReader(f.getAbsolutePath());
            return fde.getPrivateKey();

        } catch (IOException ex) {
//            try {
//                keyBytes = Files.readAllBytes(Paths.get(f.getAbsolutePath()));
//                PKCS8EncodedKeySpec spec
//                        = new PKCS8EncodedKeySpec(keyBytes);
//                kf = KeyFactory.getInstance("RSA");
//                kf.generatePublic(spec);
//            } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException exx) {
//                System.out.println("org.caulfield.enigma.crypto.x509.X509Manager.detectX509()" + exx.getMessage());
//                return false;
//            }

            Logger.getLogger(X509Manager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "No X509 detected.";
    }
}
