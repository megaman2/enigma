/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.init;

import java.util.Date;
import org.caulfield.enigma.crypto.CryptoGenerator;

/**
 *GET
 * @author pbakhtiari
 */
public class ObjectsInitializer {

    public static String[] createLocalObjects() {
        String[] out = new String[3];
        CryptoGenerator cg = new CryptoGenerator();
        String user = System.getProperty("user.name").toUpperCase();
        // GENERATE ROOT PRIVATE KEY
        out[0] = cg.buildPrivateKey("", "", user +"_private.key", 2048, "65537", 8, "RSA", user+"_private");
        // GENERATE ROOT PUBLIC KEY
        out[1] = cg.generatePublicKeyFromPrivateKey("1. "+user +"_private", "", "", user+"_public.key", user +"_public");
        // GENERATE ROOT CERTIFICATE USING PRIVATE & PUBLIC KEY
        out[2] = cg.generateCertificateFromPublicKeyAndPrivateKey("CN=AC LOCALE DE " + user+ ",O=LOCAL", "2. "+user+"_public", "1. "+user+"_private", "", "", user+"_certificate.crt", new Date(), "SHA256withRSA", "V3",System.getProperty("user.name").toUpperCase());
        return out;
    }
    public static void main(String [] args){
        createLocalObjects();
    }
}
