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
        // GENERATE ROOT PRIVATE KEY
        out[0] = cg.buildPrivateKey(".", "", "ROOT_private.key", 2048, "65537", 8, "RSA", "ROOT_private");
        // GENERATE ROOT PUBLIC KEY
        out[1] = cg.generatePublicKeyFromPrivateKey("1. ROOT_private", "", ".", "ROOT_public.key", "ROOT_public");
        // GENERATE ROOT CERTIFICATE USING PRIVATE & PUBLIC KEY
        out[2] = cg.generateCertificateFromPublicKeyAndPrivateKey("CN=AC LOCALE DE " + System.getProperty("user.name").toUpperCase() + ",O=LOCAL", "2. ROOT_public", "1. ROOT_private", "", ".", "ROOT_Certificate.crt", new Date(), "SHA256withRSA", "V3");
        return out;
    }
    public static void main(String [] args){
        createLocalObjects();
    }
}
