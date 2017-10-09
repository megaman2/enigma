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

    public String detectPrivateKey(File f) {
        PrivateKeyReader fde = new PrivateKeyReader(f.getAbsolutePath());
        return fde.getPrivateKey();
    }

    public String detectPublicKey(File f) {
        PublicKeyReader pbr = new PublicKeyReader(f.getAbsolutePath());
        return pbr.getPublicKey();
    }

    public String detectCSR(File f) {
        CSRReader pbr = new CSRReader(f.getAbsolutePath());
        return pbr.getCSR();
    }

    public String detectCertificate(File f) {
        CertificateReader pbr = new CertificateReader(f.getAbsolutePath());
        return pbr.getCertificate();
    }
}
