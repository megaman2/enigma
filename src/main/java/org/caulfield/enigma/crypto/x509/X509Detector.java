/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.x509;

import org.caulfield.enigma.crypto.x509.reader.CSRReader;
import org.caulfield.enigma.crypto.x509.reader.PublicKeyReader;
import org.caulfield.enigma.crypto.x509.reader.CertificateReader;
import org.caulfield.enigma.crypto.x509.reader.PrivateKeyReader;
import org.caulfield.enigma.crypto.x509.reader.PKCS7Reader;
import org.caulfield.enigma.crypto.x509.reader.PKCS12Reader;
import java.io.File;

/**
 *
 * @author Ender
 */
public class X509Detector {

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

    public String detectPKCS7(File f) {
        PKCS7Reader pbr = new PKCS7Reader(f.getAbsolutePath());
        return pbr.getPKCS7();
    }

    public String detectPKCS12(File f) {
        PKCS12Reader pbr = new PKCS12Reader(f.getAbsolutePath());
        return pbr.getPKCS12();
    }
}
