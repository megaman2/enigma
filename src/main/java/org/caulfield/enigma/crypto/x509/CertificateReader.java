/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.x509;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ender
 */
public class CertificateReader {

    public static final String CRT_BEGIN_MARKER
            = "-----BEGIN CERTIFICATE"; //$NON-NLS-1$
    public static final String CRT_END_MARKER
            = "-----END CERTIFICATE"; //$NON-NLS-1$

    protected final String fileName;

    public CertificateReader(String fileName) {
        this.fileName = fileName;
    }

    public String getCertificate() {
        try {
            FileInputStream fis = null;
            String format = null;
            File f = new File(fileName);

            fis = new FileInputStream(f);

            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            String firstLine = br.readLine();
            if (firstLine.startsWith(CRT_BEGIN_MARKER)) {
                format = "PEM";
                inKey = true;
            } else {
                format = "DER";
                builder.append(firstLine);
            }
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (inKey) {
                    if (line.startsWith(CRT_END_MARKER)) {
                        inKey = false;
                        break;
                    }
                    builder.append(line);
                }
            }

            //byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            File fF = new File(fileName);
            FileInputStream fiS = new FileInputStream(fF);
            X509Certificate cer = (X509Certificate) fact.generateCertificate(fiS);
            System.out.println("org.caulfield.enigma.crypto.x509.CSRReader.getCertificate()" + cer.getSubjectX500Principal().getName());
            return format + " certificate detected.";

        } catch (IOException | NullPointerException ex) {
            Logger.getLogger(PublicKeyReader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a certificate";
        } catch (CertificateException ex) {
            Logger.getLogger(CertificateReader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a certificate";
        }
    }
}
