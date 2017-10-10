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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.caulfield.enigma.analyzer.ascii.ASCIIScanner;

/**
 *
 * @author Ender
 */
public class PKCS12Reader {

    // Private key file using PKCS #8 encoding
    public static final String PKCS12_CRT_BEGIN_MARKER
            = "-----BEGIN CERTIFICATE"; //$NON-NLS-1$
    public static final String PKCS12_CRT_END_MARKER
            = "-----END CERTIFICATE"; //$NON-NLS-1$
    // Private key file using PKCS #8 encoding
    public static final String PKCS12_KEY_BEGIN_MARKER
            = "-----BEGIN PRIVATE KEY"; //$NON-NLS-1$
    public static final String PKCS12_KEY_END_MARKER
            = "-----END PRIVATE KEY"; //$NON-NLS-1$
    protected final String fileName;

    /**
     * Create a PEM private key file reader.
     *
     * @param fileName The name of the PEM file
     */
    public PKCS12Reader(String fileName) {
        this.fileName = fileName;
    }

    /**
     * Get a Private Key for the file.
     *
     * @return Private key
     * @throws IOException
     */
    public String getPKCS12() {

        FileInputStream fis = null;
        String output = null;
        File f = new File(fileName);
        boolean isAscii = ASCIIScanner.isFileASCII(f);
        String format = null;
        try {
            fis = new FileInputStream(f);
//
            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            String firstLine = br.readLine();
            
            if (firstLine.contains(PKCS12_CRT_BEGIN_MARKER) || firstLine.contains(PKCS12_KEY_BEGIN_MARKER)) {
                format = "without password";
            } else {
                format = "password protected";
            }
//            StringBuilder builder = new StringBuilder();
//            boolean inKey = false;
//            for (String line = br.readLine(); line != null; line = br.readLine()) {
//                if (!inKey) {
//                    if (line.startsWith(PKCS7_BEGIN_MARKER)) {
//                        inKey = true;
//                    }
//                    continue;
//                } else {
//                    if (line.startsWith(PKCS7_END_MARKER)) {
//                        inKey = false;
//                        break;
//                    }
//                    builder.append(line);
//                }
//            }

//            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            KeyStore p12 = KeyStore.getInstance("pkcs12");
            p12.load(fis, "password".toCharArray());
            Enumeration e = p12.aliases();
            while (e.hasMoreElements()) {
                String alias = (String) e.nextElement();
                X509Certificate c = (X509Certificate) p12.getCertificate(alias);
                Principal subject = c.getSubjectDN();
                String subjectArray[] = subject.toString().split(",");
                for (String s : subjectArray) {
                    String[] str = s.trim().split("=");
                    String key = str[0];
                    String value = str[1];
                    System.out.println(key + " - " + value);
                }
            }
            output = (isAscii?"ASCII ":"Binary ")+"PKCS12 file detected " + format;

        } catch (IOException | NullPointerException ex) {
            Logger.getLogger(PublicKeyReader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a X509 file";
        } catch (NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(PKCS12Reader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a X509 file";
        } catch (KeyStoreException ex) {
            Logger.getLogger(PKCS12Reader.class.getName()).log(Level.SEVERE, null, ex);
            return (isAscii?"ASCII ":"Binary ")+"Possible PKCS12 password protected file";
        }
        return output;
    }

}
