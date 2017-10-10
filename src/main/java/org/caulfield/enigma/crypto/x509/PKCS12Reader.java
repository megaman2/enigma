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
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    private static final int JKS = 0;
    private static final int PKCS12 = 1;
    private static final int UNKNOWN = 2;

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
        File f = new File(fileName);

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

            KeyStore kstore = null;
            int type = getKeystoreType(f);
            System.out.println("org.caulfield.enigma.crypto.x509.PKCS12Reader.getPKCS12()" + type);
            switch (type) {
                case JKS: {
                    kstore = KeyStore.getInstance("jks");
                    FileInputStream kst = new FileInputStream(f);
                    kstore.load(kst, null);
                    Enumeration e = kstore.aliases();
                    while (e.hasMoreElements()) {
                        String alias = (String) e.nextElement();
                        System.out.println("org.caulfield.enigma.crypto.x509.PKCS12Reader.getPKCS12()" + alias);
                        X509Certificate c = (X509Certificate) kstore.getCertificate(alias);
                        if (c == null) {
//                            PKCS8 ;
                            Key key = kstore.getKey(alias, "".toCharArray());
                            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key.getEncoded());
                            KeyFactory kf = KeyFactory.getInstance("RSA");
                            PrivateKey privKey = kf.generatePrivate(keySpec);
                            System.out.println("org.caulfield.enigma.crypto.x509.PKCS12Reader.getPKCS12()" + privKey);
                        } else {
                            Principal subject = c.getSubjectDN();
                            String subjectArray[] = subject.toString().split(",");
                            for (String s : subjectArray) {
                                String[] str = s.trim().split("=");
                                String key = str[0];
                                String value = str[1];
                                System.out.println(key + " - " + value);
                            }
                        }
                    }
                    return "JKS keystore file detected " + format;
                }
                case PKCS12: {
                    kstore = KeyStore.getInstance("pkcs12");
                    FileInputStream kst = new FileInputStream(f);
                    kstore.load(kst, null);
                    Enumeration e = kstore.aliases();
                    while (e.hasMoreElements()) {
                        String alias = (String) e.nextElement();
                        System.out.println("org.caulfield.enigma.crypto.x509.PKCS12Reader.getPKCS12()" + alias);
                        X509Certificate c = (X509Certificate) kstore.getCertificate(alias);
                        if (c == null) {
//                            PKCS8 ;
                            Key key = kstore.getKey(alias, null);
                            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key.getEncoded());
                            KeyFactory kf = KeyFactory.getInstance("RSA");
                            PrivateKey privKey = kf.generatePrivate(keySpec);
                            System.out.println("org.caulfield.enigma.crypto.x509.PKCS12Reader.getPKCS12()" + privKey);
                        } else {
                            Principal subject = c.getSubjectDN();
                            String subjectArray[] = subject.toString().split(",");
                            for (String s : subjectArray) {
                                String[] str = s.trim().split("=");
                                String key = str[0];
                                String value = str[1];
                                System.out.println(key + " - " + value);
                            }
                        }
                    }
                    return "PKCS12 keystore file detected " + format;
                }
                case UNKNOWN:
                    return "Not a keystore file";
                default:
                    return "Not a keystore file";
            }

        } catch (IOException | NullPointerException ex) {
            Logger.getLogger(PublicKeyReader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a keystore file";
        } catch (NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(PKCS12Reader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a keystore file";
        } catch (KeyStoreException ex) {
            Logger.getLogger(PKCS12Reader.class.getName()).log(Level.SEVERE, null, ex);
            return "Possible password protected PKCS12 keystore file";
        } catch (java.security.UnrecoverableKeyException ff) {
            Logger.getLogger(PKCS12Reader.class.getName()).log(Level.SEVERE, null, ff);
            return "Possible password protected PKCS12 keystore file";
        } catch (Exception ex) {
            Logger.getLogger(PKCS12Reader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a keystore file";
        }
    }

    private int getKeystoreType(File f) throws Exception {
        KeyStore ks = null;

        FileInputStream fis = null;

        try {
            fis = new FileInputStream(f);
            ks = KeyStore.getInstance("JKS");
            ks.load(fis, null);
            return JKS;
        } catch (IOException e) {
            try {
                if (fis != null) {
                    fis.close();
                }
                fis = new FileInputStream(f);
                ks = KeyStore.getInstance("PKCS12");
                ks.load(fis, null);
                return PKCS12;
            } catch (IOException es) {
                if (fis != null) {
                    fis.close();
                }
                return UNKNOWN;
            }
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }
}
