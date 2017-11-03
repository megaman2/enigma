/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.x509.reader;

/**
 *
 * @author Ender
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * Class for reading RSA private key from PEM file. It uses the JMeter
 * FileServer to find the file. So the file should be located in the same
 * directory as the test plan if the path is relative.
 *
 * <p/>
 * There is a cache so each file is only read once. If file is changed, it will
 * not take effect until the program restarts.
 *
 * <p/>
 * It can read PEM files with PKCS#8 or PKCS#1 encodings. It doesn't support
 * encrypted PEM files.
 *
 */
public class PublicKeyReader {

    // Private key file using PKCS #1 encoding
    public static final String P1_BEGIN_MARKER
            = "-----BEGIN RSA PUBLIC KEY"; //$NON-NLS-1$
    public static final String P1_END_MARKER
            = "-----END RSA PUBLIC KEY"; //$NON-NLS-1$

    // Private key file using PKCS #8 encoding
    public static final String P8_BEGIN_MARKER
            = "-----BEGIN PUBLIC KEY"; //$NON-NLS-1$
    public static final String P8_END_MARKER
            = "-----END PUBLIC KEY"; //$NON-NLS-1$

    protected final String fileName;

    /**
     * Create a PEM private key file reader.
     *
     * @param fileName The name of the PEM file
     */
    public PublicKeyReader(String fileName) {
        this.fileName = fileName;
    }

    /**
     * Get a Private Key for the file.
     *
     * @return Private key
     * @throws IOException
     */
    public String getPublicKey() {
        String output = null;
        PublicKey key = null;
        FileInputStream fis = null;
        boolean isRSAKey = false;

        File f = new File(fileName);
        try {
            fis = new FileInputStream(f);

            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ")
                            && line.endsWith(" PUBLIC KEY-----")) {
                        inKey = true;
                        isRSAKey = line.contains("RSA");

                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ")
                            && line.endsWith(" PUBLIC KEY-----")) {
                        inKey = false;
                        isRSAKey = line.contains("RSA");

                        break;
                    }
                    builder.append(line);
                }
            }
            KeySpec keySpec = null;
            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            Security.addProvider(new BouncyCastleProvider());
            if (isRSAKey) {
                File fs = new File(fileName);
                FileInputStream fiss = new FileInputStream(fs);

                BufferedReader brs = new BufferedReader(new InputStreamReader(fiss));

                PEMParser pemParser = new PEMParser(brs);
                Object object = pemParser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                PEMKeyPair ukp = (PEMKeyPair) object;
                KeyPair kp = converter.getKeyPair(ukp);

                // RSA
                KeyFactory keyFac = KeyFactory.getInstance("RSA");
                RSAPublicKeySpec publicKey = keyFac.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
                System.out.println(publicKey.getClass());
                System.out.println("org.caulfield.enigma.crypto.x509.PrivateKeyReader.getPublicKey()" + publicKey.getPublicExponent());

                return "RSA Public Key File detected.";
            } else {
                keySpec = new X509EncodedKeySpec(encoded);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                key = kf.generatePublic(keySpec);

                return "Public Key File detected.";

            }

        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(PublicKeyReader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a public key";
        }
    }

}
