/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.x509;

/**
 *
 * @author Ender
 */
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DLSequence;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.data;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import static org.bouncycastle.cms.RecipientId.password;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

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
public class PrivateKeyReader {

    // Private key file using PKCS #1 encoding
    public static final String P1_BEGIN_MARKER
            = "-----BEGIN RSA PRIVATE KEY"; //$NON-NLS-1$
    public static final String P1_END_MARKER
            = "-----END RSA PRIVATE KEY"; //$NON-NLS-1$

    // Private key file using PKCS #8 encoding
    public static final String P8_BEGIN_MARKER
            = "-----BEGIN PRIVATE KEY"; //$NON-NLS-1$
    public static final String P8_END_MARKER
            = "-----END PRIVATE KEY"; //$NON-NLS-1$

    private static Map<String, PrivateKey> keyCache
            = Collections.synchronizedMap(new HashMap<String, PrivateKey>());

    protected final String fileName;

    /**
     * Create a PEM private key file reader.
     *
     * @param fileName The name of the PEM file
     */
    public PrivateKeyReader(String fileName) {
        this.fileName = fileName;
    }

    /**
     * Get a Private Key for the file.
     *
     * @return Private key
     * @throws IOException
     */
    public String getPrivateKey() {
        String output = null;
        PrivateKey key = null;
        FileInputStream fis = null;
        boolean isRSAKey = false;
        boolean isEncryptedRSAKey = false;
        File f = new File(fileName);
        try {
            fis = new FileInputStream(f);

            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ")
                            && line.endsWith(" PRIVATE KEY-----")) {
                        inKey = true;
                        isRSAKey = line.contains("RSA");
                        isEncryptedRSAKey = line.contains("ENCRYPTED");
                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ")
                            && line.endsWith(" PRIVATE KEY-----")) {
                        inKey = false;
                        isRSAKey = line.contains("RSA");
                        isEncryptedRSAKey = line.contains("ENCRYPTED");
                        break;
                    }
                    builder.append(line);
                }
            }
            KeySpec keySpec = null;
            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            Security.addProvider(new BouncyCastleProvider());
            if (isEncryptedRSAKey) {
                FileInputStream fiss = null;
                File fs = new File(fileName);
                fiss = new FileInputStream(fs);

                BufferedReader brs = new BufferedReader(new InputStreamReader(fiss));

                PEMParser parser = new PEMParser(brs);
                PKCS8EncryptedPrivateKeyInfo pair = (PKCS8EncryptedPrivateKeyInfo) parser.readObject();
                JceOpenSSLPKCS8DecryptorProviderBuilder jce = new JceOpenSSLPKCS8DecryptorProviderBuilder();

                jce.setProvider("BC");
                InputDecryptorProvider decProv;
                try {
                    decProv = jce.build("aapa".toCharArray());
                    PrivateKeyInfo info = pair.decryptPrivateKeyInfo(decProv);
                    System.out.println("org.caulfield.enigma.crypto.x509.PrivateKeyReader.getPrivateKey()" + info.parsePrivateKey().toASN1Primitive().toString());
                } catch (OperatorCreationException ex) {
                    Logger.getLogger(PrivateKeyReader.class.getName()).log(Level.SEVERE, null, ex);
                } catch (PKCSException ex) {
                    Logger.getLogger(PrivateKeyReader.class.getName()).log(Level.SEVERE, null, ex);
                    if (ex.toString().contains("corrupted")) {
                        return "Encrypted RSA PKCS#8 Private Key File detected.";
                    } else {
                        return "Corrupted RSA PKCS#8 Private Key File detected.";
                    }
                }

            } else if (isRSAKey) {
                //keySpec = getRSAKeySpec(encoded);
                FileInputStream fiss = null;
                File fs = new File(fileName);
                fiss = new FileInputStream(fs);

                BufferedReader brs = new BufferedReader(new InputStreamReader(fiss));

                PEMParser pemParser = new PEMParser(brs);
                Object object = pemParser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

                KeyPair kp = null;

                PEMKeyPair ukp = (PEMKeyPair) object;
                kp = converter.getKeyPair(ukp);
//            }

// RSA
                KeyFactory keyFac = KeyFactory.getInstance("RSA");
                RSAPrivateCrtKeySpec privateKey = keyFac.getKeySpec(kp.getPrivate(), RSAPrivateCrtKeySpec.class);

                System.out.println(privateKey.getClass());
                System.out.println("org.caulfield.enigma.crypto.x509.PrivateKeyReader.getPrivateKey()" + privateKey.getPublicExponent());
                return "RSA PKCS#8 Private Key File without password detected.";

//            ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(encoded));
//            ASN1Primitive obj = bIn.readObject();
//            System.out.println(ASN1Dump.dumpAsString(obj));
//            DLSequence app = (DLSequence) obj;
//            Enumeration secEnum = app.getObjects();
//            while (secEnum.hasMoreElements()) {
//                ASN1Primitive seqObj = (ASN1Primitive) secEnum.nextElement();
//                System.out.println(seqObj);
//            }
            } else {
                keySpec = new PKCS8EncodedKeySpec(encoded);

            }
            KeyFactory kf = KeyFactory.getInstance("RSA");
            key = kf.generatePrivate(keySpec);

            return "PKCS#8 Private Key File without password detected.";

        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(PrivateKeyReader.class.getName()).log(Level.SEVERE, null, ex);
            return "not a X509 file";
        }
    }

}
