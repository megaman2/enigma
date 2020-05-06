/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.x509.reader;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

/**
 *
 * @author Ender
 */
public class PKCS7Reader {

    // Private key file using PKCS #8 encoding
    public static final String PKCS7_BEGIN_MARKER
            = "-----BEGIN CERTIFICATE REQUEST"; //$NON-NLS-1$
    public static final String PKCS7_END_MARKER
            = "-----END CERTIFICATE REQUEST"; //$NON-NLS-1$

    protected final String fileName;

    /**
     * Create a PEM private key file reader.
     *
     * @param fileName The name of the PEM file
     */
    public PKCS7Reader(String fileName) {
        this.fileName = fileName;
    }

    /**
     * Get a Private Key for the file.
     *
     * @return Private key
     * @throws IOException
     */
    public String getPKCS7() {
//        String output = null;
//        PKCS10CertificationRequest csr = null;
        FileInputStream fis = null;
        String output = "Not a PKCS7 file";
        File f = new File(fileName);
        try {
            fis = new FileInputStream(f);

            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith(PKCS7_BEGIN_MARKER)) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.startsWith(PKCS7_END_MARKER)) {
                        inKey = false;
                        break;
                    }
                    builder.append(line);
                }
            }

            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            String tryCMS = tryCMS(encoded);
            if (tryCMS.contains("detected")) {
                return tryCMS;
            }
            String tryLegacyPKCS7 = tryLegacyPKCS7(encoded);
            if (tryLegacyPKCS7.contains("detected")) {
                return tryLegacyPKCS7;
            }

        } catch (IOException | NullPointerException ex) {
            Logger.getLogger(PublicKeyReader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a PKCS7 file";
        }
        return output;
    }

    private String tryCMS(byte[] encoded) {
        // CMS BLOCK
        CMSSignedData signature;
        String out = null;
        try {
            signature = new CMSSignedData(encoded);

            Store cs = signature.getCertificates();
            SignerInformationStore signers = signature.getSignerInfos();
            Collection c = signers.getSigners();
            Iterator it = c.iterator();

            //the following array will contain the content of xml document
            byte[] data = null;

            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                Collection certCollection = cs.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();
                X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

                CMSProcessable sc = signature.getSignedContent();
                data = (byte[]) sc.getContent();
                out = cert.getSubject().toString();
                System.out.println("org.caulfield.enigma.crypto.x509.CSRReader.getCSR()" + cert.getSubject());
                System.out.println("org.caulfield.enigma.crypto.x509.CSRReader.getCSR()" + data);
            }
        } catch (CMSException ex) {
            Logger.getLogger(PKCS7Reader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a CMS signed file";
        }
        return "X509 CMS file signed with " + out + " detected";
    }

    private String tryLegacyPKCS7(byte[] encoded) {
    	return "Not a Legacy PKCS7 file";
    }
}
