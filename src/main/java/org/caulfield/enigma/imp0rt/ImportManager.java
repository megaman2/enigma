/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.imp0rt;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.DatatypeConverter;
import org.caulfield.enigma.crypto.CryptoGenerator;
import org.caulfield.enigma.crypto.hash.HashCalculator;
import org.caulfield.enigma.database.CryptoDAO;

/**
 *
 * @author Ender
 */
public class ImportManager {

    public String importCertificate(File cert) {
        try {
            CryptoGenerator cg = new CryptoGenerator();

            X509Certificate certX = cg.getCertificate(cert);
            byte[] cc = certX.getEncoded();
            String algo = certX.getSigAlgName();
            HashCalculator hashc = new HashCalculator();
            String realHash= hashc.getStringChecksum(cert, HashCalculator.SHA256);
            String thumbPrint = hashc.getThumbprint(certX);
            String CN = certX.getSubjectDN().getName();
            System.out.println(CN);
            System.out.println(thumbPrint);
            String certName = null;
            System.out.println( CN.substring(1,CN.indexOf(",")));
            //if(CN.length()>)CN.replaceAll("CN=", "");
            // DAO Write it
            //CryptoDAO.insertCertInDB(cert, certName, CN, realHash, algo, 0, thumbPrint);
            return "Certificate imported successfully as "+certName;

        } catch (CertificateEncodingException | NoSuchAlgorithmException ex) {
            Logger.getLogger(ImportManager.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate export failed.";
        }
    }

//    public String importKey(File key) {
//        try {
//
//            byte[] buffer = new byte[is.available()];
//            is.read(buffer);
//
//            OutputStream outStream = new FileOutputStream(targetFile);
//            outStream.write(buffer);
//            outStream.flush();
//            outStream.close();
//            return "Key exported successfully as " + targetFile;
//        } catch (IOException ex) {
//            Logger.getLogger(ImportManager.class.getName()).log(Level.SEVERE, null, ex);
//            return "Key export failed.";
//        }
//    }
}
