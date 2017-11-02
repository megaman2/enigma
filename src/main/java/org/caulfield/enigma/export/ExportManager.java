/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.export;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.caulfield.enigma.database.CryptoDAO;

/**
 *
 * @author Ender
 */
public class ExportManager {

    public String exportCertificate(Integer idCert, String outputFileName) {
        try {
            InputStream is = CryptoDAO.getCertFromDB(idCert);
            byte[] buffer = new byte[is.available()];
            is.read(buffer);
            File targetFile = new File(outputFileName);
            OutputStream outStream = new FileOutputStream(targetFile);
            outStream.write(buffer);
            outStream.flush();
            outStream.close();
            return "Certificate exported successfully as PEM " + targetFile;
        } catch (IOException ex) {
            Logger.getLogger(ExportManager.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate export failed.";
        }
    }

    public String exportCertificateAsDER(Integer idCert, String outputFileName) {
        try {
            InputStream is = CryptoDAO.getCertFromDB(idCert);
            byte[] buffer = new byte[is.available()];
            is.read(buffer);
            String pemFormated = new String(buffer);
            String base64 = pemFormated.replaceAll("\\s", "");
            base64 = base64.replace("-----BEGINCERTIFICATE-----", "");
            base64 = base64.replace("-----ENDCERTIFICATE-----", "");
            byte[] derformated = Base64.decode(base64.getBytes());
            File targetFile = new File(outputFileName);
            OutputStream outStream = new FileOutputStream(targetFile);
            outStream.write(derformated);
            outStream.flush();
            outStream.close();
            return "Certificate exported successfully as DER " + targetFile;
        } catch (IOException ex) {
            Logger.getLogger(ExportManager.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate export failed.";
        }
    }

    public String exportKey(Integer idKey, String outputFileName) {
        try {
            InputStream is = CryptoDAO.getKeyFromDB(idKey);
            byte[] buffer = new byte[is.available()];
            is.read(buffer);
            File targetFile = new File(outputFileName);
            OutputStream outStream = new FileOutputStream(targetFile);
            outStream.write(buffer);
            outStream.flush();
            outStream.close();
            return "Key exported successfully as " + targetFile;
        } catch (IOException ex) {
            Logger.getLogger(ExportManager.class.getName()).log(Level.SEVERE, null, ex);
            return "Key export failed.";
        }
    }

    public String exportKeyAsDER(Integer idKey, String outputFileName) {
        try {
            InputStream is = CryptoDAO.getKeyFromDB(idKey);
            byte[] buffer = new byte[is.available()];
            is.read(buffer);
            String pemFormated = new String(buffer);
            String base64 = pemFormated.replaceAll("\\s", "");
            base64 = base64.replace("-----BEGINPRIVATEKEY-----", "");
            base64 = base64.replace("-----ENDPRIVATEKEY-----", "");
            base64 = base64.replace("-----BEGINPUBLICKEY-----", "");
            base64 = base64.replace("-----ENDPUBLICKEY-----", "");
            byte[] derformated = Base64.decode(base64.getBytes());
            File targetFile = new File(outputFileName);
            OutputStream outStream = new FileOutputStream(targetFile);
            outStream.write(derformated);
            outStream.flush();
            outStream.close();
            return "Key exported successfully as " + targetFile;
        } catch (IOException ex) {
            Logger.getLogger(ExportManager.class.getName()).log(Level.SEVERE, null, ex);
            return "Key export failed.";
        }
    }
}