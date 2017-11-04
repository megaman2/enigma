/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.database;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.caulfield.enigma.crypto.CryptoGenerator;
import org.caulfield.enigma.crypto.hash.HashCalculator;

/**
 *
 * @author Ender
 */
public class CryptoDAO {

    public static InputStream getKeyFromDB(Integer idX509Key) {
        InputStream in = null;

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
            System.out.println("SELECT KEYFILE FROM X509KEYS WHERE ID_KEY=" + idX509Key);
            ResultSet ff = sql.runQuery("SELECT KEYFILE FROM X509KEYS WHERE ID_KEY=" + idX509Key);

            if (ff.next()) {
                in = ff.getBinaryStream("KEYFILE");
            }
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getKeyFromDB()" + in.toString());

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);

        }
        return in;
    }

    public static String deleteKeyFromDB(Integer iKey) {
        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
            System.out.println("DELETE FROM X509KEYS WHERE ID_KEY=" + iKey);
            int ff = sql.runUpdate("DELETE FROM X509KEYS WHERE ID_KEY=" + iKey);
            return "Certificate successfully deleted.";
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate deletion failed.";
        }

    }

    public static InputStream getCertFromDB(Integer idCert) {
        InputStream in = null;

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
            System.out.println("SELECT CERTFILE FROM CERTIFICATES WHERE ID_CERT=" + idCert);
            ResultSet ff = sql.runQuery("SELECT CERTFILE FROM CERTIFICATES WHERE ID_CERT=" + idCert);

            if (ff.next()) {
                in = ff.getBinaryStream("CERTFILE");
            }
            System.out.println("org.caulfield.enigma.database.CryptoDAO.getCertFromDB()" + in.toString());

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);

        }
        return in;
    }

    public static String deleteCertFromDB(Integer idCert) {

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
            System.out.println("DELETE FROM CERTIFICATES WHERE ID_CERT=" + idCert);
            int ff = sql.runUpdate("DELETE FROM CERTIFICATES WHERE ID_CERT=" + idCert);
            return "Key successfully deleted.";
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Key deletion failed.";
        }
    }

    public static String insertCertInDB(String filePath, String certName, String CN, String realHash, String algo, int privKid, String thumbPrint) {

        HSQLLoader sql = new HSQLLoader();
        try {
            File file = new File(filePath);
            FileInputStream inputStream = new FileInputStream(file);
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO CERTIFICATES (ID_CERT,CERTNAME,CN,ALGO,CERTFILE,SHA256,THUMBPRINT,ID_ISSUER_CERT,ID_PRIVATEKEY) VALUES (NEXT VALUE FOR CERTIFICATES_SEQ,?,?,?,?,?,?,?,?)");
            pst.setString(1, certName);
            pst.setString(2, CN);
            pst.setString(3, algo);
            pst.setBinaryStream(4, inputStream);
            pst.setString(5, realHash);
            pst.setString(6, thumbPrint);
            pst.setInt(7, 0);
            pst.setInt(8, privKid);
            pst.execute();
            pst.close();
            return "Certificate successfully inserted.";
        } catch (SQLException | FileNotFoundException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate insertion failed.";
        }
    }

    public static String insertKeyInDB(InputStream fileStream, String keyName, String algo, String realHash, Integer idAssociatedKey, boolean isPrivate) {

        HSQLLoader sql = new HSQLLoader();
        try {
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO X509KEYS (ID_KEY,KEYNAME,KEYTYPE,KEYFILE,ALGO,SHA256,ID_ASSOCIATED_KEY) VALUES (NEXT VALUE FOR X509KEYS_SEQ,?,?,?,?,?,?)");
            // CREATE TABLE X509KEYS (ID_KEY INTEGER PRIMARY KEY,	KEYNAME VARCHAR(200), KEYTYPE INTEGER,KEYFILE BLOB, ALGO VARCHAR(64), SHA256  VARCHAR(256),ID_ASSOCIATED_KEY INTEGER);
            pst.setString(1, keyName);
            pst.setInt(2, isPrivate?1:2);
            pst.setBinaryStream(3, fileStream);
            pst.setString(4, algo);
            pst.setString(5, realHash);
            pst.setInt(6, idAssociatedKey);
            pst.execute();
            pst.close();
            return "Key successfully inserted.";
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Key insertion failed.";
        }
    }

    public static String insertCertInDB(File filePath, String certName, String CN, String realHash, String algo, int privKid, String thumbPrint) {

        HSQLLoader sql = new HSQLLoader();
        try {

            FileInputStream inputStream = new FileInputStream(filePath);
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO CERTIFICATES (ID_CERT,CERTNAME,CN,ALGO,CERTFILE,SHA256,THUMBPRINT,ID_ISSUER_CERT,ID_PRIVATEKEY) VALUES (NEXT VALUE FOR CERTIFICATES_SEQ,?,?,?,?,?,?,?,?)");
            pst.setString(1, certName);
            pst.setString(2, CN);
            pst.setString(3, algo);
            pst.setBinaryStream(4, inputStream);
            pst.setString(5, realHash);
            pst.setString(6, thumbPrint);
            pst.setInt(7, 0);
            pst.setInt(8, privKid);
            pst.execute();
            pst.close();
            return "Certificate successfully inserted.";
        } catch (SQLException | FileNotFoundException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate insertion failed.";
        }
    }

    public static String insertCertInDB(InputStream fileStream, String certName, String CN, String realHash, String algo, int privKid, String thumbPrint) {

        HSQLLoader sql = new HSQLLoader();
        try {
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO CERTIFICATES (ID_CERT,CERTNAME,CN,ALGO,CERTFILE,SHA256,THUMBPRINT,ID_ISSUER_CERT,ID_PRIVATEKEY) VALUES (NEXT VALUE FOR CERTIFICATES_SEQ,?,?,?,?,?,?,?,?)");
            pst.setString(1, certName);
            pst.setString(2, CN);
            pst.setString(3, algo);
            pst.setBinaryStream(4, fileStream);
            pst.setString(5, realHash);
            pst.setString(6, thumbPrint);
            pst.setInt(7, 0);
            pst.setInt(8, privKid);
            pst.execute();
            pst.close();
            return "Certificate successfully inserted.";
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate insertion failed.";
        }
    }

}
