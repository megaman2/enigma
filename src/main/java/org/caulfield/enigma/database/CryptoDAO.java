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
import java.math.BigInteger;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.caulfield.enigma.crypto.CryptoGenerator;

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

    // A lancer sur tous les ROOT CERTS => créé l'arbre en dessous
    // ROOT CERT <=> ID ISSUER CERT = 0
    public static EnigmaCertificate getEnigmaCertTreeFromDB() {

        EnigmaCertificate root = new EnigmaCertificate();
        root.setCertname("GENERALROOT");
        ArrayList<EnigmaCertificate> certList = new ArrayList<>();

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
            ResultSet cert = sql.runQuery("SELECT ID_CERT FROM CERTIFICATES WHERE ID_ISSUER_CERT=0");
            while (cert.next()) {
                certList.add(getEnigmaCertFromDB(cert.getInt("ID_CERT"), root));
            }
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        root.setChilds(certList);
        return root;
    }

    // A lancer sur tous les ROOT CERTS => créé l'arbre en dessous
    // ROOT CERT <=> ID ISSUER CERT = 0
    public static EnigmaCertificate getEnigmaCertFromDB(Integer idCert, EnigmaCertificate parent) {
        EnigmaCertificate in = new EnigmaCertificate();

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
            ResultSet cert = sql.runQuery("SELECT * FROM CERTIFICATES WHERE ID_CERT=" + idCert);
            //CREATE TABLE CERTIFICATES (ID_CERT INTEGER PRIMARY KEY, CERTNAME VARCHAR(200),CN VARCHAR(200),ALGO VARCHAR(64),CERTFILE BLOB,SHA256  VARCHAR(256),THUMBPRINT  VARCHAR(256),ID_ISSUER_CERT INTEGER, ID_PRIVATEKEY INTEGER);
            if (cert.next()) {
                in.setId_cert(cert.getInt("ID_CERT"));
                in.setCertname(cert.getString("CERTNAME"));
                in.setCN(cert.getString("CN"));
                in.setAlgo(cert.getString("ALGO"));
                in.setCertfile(cert.getBinaryStream("CERTFILE"));
                in.setSHA256(cert.getString("SHA256"));
                in.setThumbprint(cert.getString("THUMBPRINT"));
                in.setId_issuer_cert(cert.getInt("ID_ISSUER_CERT"));
                in.setId_private_key(cert.getInt("ID_PRIVATEKEY"));
                in.setCerttype(cert.getInt("CERTTYPE"));
                in.setExpiryDate(cert.getDate("EXPIRYDATE"));
                in.setParent(parent);
                in.setSerial(new BigInteger(cert.getString("SERIAL")));
                in.setAcserialcursor(new BigInteger(cert.getString("ACSERIALCURSOR")));
                in.setLastcrlupdate(cert.getDate("CRLLASTUPDATE"));
            }

            // ADD CHILDS
            ResultSet childs = sql.runQuery("SELECT ID_CERT FROM CERTIFICATES WHERE ID_ISSUER_CERT=" + idCert);
            while (childs.next()) {
                in.getChilds().add(getEnigmaCertFromDB(childs.getInt("ID_CERT"), in));
            }
            System.out.println("org.caulfield.enigma.database.CryptoDAO.getCertFromDB()" + in.toString());

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);

        }
        return in;
    }

    public static InputStream getCRLwithidCACertFromDB(Integer idCACert) {
        InputStream in = null;

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
//            System.out.println("SELECT CRLFILE FROM CRLS WHERE ID_CA_CERT=" + idCACert +" AND ID_CRL = (SELECT MAX(ID_CRL) FROM CLRS WHERE ID_CA_CERT=" + idCACert+")");
            ResultSet ff = sql.runQuery("SELECT CRLFILE FROM CRLS WHERE ID_CA_CERT=" + idCACert + " AND ID_CRL = (SELECT MAX(ID_CRL) FROM CRLS WHERE ID_CA_CERT=" + idCACert + ")");

            if (ff.next()) {
                in = ff.getBinaryStream("CRLFILE");
            }
            System.out.println("org.caulfield.enigma.database.CryptoDAO.getCRLwithidCACertFromDB()" + in.toString());

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);

        }
        return in;
    }

    public static InputStream getCRLFromDB(Integer idCrl) {
        InputStream in = null;

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
//            System.out.println("SELECT CERTFILE FROM CRLS WHERE ID_CRL=" + idCrl);
            ResultSet ff = sql.runQuery("SELECT CRLFILE FROM CRLS WHERE ID_CRL=" + idCrl);

            if (ff.next()) {
                in = ff.getBinaryStream("CRLFILE");
            }
            System.out.println("org.caulfield.enigma.database.CryptoDAO.getCRLFromDB()" + in.toString());

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);

        }
        return in;
    }

    public static ArrayList<EnigmaCRL> getCRLforCertFromDB(Integer idCert) {

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        ArrayList<EnigmaCRL> enigmaCRLList = new ArrayList();
        try {
//CREATE TABLE CRLS (ID_CRL INTEGER PRIMARY KEY, CRLFILE BLOB,ID_CA_CERT INTEGER, DAYCYCLE INTEGER, STARTDATE DATE, ENDDATE DATE);
            ResultSet ff = sql.runQuery("SELECT * FROM CRLS WHERE ID_CA_CERT=" + idCert);
            while (ff.next()) {
                EnigmaCRL crl = new EnigmaCRL();
                crl.setIdcrl(ff.getInt("ID_CRL"));
                crl.setIdcacert(ff.getInt("ID_CA_CERT"));
                crl.setDayCycle(ff.getInt("DAYCYCLE"));
                crl.setStartdate(ff.getDate("STARTDATE"));
                crl.setEnddate(ff.getDate("ENDDATE"));
                enigmaCRLList.add(crl);
            }
            System.out.println("org.caulfield.enigma.database.CryptoDAO.getCRLforCertFromDB()");

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);

        }
        return enigmaCRLList;
    }

    public static InputStream getCertFromDB(Integer idCert) {
        InputStream in = null;

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
//            System.out.println("SELECT CERTFILE FROM CERTIFICATES WHERE ID_CERT=" + idCert);
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
//            System.out.println("DELETE FROM CERTIFICATES WHERE ID_CERT=" + idCert);
            int ff = sql.runUpdate("DELETE FROM CERTIFICATES WHERE ID_CERT=" + idCert);
            return "Key successfully deleted.";
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Key deletion failed.";
        }
    }

    public static long insertCRLInDB(InputStream crlFile, Integer idCCACert, Integer dayCycle, Date startDate, Date endDate) {
//CREATE TABLE CRLS (ID_CRL INTEGER PRIMARY KEY, CRLFILE BLOB,ID_CA_CERT INTEGER, DAYCYCLE INTEGER);
        HSQLLoader sql = new HSQLLoader();
        try {
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO CRLS (ID_CRL,CRLFILE,ID_CA_CERT,DAYCYCLE,STARTDATE,ENDDATE) VALUES (NEXT VALUE FOR CRLS_SEQ,?,?,?,?,?)", new String[]{"ID_CRL"});
            pst.setBinaryStream(1, crlFile);
            pst.setInt(2, idCCACert);
            pst.setInt(3, dayCycle);
            pst.setDate(4, new java.sql.Date(startDate.getTime()));
            pst.setDate(5, new java.sql.Date(endDate.getTime()));
            pst.executeUpdate();
            ResultSet rs = pst.getGeneratedKeys();
            if (rs.next()) {
                return rs.getLong(1);
            }
            pst.close();
            return 0;
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return 0;
        }
    }

    public static long insertCertInDB(String filePath, String certName, String CN, String realHash, String algo, int privKid, String thumbPrint, int certType, Date expiryDate, BigInteger serial, BigInteger acSerialCursor, Date lastCRLUpdate) {

        HSQLLoader sql = new HSQLLoader();
        try {
            File file = new File(filePath);
            FileInputStream inputStream = new FileInputStream(file);
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO CERTIFICATES (ID_CERT,CERTNAME,CN,ALGO,CERTFILE,SHA256,THUMBPRINT,ID_ISSUER_CERT,ID_PRIVATEKEY,CERTTYPE,EXPIRYDATE,SERIAL,ACSERIALCURSOR,CRLLASTUPDATE) VALUES (NEXT VALUE FOR CERTIFICATES_SEQ,?,?,?,?,?,?,?,?,?,?,?,?,?)", new String[]{"ID_CERT"});
            pst.setString(1, certName);
            pst.setString(2, CN);
            pst.setString(3, algo);
            pst.setBinaryStream(4, inputStream);
            pst.setString(5, realHash);
            pst.setString(6, thumbPrint);
            pst.setInt(7, 0);
            pst.setInt(8, privKid);
            pst.setInt(9, certType);
            pst.setDate(10, new java.sql.Date(expiryDate.getTime()));
            pst.setString(11, serial.toString());
            pst.setString(12, acSerialCursor.toString());
            pst.setDate(13, new java.sql.Date(lastCRLUpdate.getTime()));
            pst.executeUpdate();
            ResultSet rs = pst.getGeneratedKeys();
            if (rs.next()) {
                return rs.getLong(1);
            }
            pst.close();
            return 0;
        } catch (SQLException | FileNotFoundException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return 0;
        }
    }

    public static long insertKeyInDB(InputStream fileStream, String keyName, String algo, String realHash, Integer idAssociatedKey, boolean isPrivate) {

        HSQLLoader sql = new HSQLLoader();
        try {
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO X509KEYS (ID_KEY,KEYNAME,KEYTYPE,KEYFILE,ALGO,SHA256,ID_ASSOCIATED_KEY) VALUES (NEXT VALUE FOR X509KEYS_SEQ,?,?,?,?,?,?)", new String[]{"ID_KEY"});
            // CREATE TABLE X509KEYS (ID_KEY INTEGER PRIMARY KEY,	KEYNAME VARCHAR(200), KEYTYPE INTEGER,KEYFILE BLOB, ALGO VARCHAR(64), SHA256  VARCHAR(256),ID_ASSOCIATED_KEY INTEGER);
            pst.setString(1, keyName);
            pst.setInt(2, isPrivate ? 1 : 2);
            pst.setBinaryStream(3, fileStream);
            pst.setString(4, algo);
            pst.setString(5, realHash);
            pst.setInt(6, idAssociatedKey);
            pst.executeUpdate();
            ResultSet rs = pst.getGeneratedKeys();
            if (rs.next()) {
                return rs.getLong(1);
            }
            pst.close();
            return 0;
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return 0;
        }
    }

    public static String insertCertInDB(File filePath, String certName, String CN, String realHash, String algo, int privKid, String thumbPrint, int certType, Date expiryDate, BigInteger serial, BigInteger acSerialCursor, Date lastCRLUpdate) {

        HSQLLoader sql = new HSQLLoader();
        try {

            FileInputStream inputStream = new FileInputStream(filePath);
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO CERTIFICATES (ID_CERT,CERTNAME,CN,ALGO,CERTFILE,SHA256,THUMBPRINT,ID_ISSUER_CERT,ID_PRIVATEKEY,CERTTYPE,EXPIRYDATE,SERIAL,ACSERIALCURSOR,CRLLASTUPDATE) VALUES (NEXT VALUE FOR CERTIFICATES_SEQ,?,?,?,?,?,?,?,?,?,?,?,?,?)", new String[]{"ID_CERT"});
            pst.setString(1, certName);
            pst.setString(2, CN);
            pst.setString(3, algo);
            pst.setBinaryStream(4, inputStream);
            pst.setString(5, realHash);
            pst.setString(6, thumbPrint);
            pst.setInt(7, 0);
            pst.setInt(8, privKid);
            pst.setInt(9, certType);
            pst.setDate(10, new java.sql.Date(expiryDate.getTime()));
            pst.setString(11, serial.toString());
            pst.setString(12, acSerialCursor.toString());
            pst.setDate(13, new java.sql.Date(lastCRLUpdate.getTime()));
            pst.execute();
            pst.close();
            return "Certificate successfully inserted.";
        } catch (SQLException | FileNotFoundException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate insertion failed.";
        }
    }

    public static long insertCertInDB(InputStream fileStream, String certName, String CN, String realHash, String algo, Integer privKid, String thumbPrint, Integer issuerCertificateID, int certType, Date expiryDate, BigInteger serial, BigInteger acSerialCursor, Date lastCRLUpdate) {

        HSQLLoader sql = new HSQLLoader();
        try {
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO CERTIFICATES (ID_CERT,CERTNAME,CN,ALGO,CERTFILE,SHA256,THUMBPRINT,ID_ISSUER_CERT,ID_PRIVATEKEY,CERTTYPE,EXPIRYDATE,SERIAL,ACSERIALCURSOR,CRLLASTUPDATE) VALUES (NEXT VALUE FOR CERTIFICATES_SEQ,?,?,?,?,?,?,?,?,?,?,?,?,?)", new String[]{"ID_CERT"});
            pst.setString(1, certName);
            pst.setString(2, CN);
            pst.setString(3, algo);
            pst.setBinaryStream(4, fileStream);
            pst.setString(5, realHash);
            pst.setString(6, thumbPrint);
            pst.setInt(7, issuerCertificateID);
            pst.setInt(8, privKid);
            pst.setInt(9, certType);
            pst.setDate(10, new java.sql.Date(expiryDate.getTime()));
            pst.setString(11, serial.toString());
            pst.setString(12, acSerialCursor.toString());
            pst.setDate(13, new java.sql.Date(lastCRLUpdate.getTime()));
            pst.executeUpdate();
            ResultSet rs = pst.getGeneratedKeys();
            if (rs.next()) {
                return rs.getLong(1);
            }
            pst.close();
            return 0;
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return 0;
        }
    }

    public static EnigmaCertificate getEnigmaCertFromDB(String thumbPrint) {
        EnigmaCertificate in = new EnigmaCertificate();

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
            ResultSet cert = sql.runQuery("SELECT * FROM CERTIFICATES WHERE THUMBPRINT='" + thumbPrint + "'");
            //CREATE TABLE CERTIFICATES (ID_CERT INTEGER PRIMARY KEY, CERTNAME VARCHAR(200),CN VARCHAR(200),ALGO VARCHAR(64),CERTFILE BLOB,SHA256  VARCHAR(256),THUMBPRINT  VARCHAR(256),ID_ISSUER_CERT INTEGER, ID_PRIVATEKEY INTEGER);
            if (cert.next()) {
                in.setId_cert(cert.getInt("ID_CERT"));
                in.setCertname(cert.getString("CERTNAME"));
                in.setCN(cert.getString("CN"));
                in.setAlgo(cert.getString("ALGO"));
                in.setCertfile(cert.getBinaryStream("CERTFILE"));
                in.setSHA256(cert.getString("SHA256"));
                in.setThumbprint(cert.getString("THUMBPRINT"));
                in.setId_issuer_cert(cert.getInt("ID_ISSUER_CERT"));
                in.setId_private_key(cert.getInt("ID_PRIVATEKEY"));
                in.setCerttype(cert.getInt("CERTTYPE"));
                in.setExpiryDate(cert.getDate("EXPIRYDATE"));
                in.setSerial(new BigInteger(cert.getString("SERIAL")));
                in.setAcserialcursor(new BigInteger(cert.getString("ACSERIALCURSOR")));
                in.setLastcrlupdate(cert.getDate("CRLLASTUPDATE"));
            }
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return in;
    }

    public static void getIncrementACSerialCursor(String thumbPrint, BigInteger currentAcSerialCursor) {
        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        BigInteger newAcSerialCursor = currentAcSerialCursor.add(BigInteger.ONE);
        try {
            PreparedStatement pst = sql.getConnection().prepareStatement("UPDATE CERTIFICATES SET ACSERIALCURSOR=? WHERE THUMBPRINT='" + thumbPrint + "'");
            pst.setString(1, newAcSerialCursor.toString());
            pst.executeUpdate();
            pst.close();
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);

        }
    }

    public static void updateCertCRLUpdateInDB(Integer idCert) {
        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        try {
            PreparedStatement pst = sql.getConnection().prepareStatement("UPDATE CERTIFICATES SET LASTUPDATECRL=? WHERE ID_CERT = (SELECT ID_CA_CERT FROM CERTIFICATES WHERE ID_CERT = " + idCert + ")");
            pst.setDate(1, new java.sql.Date(System.currentTimeMillis()));
            pst.executeUpdate();
            pst.close();
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static EnigmaCRL getEnigmaCRLwithidCACertFromDB(Integer idCACert) {

        // Load key from Database
        HSQLLoader sql = new HSQLLoader();
        EnigmaCRL crl = new EnigmaCRL();
        try {
//CREATE TABLE CRLS (ID_CRL INTEGER PRIMARY KEY, CRLFILE BLOB,ID_CA_CERT INTEGER, DAYCYCLE INTEGER, STARTDATE DATE, ENDDATE DATE);
            ResultSet ff = sql.runQuery("SELECT * FROM CRLS WHERE ID_CA_CERT=" + idCACert + " AND ID_CRL = (SELECT MAX(ID_CRL) FROM CRLS WHERE ID_CA_CERT=" + idCACert + ")");
            if (ff.next()) {
                crl.setIdcrl(ff.getInt("ID_CRL"));
                crl.setDayCycle(ff.getInt("DAYCYCLE"));
                crl.setIdcacert(ff.getInt("ID_CA_CERT"));
                crl.setStartdate(ff.getDate("STARTDATE"));
                crl.setEnddate(ff.getDate("ENDDATE"));
            }
            System.out.println("org.caulfield.enigma.database.CryptoDAO.getEnigmaCRLwithidCACertFromDB()");

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);

        }
        return crl;
    }
}
