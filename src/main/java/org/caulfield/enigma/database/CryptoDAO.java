/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.database;

import java.io.InputStream;
import java.sql.ResultSet;
import java.sql.SQLException;
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
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        }
        return in;
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
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        }
        return in;
    }
}
