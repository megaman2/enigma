/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.database;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.hsqldb.cmdline.SqlFile;
import org.hsqldb.cmdline.SqlToolError;

/**
 *
 * @author Ender
 */
public class HSQLLoader {

    private Connection connexion;
    private String databaseName = "enigma-database";

    public HSQLLoader() {
        loadConnection();
    }
public Connection getConnection (){
    return connexion;
}
    public void closeConnexion() {
        try {
            connexion.close();
        } catch (SQLException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public int runUpdate(String update) throws SQLException {
        if (connexion == null) {
            loadConnection();
        }
        Statement statement = connexion.createStatement();
        int set = statement.executeUpdate(update);
        statement.close();
        return set;
    }

    public ResultSet runQuery(String query) throws SQLException {
        if (connexion == null) {
            loadConnection();
        }
        Statement statement = connexion.createStatement();
        ResultSet set = set = statement.executeQuery(query);
        statement.close();
        return set;
    }
//
//    public static void main(String[] args) {
//        HSQLLoader ldd = new HSQLLoader();
//        try {
//            ResultSet f = ldd.runQuery("select * from certificates");
//            while (f.next()) {
//                System.out.println("org.caulfield.enigma.database.HSQLLoader.main()" + f.getInt("ID_CERT") + f.getString("CN"));
//            }
//            ldd.closeConnexion();
//        } catch (SQLException ex) {
//            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
//            ldd.closeConnexion();
//        }
//
////        fz = ldd.runUpdate("CREATE TABLE Kappa (colonne1 INT , colonne2 INT)");
//    }

    private boolean baseDoesNotExist() {
        boolean exists = true;
        try {
            ResultSet f = runQuery("select * from CERTIFICATES");
            if (f.next()) {
               
                exists = false;
            }
        } catch (SQLException ex) {
            System.out.println("Base " + databaseName + " does not exist : building a fresh one ...");
        }
        return exists;
    }

    private void loadConnection() {
        try {
            Class.forName("org.hsqldb.jdbcDriver").newInstance();
            connexion = DriverManager.getConnection("jdbc:hsqldb:file:" + databaseName, "sa", "");
            if (baseDoesNotExist()) {
                initDatabase();
            }
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void initDatabase() {
        try {
            InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("enigma.sql");
            if (inputStream == null) {
                System.out.println("org.caulfield.enigma.database.HSQLLoader.initDatabase() reinstall Enigma - base corrupted");
            }
            SqlFile sqlFile = new SqlFile(new InputStreamReader(inputStream), "init", System.out, "UTF-8", false, new File("build"));
            sqlFile.setConnection(connexion);
            sqlFile.execute();
            sqlFile.closeReader();
        } catch (IOException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SqlToolError ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("Base already exists !");
        }
        int inset = 0;
        try {
        //    CREATE TABLE CERTIFICATES (ID_CERT INTEGER PRIMARY KEY, CERTNAME VARCHAR(200),CN VARCHAR(200),ALGO VARCHAR(64),KEYFILE BLOB,SHA256  VARCHAR(256),THUMBPRINT  VARCHAR(256),ID_ISSUER_CERT INTEGER);
            inset = runUpdate("INSERT INTO CERTIFICATES VALUES (1,'DefaultKey','CN=AC LOCALE DE " + System.getProperty("user.name") + ",O=LOCAL','RSA',null,'','',0)");
        } catch (SQLException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (inset == 0) {
            System.out.println("org.caulfield.enigma.database.HSQLLoader.initDatabase() INSERTS OK");
        }
        System.out.println("Build successful !");

    }
//
//    private static void runScript(String scriptPath, Connection conn, String password)
//            throws org.hsqldb.cmdline.SqlTool.SqlToolException, IOException, SQLException {
//        String urlId = "whatever";
//
//        File tempRcFile = File.createTempFile("tempRc", ".rc");
//        tempRcFile.deleteOnExit();
//        PrintWriter pw = new PrintWriter(tempRcFile);
//        pw.printf("urlid %s%n", urlId);
//        pw.printf("url %s%n", conn.getMetaData().getURL());
//        pw.printf("username %s%n", conn.getMetaData().getUserName());
//        pw.printf("password %s%n", password);
//        pw.close();
//
//        String[] args = new String[4];
//        args[0] = "--autoCommit";
//        args[1] = String.format("--rcFile=%s", tempRcFile.getAbsolutePath());
//        args[2] = urlId;
//        args[3] = scriptPath;
//        org.hsqldb.cmdline.SqlTool.objectMain(args);
//    }
}
