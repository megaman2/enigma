/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.analyzer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.caulfield.enigma.crypto.pgp.PGPManager;
import org.caulfield.enigma.crypto.x509.X509Manager;

/**
 *
 * @author Ender
 */
public class FileAnalyzer {

    private List<String> results;

    public FileAnalyzer(String file) {
        results = new ArrayList<String>();
        File f = new File(file);
        results.add("Starting analysis of " + f.getName() + "...");
        results.add("File type : " + identifyFileTypeUsingFilesProbeContentType(f));
        results.add("PGP detection : " + tryPGP(f));
        results.add("X509 detection : " + tryX509(f));
    }

    /**
     * @return the results
     */
    public List<String> getResults() {
        return results;
    }

    /**
     * @param results the results to set
     */
    public void setResults(List<String> results) {
        this.results = results;
    }

    private String identifyFileTypeUsingFilesProbeContentType(final File file) {
        String fileType = "Undetermined";
        try {
            fileType = Files.probeContentType(file.toPath());
        } catch (IOException ioException) {

        }
        return fileType;
    }

    private String tryPGP(final File file) {

        boolean b = false;
        try {
            InputStream ff = new FileInputStream(file);

            PGPManager pgpm = new PGPManager();
            b = pgpm.detectPGP(ff);
        } catch (NoSuchProviderException | SignatureException | PGPException ex) {
            Logger.getLogger(FileAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ioException) {
            Logger.getLogger(FileAnalyzer.class.getName()).log(Level.SEVERE, null, ioException);
        }
        return (b ? "PGP file detected !" : "not a PGP file");
    }

    private String tryX509(final File file) {
        String output = null;
        X509Manager xmng = new X509Manager();
        
        // Tries
        String tryResult = xmng.detectPrivateKey(file);
        if (!tryResult.contains("detected")) {
            tryResult = xmng.detectPublicKey(file);
        }
        return output;

    }
}
