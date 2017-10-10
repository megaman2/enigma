/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.analyzer;

import eu.medsea.mimeutil.MimeUtil;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.caulfield.enigma.analyzer.ascii.ASCIIScanner;
import org.caulfield.enigma.crypto.pgp.PGPManager;
import org.caulfield.enigma.crypto.x509.X509Manager;

/**
 *
 * @author Ender
 */
public class FileAnalyzer {

    private List<String> results;

    public FileAnalyzer(String file) {
        results = new ArrayList<>();
        long startTime = System.nanoTime();
        File f = new File(file);
        results.add("------------------------------------");
        results.add("Starting analysis of " + f.getName() + "...");
        results.add("Java File Type Detection : " + identifyFileTypeUsingFilesProbeContentType(f));
        results.add("MIME Cache Magic Detection : " + identifyFileMIMETypeUsingMimeCache(f));
        results.add("ASCII / Binary Detection : " + identifyFileFormatUsingGuava(f));
        results.add("PGP detection : " + tryPGP(f));
        results.add("X509 detection : " + tryX509(f));
        long endTime = System.nanoTime();
        results.add("Analysis completed in " + (endTime - startTime) / 1000000 + " ms.");
        results.add("------------------------------------");
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

    private String identifyFileFormatUsingGuava(File file) {
        if (ASCIIScanner.isFileASCII(file)) {
            return "ASCII file.";
        } else {
            return "BINARY file.";
        }
    }

    private String identifyFileTypeUsingFilesProbeContentType(File file) {
        String fileType = null;
        try {
            fileType = Files.probeContentType(file.toPath());
        } catch (IOException ex) {
            Logger.getLogger(FileAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (fileType == null) {
            fileType = "No match.";
        }
        return fileType;
    }

    private String identifyFileMIMETypeUsingMimeCache(File file) {
        MimeUtil.registerMimeDetector("eu.medsea.mimeutil.detector.MagicMimeMimeDetector");
        Collection<?> mimeTypes = MimeUtil.getMimeTypes(file);
        String mimeType = MimeUtil.getFirstMimeType(mimeTypes.toString()).toString();
        String subMimeType = MimeUtil.getSubType(mimeTypes.toString());
        return mimeTypes + ", " + mimeType + ", " + subMimeType;
    }

    private String tryPGP(File file) {

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
        return (b ? "PGP file detected !" : "Not a PGP file");
    }

    private String tryX509(File file) {

        X509Manager xmng = new X509Manager();
        Scenario scenario = new Scenario();
        scenario.addStep(X509Manager.class, xmng, file, "detectPrivateKey");
        scenario.addStep(X509Manager.class, xmng, file, "detectPublicKey");
        scenario.addStep(X509Manager.class, xmng, file, "detectCSR");
        scenario.addStep(X509Manager.class, xmng, file, "detectCertificate");
        scenario.addStep(X509Manager.class, xmng, file, "detectPKCS7");
        scenario.addStep(X509Manager.class, xmng, file, "detectPKCS12");
        String tryResult = "";
        while (scenario.hasNextStep() && !tryResult.contains("detected")) {
            tryResult += ((String) scenario.runNextStep()) + " > ";
        }
        return tryResult.substring(0, tryResult.length() - 3);

    }
}
