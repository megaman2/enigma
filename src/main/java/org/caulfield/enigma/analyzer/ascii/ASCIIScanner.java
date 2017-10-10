/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.analyzer.ascii;

import com.google.common.base.CharMatcher;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ender
 */
public class ASCIIScanner {

    public static boolean isFileASCII(File file) {
        byte[] encoded = null;
        try {
            encoded = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
            String datas = new String(encoded, Charset.defaultCharset());
            return CharMatcher.ASCII.matchesAllOf(datas);
        } catch (IOException ex) {
            Logger.getLogger(ASCIIScanner.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }
}
