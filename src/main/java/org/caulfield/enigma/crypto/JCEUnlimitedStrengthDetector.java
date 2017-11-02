/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto;

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;

/**
 *
 * @author pbakhtiari
 */
public class JCEUnlimitedStrengthDetector {
    public static boolean isJCEUnlimited(){
        try{
            int length=Cipher.getMaxAllowedKeyLength("AES");
            boolean unlimited = (length==Integer.MAX_VALUE);
            return unlimited;
        }catch(NoSuchAlgorithmException ex){
            
            
        }
        return false;
    }
}
