/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.database.algo;

/**
 *
 * @author Ender
 */
public enum AlgoEnum {
    ALIAS("Alg.Alias."),
    CIPHER("Cipher."),
    KEYAGREEMENT("KeyAgreement."),
    MAC("Mac."),
    MESSAGEDIGEST("MessageDigest."),
    SIGNATURE("Signature."),
    KEYPAIRGENERATOR("KeyPairGenerator."),
    KEYFACTORY("KeyFactory."),
    KEYGENERATOR("KeyGenerator.");

    private String name = "";

    AlgoEnum(String name) {
        this.name = name;
    }

    public String toString() {
        return name;
    }

}
