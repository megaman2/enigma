/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.stream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;

/**
 *
 * @author pbakhtiari
 */
public class StreamManager {

    public static InputStream convertPublicKeyToInputStream(PublicKey pk) {
        InputStream keyStream = null;
        try {
            StringWriter sw = new StringWriter();
            JcaPEMWriter writer = new JcaPEMWriter(sw);
            JcaPEMWriter publicPemWriter = new JcaPEMWriter(writer);
            publicPemWriter.writeObject(pk);
            publicPemWriter.flush();
            publicPemWriter.close();
            keyStream = new ByteArrayInputStream(sw.toString().getBytes(StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                keyStream.close();
            } catch (IOException ex) {
                Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return keyStream;
    }

    public static InputStream convertPrivateKeyToInputStream(PrivateKey pk, String keyPassword) {
        InputStream keyStream = null;
        try {

            StringWriter sw = new StringWriter();
            JcaPEMWriter writer = new JcaPEMWriter(sw);
            JcaPEMWriter privatePemWriter = new JcaPEMWriter(writer);
            if (keyPassword != null) {
                JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
                        PKCS8Generator.PBE_SHA1_3DES);
                encryptorBuilder.setRandom(new SecureRandom());
                encryptorBuilder.setPasssword(keyPassword.toCharArray());
                OutputEncryptor oe = encryptorBuilder.build();
                JcaPKCS8Generator gen = new JcaPKCS8Generator(pk, oe);
                PemObject obj = gen.generate();
                privatePemWriter.writeObject(obj);
            } else {
                privatePemWriter.writeObject(pk);
            }
            privatePemWriter.flush();
            privatePemWriter.close();
            keyStream = new ByteArrayInputStream(sw.toString().getBytes(StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OperatorCreationException ex) {
            Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                keyStream.close();
            } catch (IOException ex) {
                Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return keyStream;
    }

    public static InputStream convertCertificateToInputStream(X509CertificateHolder cert) {
        InputStream certStream = null;
        try {
            StringWriter sw = new StringWriter();
            JcaPEMWriter writer = new JcaPEMWriter(sw);
            JcaPEMWriter publicPemWriter = new JcaPEMWriter(writer);
            publicPemWriter.writeObject(cert);
            publicPemWriter.flush();
            publicPemWriter.close();
            certStream = new ByteArrayInputStream(sw.toString().getBytes(StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                certStream.close();
            } catch (IOException ex) {
                Logger.getLogger(StreamManager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return certStream;
    }
}
