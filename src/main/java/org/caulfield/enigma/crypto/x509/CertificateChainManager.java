/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.x509;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.caulfield.enigma.crypto.CryptoGenerator;
import org.caulfield.enigma.crypto.EnigmaException;
import org.caulfield.enigma.crypto.hash.HashCalculator;
import org.caulfield.enigma.database.CryptoDAO;
import org.caulfield.enigma.database.HSQLLoader;
import org.caulfield.enigma.export.ExportManager;

/**
 *
 * @author Ender
 */
public class CertificateChainManager {

    public Iterable<String> getFullACList() {
        return new ArrayList<String>();
    }

    public String matchKeysAndCerts() {
        return "";
    }

    public String buildIntermediateCertificate(Integer idParentCert, String subject, String caPKPassword) {
        InputStream caCertIS = CryptoDAO.getCertFromDB(idParentCert);
        CryptoGenerator cg = new CryptoGenerator();
        X509Certificate caCert = cg.getCertificate(caCertIS);
        HSQLLoader sql = new HSQLLoader();

        try {
            X509CertificateHolder caCertHolder = new JcaX509CertificateHolder(caCert);

            ResultSet set = sql.runQuery("select ALGO,ID_PRIVATEKEY, CERTNAME from CERTIFICATES WHERE ID_CERT=" + idParentCert);
            if (set.next()) {
                String algo = set.getString("ALGO");
                String certName = set.getString("CERTNAME");
                Integer associatedPK = set.getInt("ID_PRIVATEKEY");
                InputStream caPKIS = CryptoDAO.getKeyFromDB(associatedPK);
                PrivateKey caPK = cg.getPrivateKey(caPKIS, caPKPassword);
                String pkAlgo = caPK.getAlgorithm();
                AsymmetricCipherKeyPair kp = CryptoGenerator.createKeyPair(pkAlgo);
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate());
                PrivateKey intermediatePK = new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic());
                PublicKey intermediatePubK = new JcaPEMKeyConverter().getPublicKey(publicKeyInfo);
                X509CertificateHolder cert = PKCS12Builder.createIntermediateCert(intermediatePubK, caPK, caCertHolder, subject, algo);
                InputStream pkStream = new ByteArrayInputStream(intermediatePK.getEncoded());
                InputStream pubkStream = new ByteArrayInputStream(intermediatePubK.getEncoded());
                HashCalculator hc = new HashCalculator();
                long privKeyID = CryptoDAO.insertKeyInDB(pkStream, "SUB_" + certName + "_private", algo, hc.getStringChecksum(pkStream, HashCalculator.SHA256), 0, true);
                long pubKeyID = CryptoDAO.insertKeyInDB(pubkStream, "SUB_" + certName + "_public", algo, hc.getStringChecksum(pkStream, HashCalculator.SHA256), (int) (long) privKeyID, false);
                System.out.println("org.caulfield.enigma.crypto.x509.CertificateChainManager.buildIntermediateCertificate()" + privKeyID);
                System.out.println("org.caulfield.enigma.crypto.x509.CertificateChainManager.buildIntermediateCertificate()" + pubKeyID);

//                ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                Writer osWriter = new OutputStreamWriter(baos);
                StringWriter sw = new StringWriter();
                JcaPEMWriter writer = new JcaPEMWriter(sw);
                JcaPEMWriter publicPemWriter = new JcaPEMWriter(writer);
                publicPemWriter.writeObject(cert);
                publicPemWriter.flush();
                publicPemWriter.close();
                InputStream certStream = new ByteArrayInputStream(sw.toString().getBytes(StandardCharsets.UTF_8.name()));
                InputStream certStream2 = new ByteArrayInputStream(sw.toString().getBytes(StandardCharsets.UTF_8.name()));
//                System.out.println("READING CERT STREAM");
//                final BufferedReader reader = new BufferedReader(new InputStreamReader(certStream));
//                String line = null;
//                while ((line = reader.readLine()) != null) {
//                    System.out.println(line);
//                }
//                reader.close();
//                InputStream certStream = new ByteArrayInputStream(baos.toByteArray());
                System.out.println("org.caulfield.enigma.crypto.x509.CertificateChainManager.buildIntermediateCertificate()" + sw.toString());
                String thumbPrint = hc.getThumbprint(cert.getEncoded());

                long certID = CryptoDAO.insertCertInDB(certStream, "SUB_" + certName, subject, hc.getStringChecksum(certStream2, HashCalculator.SHA256), algo, (int) (long) privKeyID, thumbPrint, idParentCert);
                return "SUB_" + certName + " created along with keys " + privKeyID + " and " + pubKeyID + ".";
            } else {
                return "CA Cert not found";
            }

        } catch (SQLException ex) {
            Logger.getLogger(CertificateChainManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateEncodingException | EnigmaException ex) {
            Logger.getLogger(CertificateChainManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(CertificateChainManager.class.getName()).log(Level.SEVERE, null, ex);
        }

        return "";
    }
}
