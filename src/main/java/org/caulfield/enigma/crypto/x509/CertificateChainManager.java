/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.x509;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.caulfield.enigma.crypto.CryptoGenerator;
import org.caulfield.enigma.crypto.EnigmaException;
import org.caulfield.enigma.database.CryptoDAO;
import org.caulfield.enigma.database.HSQLLoader;

/**
 *
 * @author Ender
 */
public class CertificateChainManager {

    public Iterable<String> getFullACList() {
        return new ArrayList<String>();
    }

    public String buildIntermediateCertificate(Integer idParentCert, String subject, String caPKPassword) {
        InputStream caCertIS = CryptoDAO.getCertFromDB(idParentCert);
        CryptoGenerator cg = new CryptoGenerator();
        X509Certificate caCert = cg.getCertificate(caCertIS);
        HSQLLoader sql = new HSQLLoader();

        try {
            X509CertificateHolder caCertHolder = new JcaX509CertificateHolder(caCert);

            ResultSet set = sql.runQuery("select * from CERTIFICATES WHERE ID_CERT=" + idParentCert);
            if (set.next()) {
                String algo = set.getString("ALGO");
                Integer associatedPK = set.getInt("ID_PRIVATEKEY");
                InputStream caPKIS = CryptoDAO.getKeyFromDB(associatedPK);
                PrivateKey caPK = cg.getPrivateKey(caPKIS, caPKPassword);
                // biclef à générer pour avoir PK+PubKey à fournir lors de la création du nouveau certificat (un peu comme sur sepamail)
//                PrivateKey intermediatePK = cg.buildPrivateKey(subject, caPKPassword, algo, 0, subject, 0, algo, algo);
//                PublicKey intermediatePubK = cg.generatePublicKeyFromPrivateKey(algo, caPKPassword, algo, algo, algo);
//                PKCS12Builder.createIntermediateCert(intermediatePubK, caPK, caCertHolder, subject, algo);
// TODO generate new KeyPair with some parameters => creation popup ? heritage ?
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
