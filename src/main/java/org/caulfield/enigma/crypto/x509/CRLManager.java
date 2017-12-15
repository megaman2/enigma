/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.crypto.x509;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.caulfield.enigma.crypto.CryptoGenerator;
import org.caulfield.enigma.crypto.EnigmaException;
import org.caulfield.enigma.database.CryptoDAO;
import org.caulfield.enigma.database.EnigmaCRL;
import org.caulfield.enigma.database.EnigmaCertificate;
import org.caulfield.enigma.stream.StreamManager;

/**
 *
 * @author pbakhtiari
 */
public class CRLManager {

    public static final long MIN_IN_MS = 60L * 1000;
    public static final long DAY_IN_MS = 24L * 60 * MIN_IN_MS;

    public String revokeCert(Integer idCert, String password) {
        try {
            EnigmaCertificate certEnigma = CryptoDAO.getEnigmaCertFromDB(idCert, null);
            BigInteger certSerial = certEnigma.getSerial();
            InputStream caCertStream = CryptoDAO.getCertFromDB(certEnigma.getId_issuer_cert());
            EnigmaCertificate caCertEnigma = CryptoDAO.getEnigmaCertFromDB(certEnigma.getId_issuer_cert(), null);
            CryptoGenerator cg = new CryptoGenerator();
            X509Certificate caCert = cg.getCertificate(caCertStream);
            X509CertificateHolder caCertHolder = new JcaX509CertificateHolder(caCert);
            Integer idCAPk = caCertEnigma.getId_private_key();
            InputStream caPKstream = CryptoDAO.getKeyFromDB(idCAPk);
            PrivateKey caPK = cg.getPrivateKey(caPKstream, password);
            String sigAlgo = null;
            InputStream tempo = CryptoDAO.getCRLwithidCACertFromDB(certEnigma.getId_issuer_cert());
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = tempo.read(buffer)) > -1) {
                baos.write(buffer, 0, len);
            }
            baos.flush();
//            System.out.println("org.caulfield.enigma.crypto.x509.CRLManager.revokeCert()" + baos.toString());
            System.out.println("org.caulfield.enigma.crypto.x509.CRLManager.revokeCert()"+ baos.toString().replace("-----BEGIN X509 CRL-----", "").replace("-----END X509 CRL-----", ""));
            InputStream currentCRLstream = new ByteArrayInputStream(baos.toString().replace("-----BEGIN X509 CRL-----", "").replace("-----END X509 CRL-----", "").getBytes(StandardCharsets.UTF_8.name()));
// Open new InputStreams using the recorded bytes
// Can be repeated as many times as you wish
//            InputStream currentCRLstream = new ByteArrayInputStream(baos.toByteArray());
            EnigmaCRL crlEnigma = CryptoDAO.getEnigmaCRLwithidCACertFromDB(caCertEnigma.getId_cert());
            X509CRLHolder currentCRL = cg.getCRL(currentCRLstream);
            X509CRLHolder newCRL = getCurrentCRL(caCertHolder, caPK, sigAlgo, certSerial, currentCRL, crlEnigma.getDayCycle());
            InputStream newCRLStream = StreamManager.convertCRLToInputStream(newCRL);
            // Save CRL 
            Date CRLstartDate = new Date();
            Integer cycleId = crlEnigma.getDayCycle();
            Date CRLendDate = new Date(CRLstartDate.getTime() + cycleId * CRLManager.DAY_IN_MS);
            CryptoDAO.insertCRLInDB(newCRLStream, certEnigma.getId_issuer_cert(), crlEnigma.getDayCycle(), CRLstartDate, CRLendDate);
            // Update last CRL update Date
            CryptoDAO.updateACSerialCursorAndDate(caCertEnigma.getId_cert(),caCertEnigma.getAcserialcursor().add(BigInteger.ONE));
            return "Certificate revoked successfully. New CRL created for " + caCertEnigma.getCertname() + ".";
        } catch (CertificateEncodingException | EnigmaException ex) {
            Logger.getLogger(CRLManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CRLManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    // Transaction Level
    public synchronized X509CRLHolder createCRLandInsertSerial(Integer idCACert, BigInteger certSerial, String password, Integer dayCycle) {
        try {
            InputStream caCertStream = CryptoDAO.getCertFromDB(idCACert);
            CryptoGenerator cg = new CryptoGenerator();
            X509Certificate caCert = cg.getCertificate(caCertStream);
            X509CertificateHolder caCertHolder = new JcaX509CertificateHolder(caCert);
            EnigmaCertificate caCertEnigma = CryptoDAO.getEnigmaCertFromDB(idCACert, null);

            Integer idCAPk = caCertEnigma.getId_private_key();
            InputStream caPKstream = CryptoDAO.getKeyFromDB(idCAPk);
            PrivateKey caPK = cg.getPrivateKey(caPKstream, password);
            String sigAlgo = null;
            InputStream currentCRLstream = CryptoDAO.getCRLwithidCACertFromDB(idCACert);
            X509CRLHolder currentCRL = cg.getCRL(currentCRLstream);
            X509CRLHolder newCRL = getCurrentCRL(caCertHolder, caPK, sigAlgo, certSerial, currentCRL, dayCycle);
            return newCRL;
        } catch (EnigmaException ex) {
            Logger.getLogger(CRLManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(CRLManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(CRLManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    // X509 Level
    public synchronized X509CRLHolder initializeCRL(X509CertificateHolder cACert, PrivateKey cAKey, String signatureAlgorithm, Integer dayCycle, Date startDate, Date endDate) {

        try {

            Date thisUpdate = new Date();
            X500Name cASubject = cACert.getSubject();
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(cASubject, thisUpdate);
            Date nextUpdate = new Date(thisUpdate.getTime() + dayCycle * DAY_IN_MS);
            crlBuilder.setNextUpdate(nextUpdate);
            // Fill the CRL entries
            crlBuilder.addExtension(Extension.cRLNumber, false, new ASN1Integer(1));
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(cAKey);
            X509CRLHolder _crl = crlBuilder.build(contentSigner);
            return _crl;
        } catch (CertIOException | OperatorCreationException ex) {
            Logger.getLogger(CRLManager.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    // X509 Level
    public synchronized X509CRLHolder getCurrentCRL(X509CertificateHolder cACert, PrivateKey cAKey, String signatureAlgorithm, final BigInteger serialNumber, X509CRLHolder currentCRL, Integer dayCycle) {
        try {

            Date thisUpdate = new Date();
            X500Name cASubject = cACert.getSubject();
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(cASubject, thisUpdate);
            Date nextUpdate = new Date(thisUpdate.getTime() + dayCycle * DAY_IN_MS);
            crlBuilder.setNextUpdate(nextUpdate);
            Date cAStartTime = cACert.getNotBefore();
            Date revocationTime = new Date(cAStartTime.getTime() + 1);
            if (revocationTime.after(thisUpdate)) {
                revocationTime = cAStartTime;
            }
            // Fill the CRL entries
            crlBuilder.addCRL(currentCRL);
            ASN1Integer currentCRLcursor = (ASN1Integer) currentCRL.getExtension(Extension.cRLNumber).getParsedValue();
            AtomicLong atoCursor = new AtomicLong(currentCRLcursor.getValue().longValue());
            crlBuilder.addCRLEntry(serialNumber, revocationTime, CRLReason.keyCompromise);
            crlBuilder.addExtension(Extension.cRLNumber, false, new ASN1Integer(atoCursor.getAndAdd(1)));
            //String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(cAKey, HashAlgoType.SHA256);
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(cAKey);
            X509CRLHolder _crl = crlBuilder.build(contentSigner);
            return _crl;
        } catch (CertIOException | OperatorCreationException ex) {
            Logger.getLogger(CRLManager.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public boolean isRevoked(X509Certificate certificate, PrivateKey privateKey) {
        try {
            X500Name issuer = X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded());

            X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, new Date());

            builder.addCRLEntry(certificate.getSerialNumber(), new Date(), CRLReason.cACompromise);

            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");

            contentSignerBuilder.setProvider("BC");

            X509CRLHolder cRLHolder = builder.build(contentSignerBuilder.build(privateKey));

            if (!cRLHolder.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(certificate))) {
                // fail("CRL signature not valid");
            }

            X509CRLEntryHolder cRLEntryHolder = cRLHolder.getRevokedCertificate(certificate.getSerialNumber());

            if (!cRLEntryHolder.getCertificateIssuer().equals(new GeneralNames(new GeneralName(cRLHolder.getIssuer())))) {
                //    fail("certificate issuer incorrect");
            }

            JcaX509CRLConverter converter = new JcaX509CRLConverter();
            converter.setProvider("BC");

            X509CRL crl = converter.getCRL(cRLHolder);
            crl.verify(certificate.getPublicKey());

            if (!crl.isRevoked(certificate)) {
                // fail("Certificate should be revoked");
            }

            // now encode the CRL and load the CRL with the JCE provider
            CertificateFactory fac = CertificateFactory.getInstance("X.509");

            X509CRL jceCRL = (X509CRL) fac.generateCRL(new ByteArrayInputStream(crl.getEncoded()));

            jceCRL.verify(certificate.getPublicKey());

            return jceCRL.isRevoked(certificate);

        } catch (OperatorCreationException | CertException | CRLException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | CertificateException ex) {
            Logger.getLogger(CRLManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public X509CRL updateCRL() {
        return null;
//        X509V2CRLGenerator crlGen = new X509V2CRLGenerator();
//        Date nextUpdate = ...;
//X509Certificate caCrlCert = ...;
//PrivateKey caCrlPrivateKey = ...;
//X509CRL existingCRL = ...
// 
// 
//crlGen.setIssuerDN(new X500Principal("CN=Test CA"));
//
//        crlGen.setThisUpdate(now);
//        crlGen.setNextUpdate(nextUpdate);
//        crlGen.setSignatureAlgorithm(signatureAlgorithm);
//        crlGen.addCRL(existingCRL);
//
//        crlGen.addCRLEntry(BigInteger.valueOf(2), now, CRLReason.privilegeWithdrawn);
//
//        crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier,
//                false, new AuthorityKeyIdentifierStructure(caCrlCert));
//        crlGen.addExtension(X509Extensions.CRLNumber,
//                false, new CRLNumber(crlNumber));
//
//        X509CRL crl = crlGen.generateX509CRL(pair.getPrivate(), "BC");
    }
}
