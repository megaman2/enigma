package org.caulfield.enigma.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.ASN1Sequence;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.caulfield.enigma.crypto.x509.PrivateKeyReader;

public class CryptoGenerator {

    private static AsymmetricCipherKeyPair CreateRSAKey(int size) {
        RSAKeyPairGenerator g = new RSAKeyPairGenerator();
        g.init(new RSAKeyGenerationParameters(new BigInteger("65537"),
                new SecureRandom(), size, 8));
        return g.generateKeyPair();
    }

    public static PKCS10CertificationRequest CreateCSRfromKeyPair(KeyPair pair) {

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        // import javax.security.auth.x500.X500Principal
        X500Principal subject = new X500Principal(
                "C=NO, ST=Trondheim, L=Trondheim, O=Senthadev, OU=Innovation, CN=www.senthadev.com, EMAILADDRESS=senthadev@gmail.com");

        // import org.bouncycastle.operator.ContentSigner
        ContentSigner signGen = null;
        try {
            signGen = new JcaContentSignerBuilder("SHA1withRSA")
                    .build(privateKey);
        } catch (OperatorCreationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // import org.bouncycastle.pkcs.PKCS10CertificationRequest;
        // import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
        // import
        // org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                subject, publicKey);
        PKCS10CertificationRequest csr = builder.build(signGen);
        return csr;

    }

    /**
     * Get a Private Key for the file.
     *
     * @return Private key
     * @throws IOException
     */
    public PrivateKey getPrivateKey(String fileName, String password) throws EnigmaException {

        PrivateKey key = null;
        FileInputStream fis = null;
        boolean isRSAKey = false;
        boolean isEncryptedRSAKey = false;
        File f = new File(fileName);

        try {
            if (!quickCheckPrivateKey(f)) {
                throw new EnigmaException(fileName + " is not a private key file.");
            }
            fis = new FileInputStream(f);

            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ")
                            && line.endsWith(" PRIVATE KEY-----")) {
                        inKey = true;
                        isRSAKey = line.contains("RSA");
                        isEncryptedRSAKey = line.contains("ENCRYPTED");
                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ")
                            && line.endsWith(" PRIVATE KEY-----")) {
                        inKey = false;
                        isRSAKey = line.contains("RSA");
                        isEncryptedRSAKey = line.contains("ENCRYPTED");
                        break;
                    }
                    builder.append(line);
                }
            }
            KeySpec keySpec = null;
            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            Security.addProvider(new BouncyCastleProvider());
            if (isEncryptedRSAKey) {
                FileInputStream fiss = null;
                File fs = new File(fileName);
                fiss = new FileInputStream(fs);

                BufferedReader brs = new BufferedReader(new InputStreamReader(fiss));

                PEMParser parser = new PEMParser(brs);
                PKCS8EncryptedPrivateKeyInfo pair = (PKCS8EncryptedPrivateKeyInfo) parser.readObject();
                JceOpenSSLPKCS8DecryptorProviderBuilder jce = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC");

                InputDecryptorProvider decProv;
                try {
                    decProv = jce.build(password.toCharArray());
                    PrivateKeyInfo info = pair.decryptPrivateKeyInfo(decProv);
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

                    key = converter.getPrivateKey(info);
                    System.out.println("org.caulfield.enigma.crypto.x509.PrivateKeyReader.getPrivateKey()" + info.parsePrivateKey().toASN1Primitive().toString());
                } catch (OperatorCreationException ex) {
                    Logger.getLogger(PrivateKeyReader.class.getName()).log(Level.SEVERE, null, ex);
                } catch (PKCSException ex) {
                    Logger.getLogger(PrivateKeyReader.class.getName()).log(Level.SEVERE, null, ex + "\n possible bad password");
                }

            } else if (isRSAKey) {
                //keySpec = getRSAKeySpec(encoded);
                FileInputStream fiss = null;
                File fs = new File(fileName);
                fiss = new FileInputStream(fs);
                BufferedReader brs = new BufferedReader(new InputStreamReader(fiss));
                PEMParser pemParser = new PEMParser(brs);
                Object object = pemParser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                KeyPair kp = null;
                PEMKeyPair ukp = (PEMKeyPair) object;
                kp = converter.getKeyPair(ukp);
                key = kp.getPrivate();
//            }

// RSA
//            ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(encoded));
//            ASN1Primitive obj = bIn.readObject();
//            System.out.println(ASN1Dump.dumpAsString(obj));
//            DLSequence app = (DLSequence) obj;
//            Enumeration secEnum = app.getObjects();
//            while (secEnum.hasMoreElements()) {
//                ASN1Primitive seqObj = (ASN1Primitive) secEnum.nextElement();
//                System.out.println(seqObj);
//            }
            } else {
                keySpec = new PKCS8EncodedKeySpec(encoded);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                key = kf.generatePrivate(keySpec);
            }

        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(PrivateKeyReader.class.getName()).log(Level.SEVERE, null, ex);

        }
        return key;
    }

    private PublicKey buildPublicKeyFromPrivateKey(String filename, String privateKeyPassword) {

        PrivateKey myPrivateKey = null;
        try {
            myPrivateKey = getPrivateKey(filename, privateKeyPassword);
        } catch (EnigmaException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            //return ex.getMsg();
        }

        RSAPrivateCrtKey privk = (RSAPrivateCrtKey) myPrivateKey;
        PublicKey myPublicKey = null;

        KeyFactory keyFactory = null;
        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());

        try {
            keyFactory = KeyFactory.getInstance("RSA");
            myPublicKey = keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return myPublicKey;
    }

    private String writePublicKey(PublicKey myPublicKey, String directory, String fileOutName) {
        String retour = null;
        // Save the public key to the file system, in the webapp this should
        // get saved to some directory configurable via a properties file
        final File publicKeyFile = new File(directory + fileOutName);
        final JcaPEMWriter publicPemWriter;
        try {
            publicPemWriter = new JcaPEMWriter(
                    new FileWriter(publicKeyFile));
            publicPemWriter.writeObject(myPublicKey);
            publicPemWriter.flush();
            publicPemWriter.close();
            byte[] encoded = myPublicKey.getEncoded();
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
                    ASN1Sequence.getInstance(encoded));
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.writePublicKey()" + subjectPublicKeyInfo.parsePublicKey().toASN1Primitive().toString());
            retour = "Public key " + directory + fileOutName + " successfully created.";
        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }

        return retour;
    }

    public String generatePublicKeyFromPrivateKey(String privateKeyFilename, String privateKeyPassword, String targetDirectory, String fileOutName) {
        PublicKey myPublicKey = buildPublicKeyFromPrivateKey(privateKeyFilename, privateKeyPassword);
        return writePublicKey(myPublicKey, targetDirectory, fileOutName);
    }

    public static String generatePKCS12(int size, String CN, String p12Password, String keyPassword, String directory) {
        String returnString = "OK";
        AsymmetricCipherKeyPair pair = CryptoGenerator.CreateRSAKey(1024);
        AsymmetricKeyParameter privateKey = pair.getPrivate();
        AsymmetricKeyParameter publicKey = pair.getPublic();

        try {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory
                    .createPrivateKeyInfo(privateKey);
            byte[] serializedPrivateBytes = privateKeyInfo.getEncoded();
            String serializedPrivate = Base64
                    .toBase64String(serializedPrivateBytes);

            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory
                    .createSubjectPublicKeyInfo(publicKey);
            byte[] serializedPublicBytes = publicKeyInfo.getEncoded();
            String serializedPublic = Base64
                    .toBase64String(serializedPublicBytes);
            System.out.println(serializedPrivate);
            System.out.println(serializedPublic);

            Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60
                    * 1000);
            Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60
                    * 60 * 1000);

            X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(
                    new X500Name(CN), BigInteger.ONE, startDate, endDate,
                    new X500Name(CN), publicKeyInfo);

            JcaPEMKeyConverter conv = new JcaPEMKeyConverter();

            PublicKey pubkey = conv.getPublicKey(publicKeyInfo);
            PrivateKey privkey = conv.getPrivateKey(privateKeyInfo);
            Security.addProvider(new BouncyCastleProvider());
            ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA")
                    .setProvider("BC").build(privkey);
            X509CertificateHolder certHolder = v1CertGen.build(sigGen);
            System.out.println(certHolder.getSubject().toString() + " - "
                    + certHolder.getNotAfter());

            // Save the private key to the file system, in the webapp this
            // should get saved to some directory configurable via a properties
            // file
            final File privateKeyFile = new File(directory + "private.key");
            final JcaPEMWriter privatePemWriter = new JcaPEMWriter(
                    new FileWriter(privateKeyFile));

            if (keyPassword != null) {
                JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
                        PKCS8Generator.PBE_SHA1_3DES);
                encryptorBuilder.setRandom(new SecureRandom());
                encryptorBuilder.setPasssword(keyPassword.toCharArray());
                OutputEncryptor oe = encryptorBuilder.build();
                JcaPKCS8Generator gen = new JcaPKCS8Generator(privkey, oe);
                PemObject obj = gen.generate();
                privatePemWriter.writeObject(obj);
            } else {
                privatePemWriter.writeObject(privkey);
            }

            privatePemWriter.flush();
            privatePemWriter.close();

            // Save the public key to the file system, in the webapp this should
            // get saved to some directory configurable via a properties file
            final File publicKeyFile = new File(directory + "public.pem");
            final JcaPEMWriter publicPemWriter = new JcaPEMWriter(
                    new FileWriter(publicKeyFile));
            publicPemWriter.writeObject(certHolder);
            publicPemWriter.flush();
            publicPemWriter.close();

            // X509Certificate[] chain = {};
            X509Certificate pubCert = new JcaX509CertificateConverter()
                    .setProvider("BC").getCertificate(certHolder);
            // PKCS12PfxPdu pfx = makePKCS12(pubCert, pubkey, privkey,
            // p12Password);

            // Save the PKCS12 to the file system, in the webapp this should
            // get saved to some directory configurable via a properties file
            // final File pkcs12File = new File("output.p12");
            // final JcaPEMWriter pkcs12PemWriter = new JcaPEMWriter(
            // new FileWriter(pkcs12File));
            // pkcs12PemWriter.writeObject(pfx);
            // pkcs12PemWriter.flush();
            // pkcs12PemWriter.close();
            Certificate[] chain = {pubCert};

            //
            // store the key and the certificate chain
            //
            KeyStore store = KeyStore.getInstance("PKCS12", "BC");

            store.load(null, null);

            //
            // if you haven't set the friendly name and local key id above
            // the name below will be the name of the key
            //
            store.setCertificateEntry("PublicCert", pubCert);
            store.setKeyEntry("PrivateKey", privkey, p12Password.toCharArray(),
                    chain);

            FileOutputStream fOut = new FileOutputStream(directory + "id.p12");

            store.store(fOut, p12Password.toCharArray());

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return returnString;
    }

    private static X509Certificate createCertificate(String dn, String issuer,
            PublicKey publicKey, PrivateKey privateKey) throws Exception {
        X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
        certGenerator.setSerialNumber(BigInteger.valueOf(Math.abs(new Random()
                .nextLong())));
        certGenerator.setIssuerDN(new X500Principal(dn));
        certGenerator.setSubjectDN(new X500Principal(dn));
        certGenerator.setIssuerDN(new X500Principal(issuer)); // Set issuer!
        certGenerator.setNotBefore(Calendar.getInstance().getTime());
        certGenerator.setNotAfter(Calendar.getInstance().getTime());
        certGenerator.setPublicKey(publicKey);
        certGenerator.setSignatureAlgorithm("SHA1withRSA");
        X509Certificate certificate = (X509Certificate) certGenerator.generate(
                privateKey, "BC");
        return certificate;
    }

    private static PKCS12PfxPdu makePKCS12(X509Certificate[] chain,
            PublicKey pubKey, PrivateKey privKey, String passwd) {
        PKCS12PfxPdu pfx = null;
        JcaX509ExtensionUtils extUtils;
        try {
            extUtils = new JcaX509ExtensionUtils();

            PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder(
                    chain[2]);

            taCertBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                    new DERBMPString("Bouncy Primary Certificate"));

            PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder(
                    chain[1]);

            caCertBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                    new DERBMPString("Bouncy Intermediate Certificate"));

            PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(
                    chain[0]);

            eeCertBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                    new DERBMPString("Eric's Key"));
            eeCertBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                    extUtils.createSubjectKeyIdentifier(pubKey));

            PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(
                    privKey,
                    new BcPKCS12PBEOutputEncryptorBuilder(
                            PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                            new CBCBlockCipher(new DESedeEngine()))
                            .build(passwd.toCharArray()));

            keyBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                    new DERBMPString("Eric's Key"));
            keyBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                    extUtils.createSubjectKeyIdentifier(pubKey));

            //
            // construct the actual key store
            //
            PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();

            PKCS12SafeBag[] certs = new PKCS12SafeBag[3];

            certs[0] = eeCertBagBuilder.build();
            certs[1] = caCertBagBuilder.build();
            certs[2] = taCertBagBuilder.build();

            pfxPduBuilder.addEncryptedData(
                    new BcPKCS12PBEOutputEncryptorBuilder(
                            PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                            new CBCBlockCipher(new RC2Engine())).build(passwd
                            .toCharArray()), certs);

            pfxPduBuilder.addData(keyBagBuilder.build());

            pfx = pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(),
                    passwd.toCharArray());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (PKCSException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        return pfx;

    }

    private static PKCS12PfxPdu makePKCS12(X509Certificate cert,
            PublicKey pubKey, PrivateKey privKey, String passwd) {
        PKCS12PfxPdu pfx = null;
        JcaX509ExtensionUtils extUtils;
        try {
            extUtils = new JcaX509ExtensionUtils();

            PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(
                    cert);

            eeCertBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                    new DERBMPString("Eric's Key"));
            eeCertBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                    extUtils.createSubjectKeyIdentifier(pubKey));

            PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(
                    privKey,
                    new BcPKCS12PBEOutputEncryptorBuilder(
                            PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                            new CBCBlockCipher(new DESedeEngine()))
                            .build(passwd.toCharArray()));

            keyBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                    new DERBMPString("Eric's Key"));
            keyBagBuilder.addBagAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                    extUtils.createSubjectKeyIdentifier(pubKey));

            //
            // construct the actual key store
            //
            PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();

            PKCS12SafeBag[] certs = new PKCS12SafeBag[1];

            certs[0] = eeCertBagBuilder.build();

            pfxPduBuilder.addEncryptedData(
                    new BcPKCS12PBEOutputEncryptorBuilder(
                            PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                            new CBCBlockCipher(new RC2Engine())).build(passwd
                            .toCharArray()), certs);

            pfxPduBuilder.addData(keyBagBuilder.build());

            pfx = pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(),
                    passwd.toCharArray());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (PKCSException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        return pfx;

    }

    public String generatePKCS10CertificateRequestString(X509Certificate cert,
            PrivateKey privateKey) throws CertificateException {
        X509CertificateHolder holder;
        try {
            holder = new JcaX509CertificateHolder(cert);
        } catch (CertificateEncodingException e) {
            throw new CertificateException("Error creating CSR", e);
        }
        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
                holder.getSubject(), holder.getSubjectPublicKeyInfo());
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(
                cert.getSigAlgOID());
        ContentSigner signer;
        try {
            signer = signerBuilder.build(privateKey);
        } catch (OperatorCreationException e) {
            throw new CertificateException("Error signing certificate request",
                    e);
        }
        PKCS10CertificationRequest csr = builder.build(signer);
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        try {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr
                    .getEncoded()));
        } catch (IOException e) {
            throw new CertificateException("Error signing certificate", e);
        } finally {
            try {
                pemWriter.flush();
                pemWriter.close();
                writer.close();
            } catch (IOException e) {
                // ignore this
            }
        }
        return writer.toString();
    }

//    public static void main(String[] args) {
//        System.out.println(generatePKCS12(1024, "CN=TEST PBA", "password",
//                "keypassword", "F:\\Certificates\\"));
//    }
    public String buildPrivateKey(String directory, String privateKeyPassword, String fileOutName) {

        AsymmetricCipherKeyPair pair = CryptoGenerator.CreateRSAKey(1024);
        AsymmetricKeyParameter privateKey = pair.getPrivate();
        PrivateKey privkey = null;
        boolean hasPassword = false;
        try {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory
                    .createPrivateKeyInfo(privateKey);
            byte[] serializedPrivateBytes = privateKeyInfo.getEncoded();
            String serializedPrivate = Base64
                    .toBase64String(serializedPrivateBytes);

            System.out.println(serializedPrivate);

            JcaPEMKeyConverter conv = new JcaPEMKeyConverter();

            privkey = conv.getPrivateKey(privateKeyInfo);
            Security.addProvider(new BouncyCastleProvider());

            final File privateKeyFile = new File(directory + fileOutName);
            final JcaPEMWriter privatePemWriter = new JcaPEMWriter(
                    new FileWriter(privateKeyFile));

            if (privateKeyPassword != null && !"".equals(privateKeyPassword)) {
                hasPassword = true;
            }
            if (hasPassword) {
                JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
                        PKCS8Generator.PBE_SHA1_3DES);
                encryptorBuilder.setRandom(new SecureRandom());
                encryptorBuilder.setPasssword(privateKeyPassword.toCharArray());
                OutputEncryptor oe = encryptorBuilder.build();
                JcaPKCS8Generator gen = new JcaPKCS8Generator(privkey, oe);
                PemObject obj = gen.generate();
                privatePemWriter.writeObject(obj);
            } else {
                privatePemWriter.writeObject(privkey);
            }

            privatePemWriter.flush();
            privatePemWriter.close();
            byte[] encoded = privkey.getEncoded();
            PrivateKeyInfo info = new PrivateKeyInfo(ASN1Sequence.getInstance(encoded));
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.writePrivateKey()" + info.parsePrivateKey().toASN1Primitive().toString());

        } catch (IOException | OperatorCreationException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Build failed : " + ex;
        }
        return "Private key " + directory + fileOutName + " successfully created" + (hasPassword ? " with password " + privateKeyPassword + "." : " without password.");
    }

    public boolean quickCheckPublicKey(File publicKeyFile) throws FileNotFoundException, IOException {
        File publicFile = publicKeyFile;
        FileInputStream fis = new FileInputStream(publicFile);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        return br.readLine().contains("PUBLIC");
    }

    public boolean quickCheckPrivateKey(File privateKeyFile) throws FileNotFoundException, IOException {
        File privateFile = privateKeyFile;
        FileInputStream fis = new FileInputStream(privateFile);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        return br.readLine().contains("PRIVATE");
    }

    public String generateCertificateFromPublicKeyAndPrivateKey(String CN, String pubFile, String privFile, String privPassword, String targetDirectory, String targetFilename, Date expiryDate) {

        PrivateKey privateKey = null;
        try {
            privateKey = getPrivateKey(privFile, privPassword);
        } catch (EnigmaException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return ex.getMsg();
        }
        PublicKey publicKey = null;
        try {
            publicKey = getPublicKeyV2(pubFile);
        } catch (EnigmaException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return ex.getMsg();
        }
        try {
            byte[] encoded = publicKey.getEncoded();
            SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(
                    ASN1Sequence.getInstance(encoded));

            Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60
                    * 1000);
            Date endDate = expiryDate;

            X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(
                    new X500Name(CN), BigInteger.ONE, startDate, endDate,
                    new X500Name(CN), publicKeyInfo);

            Security.addProvider(new BouncyCastleProvider());
            ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA")
                    .setProvider("BC").build(privateKey);
            X509CertificateHolder certHolder = v1CertGen.build(sigGen);
            System.out.println(certHolder.getSubject().toString() + " - "
                    + certHolder.getNotAfter());

            // Save the public key to the file system, in the webapp this should
            // get saved to some directory configurable via a properties file
            final File publicKeyFile = new File(targetDirectory + targetFilename);
            final JcaPEMWriter publicPemWriter = new JcaPEMWriter(
                    new FileWriter(publicKeyFile));
            publicPemWriter.writeObject(certHolder);
            publicPemWriter.flush();
            publicPemWriter.close();

            X509Certificate pubCert = new JcaX509CertificateConverter()
                    .setProvider("BC").getCertificate(certHolder);
            return "Certificate successfully generated with " + pubCert.getSubjectDN().getName() + " and expiry date : " + pubCert.getNotAfter();
        } catch (OperatorCreationException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate generation failed : " + ex;
        } catch (CertificateException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate generation failed : " + ex;
        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate generation failed : " + ex;
        }
    }

    private PublicKey getPublicKeyV2(String pubFile) throws EnigmaException {

        try {

            FileInputStream fis = null;
            File f = new File(pubFile);
            if (!quickCheckPublicKey(f)) {
                throw new EnigmaException(pubFile + " is not a public key file.");
            }
            fis = new FileInputStream(f);

            // We hack the key into a common Header and Footer ! 
            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ")
                            && line.endsWith(" PUBLIC KEY-----")) {
                        inKey = true;
                        //builder.append(line);
                        //builder.append("-----BEGIN RSA PUBLIC KEY-----\n");
                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ")
                            && line.endsWith(" PUBLIC KEY-----")) {
                        inKey = false;
                        //builder.append("\n-----END RSA PUBLIC KEY-----");
                        //  builder.append(line);
                        break;
                    }
                    builder.append(line);
                }
            }

            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            X509EncodedKeySpec spec
                    = new X509EncodedKeySpec(encoded);
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPublicKeyV2() : " + builder.toString());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            
             
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
                    ASN1Sequence.getInstance(encoded));
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPublicKeyV2()" + subjectPublicKeyInfo.parsePublicKey().toASN1Primitive().toString());
            
            return kf.generatePublic(spec);

        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private PublicKey getPublicKey(String pubFile) {
// meh
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(pubFile));
            X509EncodedKeySpec spec
                    = new X509EncodedKeySpec(keyBytes);

            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);

        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
