package org.caulfield.enigma.crypto;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.CertificationRequest;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
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
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
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
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.caulfield.enigma.crypto.hash.HashCalculator;
import org.caulfield.enigma.crypto.x509.CRLManager;
import org.caulfield.enigma.crypto.x509.reader.PrivateKeyReader;
import org.caulfield.enigma.database.CryptoDAO;
import org.caulfield.enigma.database.HSQLLoader;
import org.caulfield.enigma.stream.StreamManager;

public class CryptoGenerator {

    public static AsymmetricCipherKeyPair createRSAKey(int size, String publicExponent, int certainty) {
        RSAKeyPairGenerator g = new RSAKeyPairGenerator();
        g.init(new RSAKeyGenerationParameters(new BigInteger(publicExponent),
                new SecureRandom(), size, certainty));
        return g.generateKeyPair();
    }

    public static AsymmetricCipherKeyPair createKeyPair(String algo) {
        if ("RSA".equals(algo)) {
            return createRSAKey(2048, "65537", 8);
        } else if ("DSA".equals(algo)) {
            return createDSAKey(2048, "65537", 8);
        }
        return null;
    }

    public static AsymmetricCipherKeyPair createDSAKey(int size, String publicExponent, int certainty) {
        DSAKeyPairGenerator g = new DSAKeyPairGenerator();
        DSAParametersGenerator dpg = new DSAParametersGenerator();
        dpg.init(size, certainty, new SecureRandom());
        DSAParameters params = dpg.generateParameters();
        g.init(new DSAKeyGenerationParameters(new SecureRandom(), params));
        return g.generateKeyPair();
    }

    /**
     * Generate a random EC (Elliptic Curve) random 192-bit key pair (equivalent
     * to 1536-bit RSA) based on NIST and SECG, using Bc (Bouncy Castle) classes
     *
     * @return a pair of EC keys (AsymmetricCipherKeyPair type)
     */
    public static AsymmetricCipherKeyPair generateECKeyPair192() {
//        try {
//            ECKeyPairGenerator kpGen = new ECKeyPairGenerator();
////
////        // First, define an EC curve
////        // ECCurve.Fp(p, a, b); p = prime; a,b = constants defined in equation E: y^2=x^3+ax+b (mod p)
////        ECCurve curve = new ECCurve.Fp(new BigInteger(ECParams.P_192_R1, 16), // p 
////                new BigInteger(ECParams.A_192_R1, 16), // a
////                new BigInteger(ECParams.B_192_R1, 16));			// b
////
////        byte[] seed = Hex.decode(ECParams.SEED_192_R1);
////
////        // finally use the seed in the ECKeyGenerationParameters along with the others
////        // ECKeyGenerationParameters(ECDomainParameters(ECCurve, G, n, h),random)
////        kpGen.init(new ECKeyGenerationParameters(new ECDomainParameters(curve,
////                curve.decodePoint(Hex.decode(ECParams.G_192_R1_NCOMP)), // G		 
////                new BigInteger(ECParams.N_192_R1, 16), // n
////                new BigInteger(ECParams.H_192_R1, 16), // h 
////                seed), // seed
////                new SecureRandom()));
////ECCurve curve = new ECCurve.Fp(
////        new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
////        new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
////        new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
////ECParameterSpec ecSpec = new ECParameterSpec(
////        curve,
////        curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
////        new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
////KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
////g.initialize(ecSpec, new SecureRandom());
//////KeyPair pair = g.generateKeyPair();
////return g.generateKeyPair();
//        } catch (NoSuchAlgorithmException ex) {
//            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (NoSuchProviderException ex) {
//            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (InvalidAlgorithmParameterException ex) {
//            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
//        }
        return null;

    }

    private static final String modp2048 = ("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            + "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            + "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            + "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            + "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
            + "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
            + "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            + "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
            + "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
            + "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
            + "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF")
            .replaceAll("\\s", "");

    public void createDHKey(String directory, String filename) {
        BigInteger p = new BigInteger(modp2048, 16);
        BigInteger g = BigInteger.valueOf(2L);
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("DiffieHellman");
            gen.initialize(new DHParameterSpec(p, g));
            KeyPair keyPair = gen.genKeyPair();
            PemWriter publicPemWriter = new PemWriter(new BufferedWriter(new FileWriter(directory + filename + ".pub")));
            publicPemWriter.writeObject(new PemObject("PUBLIC KEY", keyPair.getPublic().getEncoded()));
            publicPemWriter.flush();
            publicPemWriter.close();
            PemWriter privatePemWriter = new PemWriter(new BufferedWriter(new FileWriter(directory + filename)));
            privatePemWriter.writeObject(new PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
            privatePemWriter.flush();
            privatePemWriter.close();
        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public String buildCSRfromKeyPair(String CN, String pkFileName, String pkPassword, String pubFileName, String outputFileName, String outputDirectory) {
        try {
            Integer keyId = getKeyIDFromComboBox(pkFileName);
            InputStream stream = CryptoDAO.getKeyFromDB(keyId);
            Integer pubkeyId = getKeyIDFromComboBox(pubFileName);
            InputStream streamPub = CryptoDAO.getKeyFromDB(pubkeyId);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
// Fake code simulating the copy
// You can generally do better with nio if you need...
// And please, unlike me, do something about the Exceptions :D
            byte[] buffer = new byte[1024];
            int len;
            while ((len = stream.read(buffer)) > -1) {
                baos.write(buffer, 0, len);
            }
            baos.flush();
// Open new InputStreams using the recorded bytes
// Can be repeated as many times as you wish
            InputStream is1 = new ByteArrayInputStream(baos.toByteArray());
            InputStream is2 = new ByteArrayInputStream(baos.toByteArray());

            PublicKey pubK = null;
            if ("".equals(pubFileName)) {
                pubK = buildPublicKeyFromPrivateKey(is1, pkPassword);
            } else {
                pubK = getPublicKeyV2(streamPub);
            }
            PrivateKey privK = getPrivateKey(is2, pkPassword);

            PKCS10CertificationRequest csr = createCSRfromKeyPair(CN, privK, pubK);
            final File csrFile = new File(outputDirectory + outputFileName);
            final JcaPEMWriter publicPemWriter;
            publicPemWriter = new JcaPEMWriter(new FileWriter(csrFile));
            publicPemWriter.writeObject(csr);
            publicPemWriter.flush();
            publicPemWriter.close();

        } catch (EnigmaException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "PKCS#10 generation failed : " + ex.getMsg();
        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "PKCS#10 generation failed : " + ex.getMessage();
        }
        return "PKCS#10 file " + outputFileName + " successfully generated with " + CN;
    }

    private PKCS10CertificationRequest createCSRfromKeyPair(String CN, PrivateKey privateKey, PublicKey publicKey) {

        X500Principal subject = new X500Principal(CN);

        ContentSigner signGen = null;
        try {
            signGen = new JcaContentSignerBuilder("SHA1withRSA")
                    .build(privateKey);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }

        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        PKCS10CertificationRequest csr = builder.build(signGen);
        return csr;

    }

    /**
     * Get a Private Key for the file.
     *
     * @return Private key
     * @throws IOException
     */
    public PrivateKey getPrivateKey(InputStream is, String password) throws EnigmaException {

        PrivateKey key = null;
        boolean isRSAKey = false;
        boolean isEncryptedRSAKey = false;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
// Fake code simulating the copy
// You can generally do better with nio if you need...
// And please, unlike me, do something about the Exceptions :D
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) > -1) {
                baos.write(buffer, 0, len);
            }
            baos.flush();
// Open new InputStreams using the recorded bytes
// Can be repeated as many times as you wish
            InputStream is1 = new ByteArrayInputStream(baos.toByteArray());
            InputStream is2 = new ByteArrayInputStream(baos.toByteArray());
            InputStream is3 = new ByteArrayInputStream(baos.toByteArray());

            if (!quickCheckPrivateKey(is1)) {
                throw new EnigmaException("Not a private key file.");
            } else {
                System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPrivateKey() private key file");
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(is3));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                System.out.println(line);
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
                System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPrivateKey() ENCRYPTED CASE");
                BufferedReader brs = new BufferedReader(new InputStreamReader(is2));

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
                System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPrivateKey() RSA CASE");
                BufferedReader brs = new BufferedReader(new InputStreamReader(is2));
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

//                keySpec = new PKCS8EncodedKeySpec(encoded);
//                KeyFactory kf = KeyFactory.getInstance("DSA");
//                key = kf.generatePrivate(keySpec);
//                
// strip of header, footer, newlines, whitespaces
//                String privateKeyPEM = builder.toString();
//                privateKeyPEM
//                        .replace("-----BEGIN DSA PRIVATE KEY-----", "")
//                        .replace("-----END DSA PRIVATE KEY-----", "")
//                        .replaceAll("\\s", "");
//
//                // decode to get the binary DER representation
//                byte[] privateKeyDER = Base64.decode(privateKeyPEM);
//                System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPrivateKey() " + new String(privateKeyDER));
//                Security.addProvider(new BouncyCastleProvider());
//                PemReader reader = new PemReader(new StringReader(privateKeyPEM));
//                DSAPrivateKey decoded = (DSAPrivateKey) reader.readPemObject();
//                key = decoded;
//                KeyFactory keyFactory = KeyFactory.getInstance("DSA", "BC");
//                key = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDER));
                System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPrivateKey() ENTERING PKCS8 Loader");
                // TRY RSA PKCS8
                try {
                    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
                    KeyFactory kf = KeyFactory.getInstance("RSA", "BC");

                    key = kf.generatePrivate(spec);
                } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException ex) {
                    try {
                        System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPrivateKey() GOING DEEPER DSA PKCS8 !");
                        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
                        KeyFactory kf = KeyFactory.getInstance("DSA", "BC");

                        key = kf.generatePrivate(spec);
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException xex) {
                        try {
                            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPrivateKey() STILL NOTHING GOING EC ?");
                            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
                            KeyFactory kf = KeyFactory.getInstance("EC", "BC");

                            key = kf.generatePrivate(spec);
                        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException xesx) {
                            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPrivateKey() MORE MORE");
                        }
                    }
                }

            }
        } catch (IOException ex) {
            Logger.getLogger(PrivateKeyReader.class.getName()).log(Level.SEVERE, null, ex);
        }
        return key;
    }

    public void regenerateLocalPublicKey(DSAPrivateKey privKey) {

        BigInteger x = privKey.getX();
        DSAParams params = privKey.getParams();
        BigInteger y = params.getG().modPow(x, params.getP());
        DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, params.getP(), params.getQ(), params.getG());
        PublicKey pubKey;
        try {
            KeyFactory factory = KeyFactory.getInstance("DSA", "BC");
            pubKey = factory.generatePublic(keySpec);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

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
                    Logger.getLogger(PrivateKeyReader.class
                            .getName()).log(Level.SEVERE, null, ex);

                } catch (PKCSException ex) {
                    Logger.getLogger(PrivateKeyReader.class
                            .getName()).log(Level.SEVERE, null, ex + "\n possible bad password");
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
            Logger.getLogger(PrivateKeyReader.class
                    .getName()).log(Level.SEVERE, null, ex);

        }
        return key;
    }

    private PublicKey buildPublicKeyFromPrivateKey(String filename, String privateKeyPassword) {

        PrivateKey myPrivateKey = null;
        try {
            myPrivateKey = getPrivateKey(filename, privateKeyPassword);

        } catch (EnigmaException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
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
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
        }

        return myPublicKey;
    }

    private PublicKey buildPublicKeyFromPrivateKey(InputStream filename, String privateKeyPassword) {

        PrivateKey myPrivateKey = null;
        PublicKey myPublicKey = null;
        try {
            myPrivateKey = getPrivateKey(filename, privateKeyPassword);
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.buildPublicKeyFromPrivateKey() PRIVATE IS " + myPrivateKey.getClass());

        } catch (EnigmaException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
            //return ex.getMsg();
        }
        if (myPrivateKey instanceof BCDSAPrivateKey) {
            BCDSAPrivateKey privk = (BCDSAPrivateKey) myPrivateKey;

            BigInteger X = privk.getX();
            BigInteger P = privk.getParams().getP();
            BigInteger G = privk.getParams().getG();
            BigInteger Q = privk.getParams().getQ();
            BigInteger Y = G.modPow(X, P);
            KeyFactory keyFactory = null;
            DSAPublicKeySpec publicKeySpec = new java.security.spec.DSAPublicKeySpec(Y, P, Q, G);

            try {
                keyFactory = KeyFactory.getInstance("DSA", "BC");
                myPublicKey = keyFactory.generatePublic(publicKeySpec);

            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);

            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);

            } catch (NoSuchProviderException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);
            }

        } else if (myPrivateKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey privk = (RSAPrivateCrtKey) myPrivateKey;

            KeyFactory keyFactory = null;
            RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());

            try {
                keyFactory = KeyFactory.getInstance("RSA", "BC");
                myPublicKey = keyFactory.generatePublic(publicKeySpec);

            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);

            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);

            } catch (NoSuchProviderException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);
            }

        } else if (myPrivateKey instanceof ECPrivateKey) {
            ECPrivateKey ecPriv = (ECPrivateKey) myPrivateKey;
            ECParameterSpec params = ecPriv.getParams();

            // Calculate public key Y
            ECPoint generator = params.getGenerator();
            BigInteger[] wCoords = multiplyPointA(new BigInteger[]{
                generator.getAffineX(), generator.getAffineY()},
                    ecPriv.getS(), params);
            ECPoint w = new ECPoint(wCoords[0], wCoords[1]);

            try {
                KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                myPublicKey = keyFactory.generatePublic(new ECPublicKeySpec(w, params));

            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);

            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);

            } catch (NoSuchProviderException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);
            }
        }
        if (myPublicKey == null) {
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.buildPublicKeyFromPrivateKey() EMPTY KEY");
        }
        return myPublicKey;

    }

    private static BigInteger[] multiplyPointA(BigInteger[] P, BigInteger k,
            ECParameterSpec params) {
        BigInteger[] Q = new BigInteger[]{null, null};

        for (int i = k.bitLength() - 1; i >= 0; i--) {
            Q = doublePointA(Q, params);
            if (k.testBit(i)) {
                Q = addPointsA(Q, P, params);
            }
        }

        return Q;
    }

    private static BigInteger[] addPointsA(BigInteger[] P1, BigInteger[] P2,
            ECParameterSpec params) {
        final BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();

        if (P2[0] == null || P2[1] == null) {
            return P1;
        }

        if (P1[0] == null || P1[1] == null) {
            return P2;
        }

        BigInteger d = (P2[1].subtract(P1[1])).multiply((P2[0].subtract(P1[0]))
                .modInverse(p));
        BigInteger[] R = new BigInteger[2];
        R[0] = d.pow(2).subtract(P1[0]).subtract(P2[0]).mod(p);
        R[1] = d.multiply(P1[0].subtract(R[0])).subtract(P1[1]).mod(p);

        return R;
    }

    private static BigInteger[] doublePointA(BigInteger[] P,
            ECParameterSpec params) {
        final BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();
        final BigInteger a = params.getCurve().getA();

        if (P[0] == null || P[1] == null) {
            return P;
        }

        BigInteger d = (P[0].pow(2).multiply(BigInteger.valueOf(3)).add(a)).multiply(P[1]
                .shiftLeft(1).modInverse(p));
        BigInteger[] R = new BigInteger[2];
        R[0] = d.pow(2).subtract(P[0].shiftLeft(1)).mod(p);
        R[1] = d.multiply(P[0].subtract(R[0])).subtract(P[1]).mod(p);

        return R;
    }

    private String writePublicKey(PublicKey myPublicKey, String directory, String fileOutName) {
        String retour = null;
        // Save the public key to the file system, in the webapp this should
        // get saved to some directory configurable via a properties file
        final File publicKeyFile = new File(directory + fileOutName);
        System.out.println("WRITING PUBLIC KEY TO : " + directory
                + fileOutName + " : " + myPublicKey.getAlgorithm());

//        final JcaPEMWriter publicPemWriter;
        try {
            PemWriter publicPemWriterx = new PemWriter(new BufferedWriter(new FileWriter(directory + fileOutName)));
            publicPemWriterx.writeObject(new PemObject("PUBLIC KEY", myPublicKey.getEncoded()));
            publicPemWriterx.flush();
            publicPemWriterx.close();

//            publicPemWriter = new JcaPEMWriter(new FileWriter(publicKeyFile));
//            publicPemWriter.writeObject(myPublicKey);
//            publicPemWriter.flush();
//            publicPemWriter.close();
            byte[] encoded = myPublicKey.getEncoded();
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
                    ASN1Sequence.getInstance(encoded));
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.writePublicKey()" + subjectPublicKeyInfo.parsePublicKey().toASN1Primitive().toString());
            retour = "Public key " + directory + fileOutName + " successfully created.";

        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
        }

        return retour;
    }
//That means if you take your second X.509 public key, and separate the first 32 characters:
//
//-----BEGIN PUBLIC KEY-----
//MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
//MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa
//D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw
//luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB
//o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV
//gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH
//Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB
//-----END PUBLIC KEY-----
//remove the first 32 characters, and change it to BEGIN RSA PUBLIC KEY:
//
//-----BEGIN RSA PUBLIC KEY-----
//MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa
//D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw
//luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB
//o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV
//gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH
//Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB
//-----END RSA PUBLIC KEY-----

    public Integer getKeyIDFromComboBox(String comboText) {
        return new Integer(comboText.substring(0, comboText.indexOf(".")));
    }

    public String generatePublicKeyFromPrivateKey(String privateKeyFilename, String privateKeyPassword, String targetDirectory, String fileOutName, String keyName) {
        String output = "";

        Integer idPrivateKey = getKeyIDFromComboBox(privateKeyFilename);
        // Load key from Database
        PublicKey myPublicKey = buildPublicKeyFromPrivateKey(CryptoDAO.getKeyFromDB(idPrivateKey), privateKeyPassword);
        output = writePublicKey(myPublicKey, targetDirectory, fileOutName);

        // Calculate SHA256
        HashCalculator hashc = new HashCalculator();
        String realHash = hashc.getStringChecksum(targetDirectory + fileOutName, HashCalculator.SHA256);

        // Write in Database
        try {
            File file = new File(targetDirectory + fileOutName);
            FileInputStream inputStream = new FileInputStream(file);
            CryptoDAO.insertKeyInDB(inputStream, keyName, "Inherited", realHash, idPrivateKey, false);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return output;
    }

    public static String generatePKCS12(int size, String CN, String p12Password, String keyPassword, String directory, String publicExponent, int certainty, Date expiryDate, String targetFilename, boolean writeCrtPk, String issuer) {
        String returnString = "OK";
        AsymmetricCipherKeyPair pair = createRSAKey(size, publicExponent, certainty);
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
            Date endDate = expiryDate;

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

            if (writeCrtPk) {
                // Save the private key to the file system, in the webapp this
                // should get saved to some directory configurable via a properties
                // file
                final File privateKeyFile = new File(directory + targetFilename.substring(0, targetFilename.indexOf(".")) + "key");
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
            }

            if (writeCrtPk) {
                // Save the public key to the file system, in the webapp this should
                // get saved to some directory configurable via a properties file
                final File publicKeyFile = new File(directory + targetFilename.substring(0, targetFilename.indexOf(".")) + "crt");
                final JcaPEMWriter publicPemWriter = new JcaPEMWriter(
                        new FileWriter(publicKeyFile));
                publicPemWriter.writeObject(certHolder);
                publicPemWriter.flush();
                publicPemWriter.close();
            }
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

            FileOutputStream fOut = new FileOutputStream(directory + targetFilename);

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
    public String buildPrivateKey(String directory, String privateKeyPassword, String fileOutName, int size, String publicExponent, int certainty, String algo, String keyname) {
        AsymmetricCipherKeyPair pair = null;
        PrivateKey privkey = null;
        boolean hasPassword = false;
        boolean donee = false;
        if ("RSA".equals(algo)) {
            pair = createRSAKey(size, publicExponent, certainty);
        } else if ("DSA".equals(algo)) {
            pair = createDSAKey(size, publicExponent, certainty);
        } else if ("DH".equals(algo)) {
            createDHKey(directory, fileOutName);
            donee = true;
        }
        if (!donee) {
            AsymmetricKeyParameter privateKey = pair.getPrivate();

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
                    //  privatePemWriter.writeObject(privkey);

                    JcaPKCS8Generator gen = new JcaPKCS8Generator(privkey, null);
                    PemObject obj = gen.generate();
                    privatePemWriter.writeObject(obj);
                }

                privatePemWriter.flush();
                privatePemWriter.close();
                byte[] encoded = privkey.getEncoded();
                PrivateKeyInfo info = new PrivateKeyInfo(ASN1Sequence.getInstance(encoded));
                System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.writePrivateKey()" + info.parsePrivateKey().toASN1Primitive().toString());

            } catch (IOException | OperatorCreationException ex) {
                Logger.getLogger(CryptoGenerator.class
                        .getName()).log(Level.SEVERE, null, ex);
                return "Build failed : " + ex;
            }
        }
        // Calculate SHA256
        HashCalculator hashc = new HashCalculator();
        byte[] hash = hashc.checksum(directory + fileOutName, HashCalculator.SHA256);
        String realHash = DatatypeConverter.printHexBinary(hash);
        // Write in Database
        try {
            File file = new File(directory + fileOutName);
            FileInputStream inputStream = new FileInputStream(file);
            CryptoDAO.insertKeyInDB(inputStream, keyname, algo, realHash, 0, true);
        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return algo + " Private key " + directory + fileOutName + " successfully created" + (hasPassword ? " with password " + privateKeyPassword + "." : " without password.");
    }

    public boolean quickCheckPublicKey(File publicKeyFile) throws FileNotFoundException, IOException {
        File publicFile = publicKeyFile;
        FileInputStream fis = new FileInputStream(publicFile);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        return br.readLine().contains("PUBLIC");
    }

    public boolean quickCheckPublicKey(InputStream publicKeyFile) throws FileNotFoundException, IOException {

        BufferedReader br = new BufferedReader(new InputStreamReader(publicKeyFile));

        String line = br.readLine();
        System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.quickCheckPublicKey() LINE READ " + line);
        return line.contains("PUBLIC");
    }

    public boolean quickCheckPrivateKey(File privateKeyFile) throws FileNotFoundException, IOException {
        File privateFile = privateKeyFile;
        FileInputStream fis = new FileInputStream(privateFile);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        return br.readLine().contains("PRIVATE");
    }

    public boolean quickCheckPrivateKey(InputStream privateKeyFile) throws FileNotFoundException, IOException {

        BufferedReader br = new BufferedReader(new InputStreamReader(privateKeyFile));
        return br.readLine().contains("PRIVATE");
    }

    public String generateCertificateFromPublicKeyAndPrivateKey(String CN, String pubKey, String privKey, String privPassword, String targetDirectory, String targetFilename, Date expiryDate, String algo, String certVersion, String certName) {
// TODO CHANGE ARGS FILES
        Integer pubKid = getKeyIDFromComboBox(pubKey);
        Integer privKid = getKeyIDFromComboBox(privKey);
        InputStream stPubKey = CryptoDAO.getKeyFromDB(pubKid);
        InputStream stPrivKey = CryptoDAO.getKeyFromDB(privKid);

        PrivateKey privateKey = null;
        try {
            privateKey = getPrivateKey(stPrivKey, privPassword);

        } catch (EnigmaException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
            return ex.getMsg();
        }
        PublicKey publicKey = null;
        try {
            publicKey = getPublicKeyV2(stPubKey);

        } catch (EnigmaException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
            return ex.getMsg();
        }
        try {
            byte[] encoded = publicKey.getEncoded();
            SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(
                    ASN1Sequence.getInstance(encoded));

            Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60
                    * 1000);
            Date endDate = expiryDate;
            Security.addProvider(new BouncyCastleProvider());
            ContentSigner sigGen = new JcaContentSignerBuilder(algo)
                    .setProvider("BC").build(privateKey);

            X509CertificateHolder certHolder = null;
            if ("V1".equals(certVersion)) {
                X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(new X500Name(CN), BigInteger.ONE, startDate, endDate, new X500Name(CN), publicKeyInfo);
                certHolder = v1CertGen.build(sigGen);
            } else {
                X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(new X500Name(CN), BigInteger.ONE, startDate, endDate, new X500Name(CN), publicKeyInfo);
                certHolder = v3CertGen.build(sigGen);
            }
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

            // Calculate SHA256
            HashCalculator hashc = new HashCalculator();
            String realHash = hashc.getStringChecksum(targetDirectory + targetFilename, HashCalculator.SHA256);
            String thumbPrint = hashc.getThumbprint(pubCert.getEncoded());

            // Save the certificate in DB
            long idCert = CryptoDAO.insertCertInDB(targetDirectory + targetFilename, certName, CN, realHash, algo, privKid, thumbPrint, 1, certHolder.getNotAfter(), BigInteger.ONE, BigInteger.ONE, new Date());

            // Generate the associated CRL
            CRLManager crlm = new CRLManager();
            Date CRLstartDate = new Date();
            Integer cycleId = 30;
            Date CRLendDate = new Date(CRLstartDate.getTime() + cycleId * CRLManager.DAY_IN_MS);
            X509CRLHolder crl = crlm.initializeCRL(certHolder, privateKey, "SHA512withRSA", cycleId, CRLstartDate, CRLendDate);
            InputStream crlStream = StreamManager.convertCRLToInputStream(crl);

            // Save the CRL in DB
            CryptoDAO.insertCRLInDB(crlStream, (int) idCert, cycleId, CRLstartDate, CRLendDate);

            return "Certificate successfully generated with " + pubCert.getSubjectDN().getName() + " and expiry date : " + pubCert.getNotAfter();

        } catch (OperatorCreationException | CertificateException | IOException | NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
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
                System.out.println(line);
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
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private PublicKey getPublicKeyV2(InputStream is) throws EnigmaException {
        PublicKey key = null;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
// Fake code simulating the copy
// You can generally do better with nio if you need...
// And please, unlike me, do something about the Exceptions :D
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) > -1) {
                baos.write(buffer, 0, len);
            }
            baos.flush();
// Open new InputStreams using the recorded bytes
// Can be repeated as many times as you wish
            InputStream is1 = new ByteArrayInputStream(baos.toByteArray());
            InputStream is2 = new ByteArrayInputStream(baos.toByteArray());
            InputStream is3 = new ByteArrayInputStream(baos.toByteArray());

            if (!quickCheckPublicKey(is1)) {
                throw new EnigmaException("Not a public key file.");
            }

            // We hack the key into a common Header and Footer ! 
            BufferedReader br = new BufferedReader(new InputStreamReader(is3));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                System.out.println(line);
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
            KeyFactory kf;
            try {
                System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPublicKeyV2() TRY RSA");
                kf = KeyFactory.getInstance("RSA", "BC");
                key = kf.generatePublic(spec);
            } catch (NoSuchProviderException ex) {
                try {
                    System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPublicKeyV2() TRY DSA");
                    kf = KeyFactory.getInstance("DSA", "BC");
                    key = kf.generatePublic(spec);
                } catch (NoSuchProviderException ex2) {
                    try {
                        System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPublicKeyV2() TRY EC");
                        kf = KeyFactory.getInstance("EC", "BC");
                        key = kf.generatePublic(spec);
                    } catch (NoSuchProviderException ex3) {
                        System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.getPublicKeyV2() MORE MORE");
                    }
                }
            }

            return key;

        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
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
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

//    public String signFile(String targetFile, String privateKey, String privateKeyPassword, String targetDirectory, String targetFileName, String algorithm) {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
    public static byte[] signer(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA/ISO9796-2", "BC");
        signer.initSign(key);
        signer.update(data);
        return signer.sign();
    }

    public String signFile(String targetFile, String privateKeyFilename, String privateKeyPassword, String targetDirectory, String targetFileName, String algorithm, String signerCertificate) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            Integer idPrivateKey = getKeyIDFromComboBox(privateKeyFilename);
            Integer idCert = getKeyIDFromComboBox(signerCertificate);
            InputStream is = CryptoDAO.getKeyFromDB(idPrivateKey);
            PrivateKey pk = getPrivateKey(is, privateKeyPassword);
            InputStream isc = CryptoDAO.getCertFromDB(idCert);
            Certificate certificate = getCertificate(isc);

            Path path = Paths.get(targetFile);
            byte[] data = Files.readAllBytes(path);

            X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());

            List certList = new ArrayList();
            CMSTypedData msg = new CMSProcessableByteArray(data); //Data to sign

            certList.add(certificateHolder); //Adding the X509 Certificate

            Store certs = new JcaCertStore(certList);

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            //Initializing the the BC's Signer http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html
            ContentSigner sha1Signer = new JcaContentSignerBuilder(algorithm).setProvider("BC").build(pk);

            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                            .build(sha1Signer, certificateHolder));
            //adding the certificate
            gen.addCertificates(certs);
            //Getting the signed data
            CMSSignedData sigData = gen.generate(msg, false);
            //byte[] signedDatas = sigData.getEncoded();

            //  Write the file 
            ContentInfo ci = sigData.toASN1Structure();
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.signFile()" + ci.getContent());
            final File signedFile = new File(targetDirectory + targetFileName);
            final JcaPEMWriter publicPemWriter = new JcaPEMWriter(
                    new FileWriter(signedFile));
            publicPemWriter.writeObject(ci);
            publicPemWriter.flush();
            publicPemWriter.close();
            return "File " + targetFileName + " successfuly signed.";

        } catch (FileNotFoundException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
            return "Failed to sign file " + targetFileName + " : " + ex.getMessage();

        } catch (IOException | CMSException | CertificateEncodingException | EnigmaException | OperatorCreationException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
            return "Failed to sign file " + targetFileName + " : " + ex.getMessage();
        }
    }

    public X509Certificate getCertificate(InputStream targetStream) {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate cer = (X509Certificate) cf.generateCertificate(targetStream);
            return cer;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public X509Certificate getCertificate(File cert) {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            InputStream targetStream = new FileInputStream(cert);
            X509Certificate cer = (X509Certificate) cf.generateCertificate(targetStream);
            return cer;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private Certificate getCertificate(String signerCertificate) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            Certificate cert = cf.generateCertificate(new FileInputStream(signerCertificate));
            return cert;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public String importPrivateKey(String absolutePath, String keyname) throws EnigmaException {
        PrivateKey pk = null;
        File f = new File(absolutePath);
        boolean isRSAPKCS1Key = false;
        boolean isDSAPKCS1Key = false;
        boolean isEncryptedRSAKey = false;
        PKCS8EncodedKeySpec pssk = null;
        try {
            if (!quickCheckPrivateKey(f)) {
                throw new EnigmaException(absolutePath + " is not a private key file.");
            }
            InputStream fis = new FileInputStream(f);

            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ")
                            && line.endsWith(" PRIVATE KEY-----")) {
                        inKey = true;
                        isRSAPKCS1Key = line.contains("RSA");
                        isDSAPKCS1Key = line.contains("DSA");
                        isEncryptedRSAKey = line.contains("ENCRYPTED");
                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ")
                            && line.endsWith(" PRIVATE KEY-----")) {
                        inKey = false;
                        isRSAPKCS1Key = line.contains("RSA");
                        isDSAPKCS1Key = line.contains("DSA");
                        isEncryptedRSAKey = line.contains("ENCRYPTED");
                        break;
                    }
                    builder.append(line);
                }
            }

            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            Security.addProvider(new BouncyCastleProvider());
            pssk = new PKCS8EncodedKeySpec(encoded);
            if (pssk == null) {
                throw new EnigmaException(absolutePath + " is not a valid PKCS8 private key file.");
            }
        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        }

        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("RSA", "BC");
            pk = kf.generatePrivate(pssk);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
            try {
                kf = KeyFactory.getInstance("DSA", "BC");
                pk = kf.generatePrivate(pssk);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex2) {
                try {
                    kf = KeyFactory.getInstance("EC", "BC");
                    pk = kf.generatePrivate(pssk);
                } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex3) {

                }
            }
        }
        String algo = pk.getAlgorithm();
        System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.importPrivateKey() DETECTED PK ALGO IS " + algo);

        // Calculate SHA256
        HashCalculator hashc = new HashCalculator();
        byte[] hash = hashc.checksum(absolutePath, HashCalculator.SHA256);
        String realHash = DatatypeConverter.printHexBinary(hash);
        // Write in Database

        HSQLLoader sql = new HSQLLoader();
        try {
            File file = new File(absolutePath);
            FileInputStream inputStream = new FileInputStream(file);
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO X509KEYS (ID_KEY,KEYNAME,KEYTYPE,KEYFILE,ALGO,SHA256,ID_ASSOCIATED_KEY) VALUES (NEXT VALUE FOR X509KEYS_SEQ,?,?,?,?,?,null)");
            // CREATE TABLE X509KEYS (ID_KEY INTEGER PRIMARY KEY,	KEYNAME VARCHAR(200), KEYTYPE INTEGER,KEYFILE BLOB, ALGO VARCHAR(64), SHA256  VARCHAR(256),ID_ASSOCIATED_KEY INTEGER);
            pst.setString(1, keyname);
            pst.setInt(2, 1);
            pst.setBinaryStream(3, inputStream);
            pst.setString(4, algo);
            pst.setString(5, realHash);
            pst.execute();
            pst.close();

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "Private key " + keyname + " successfully imported.";
    }

    public String importPublicKey(String pubFile, String keyname) throws EnigmaException {
        FileInputStream fis = null;
        X509EncodedKeySpec spec = null;
        PublicKey pubk = null;
        try {
            File f = new File(pubFile);
            if (!quickCheckPublicKey(f)) {
                throw new EnigmaException(pubFile + " is not a public key file.");
            }
            fis = new FileInputStream(f);

            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ")
                            && line.endsWith(" PUBLIC KEY-----")) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ")
                            && line.endsWith(" PUBLIC KEY-----")) {
                        inKey = false;
                        break;
                    }
                    builder.append(line);
                }
            }
            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            spec = new X509EncodedKeySpec(encoded);
            if (spec == null) {
                throw new EnigmaException(pubFile + " is not a valid X509 public key file.");
            }
        } catch (IOException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        String modulus = null;
        KeyFactory kf;
        Security.addProvider(new BouncyCastleProvider());
        try {
            kf = KeyFactory.getInstance("RSA", "BC");
            pubk = kf.generatePublic(spec);
            BCRSAPublicKey pub = (BCRSAPublicKey) pubk;
            modulus = pub.getModulus().toString(16);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.importPublicKey()" + ex);
            try {
                kf = KeyFactory.getInstance("DSA", "BC");
                pubk = kf.generatePublic(spec);
                BCDSAPublicKey pub = (BCDSAPublicKey) pubk;
                modulus = pub.getY().toString(16);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex2) {
                System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.importPublicKey()" + ex2);
                try {
                    kf = KeyFactory.getInstance("EC", "BC");
                    pubk = kf.generatePublic(spec);
                    BCECPublicKey pub = (BCECPublicKey) pubk;
                    modulus = pub.getW().toString();
                } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex3) {
                    System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.importPublicKey()" + ex3);
                }
            }
        }

        if (pubk == null) {
            throw new EnigmaException(pubFile + " is ruined.");
        }
        System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.importPublicKey() MODULUS IS " + modulus);
        String algo = pubk.getAlgorithm();
        System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.importPublicKey() DETECTED PUBK ALGO IS " + algo);

        // Calculate SHA256
        HashCalculator hashc = new HashCalculator();
        byte[] hash = hashc.checksum(pubFile, HashCalculator.SHA256);
        String realHash = DatatypeConverter.printHexBinary(hash);
        // Write in Database

        HSQLLoader sql = new HSQLLoader();
        try {
            File file = new File(pubFile);
            FileInputStream inputStream = new FileInputStream(file);
            PreparedStatement pst = sql.getConnection().prepareStatement("INSERT INTO X509KEYS (ID_KEY,KEYNAME,KEYTYPE,KEYFILE,ALGO,SHA256,ID_ASSOCIATED_KEY) VALUES (NEXT VALUE FOR X509KEYS_SEQ,?,?,?,?,?,null)");
            // CREATE TABLE X509KEYS (ID_KEY INTEGER PRIMARY KEY,	KEYNAME VARCHAR(200), KEYTYPE INTEGER,KEYFILE BLOB, ALGO VARCHAR(64), SHA256  VARCHAR(256),ID_ASSOCIATED_KEY INTEGER);
            pst.setString(1, keyname);
            pst.setInt(2, 2);
            pst.setBinaryStream(3, inputStream);
            pst.setString(4, algo);
            pst.setString(5, realHash);
            pst.execute();
            pst.close();

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "Public key " + keyname + " successfully imported.";
    }

    /**
     * Given a Keystore containing a private key and certificate and a Reader
     * containing a PEM-encoded Certificiate Signing Request (CSR), sign the CSR
     * with that private key and return the signed certificate as a PEM-encoded
     * PKCS#7 signedData object. The returned value can be written to a file and
     * imported into a Java KeyStore with "keytool -import -trustcacerts -alias
     * subjectalias -file file.pem"
     *
     * @param pemcsr a Reader from which will be read a PEM-encoded CSR (begins
     * "-----BEGIN NEW CERTIFICATE REQUEST-----")
     * @param validity the number of days to sign the Certificate for
     * @param keystore the KeyStore containing the CA signing key
     * @param alias the alias of the CA signing key in the KeyStore
     * @param password the password of the CA signing key in the KeyStore
     *
     * @return a String containing the PEM-encoded signed Certificate (begins
     * "-----BEGIN PKCS #7 SIGNED DATA-----")
     */
    public static String signCSR(Reader pemcsr, int validity, KeyStore keystore, String alias, char[] password) throws Exception {
        PrivateKey cakey = (PrivateKey) keystore.getKey(alias, password);
        X509Certificate cacert = (X509Certificate) keystore.getCertificate(alias);
        PEMParser reader = new PEMParser(pemcsr);
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest((CertificationRequest) reader.readObject());

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        X500Name issuer = new X500Name(cacert.getSubjectX500Principal().getName());
        BigInteger serial = new BigInteger(32, new SecureRandom());
        Date from = new Date();
        Date to = new Date(System.currentTimeMillis() + (validity * 86400000L));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, serial, from, to, csr.getSubject(), csr.getSubjectPublicKeyInfo());
        certgen.addExtension(X509Extension.basicConstraints, false, new BasicConstraints(false));
        certgen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(
                csr.getSubjectPublicKeyInfo()));
        certgen.addExtension(X509Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(new GeneralNames(new GeneralName(new X509Name(cacert.getSubjectX500Principal().getName()))), cacert.getSerialNumber()));

        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(cakey.getEncoded()));
        X509CertificateHolder holder = certgen.build(signer);
        byte[] certencoded = holder.toASN1Structure().getEncoded();

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        signer = new JcaContentSignerBuilder("SHA1withRSA").build(cakey);
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, cacert));
        generator.addCertificate(new X509CertificateHolder(certencoded));
        generator.addCertificate(new X509CertificateHolder(cacert.getEncoded()));
        CMSTypedData content = new CMSProcessableByteArray(certencoded);
        CMSSignedData signeddata = generator.generate(content, true);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("-----BEGIN PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
        out.write(Base64.encode(signeddata.getEncoded()));
        out.write("\n-----END PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
        out.close();
        return new String(out.toByteArray(), "ISO-8859-1");
    }

//    private CRL readPKCS7CRL(
//            InputStream in)
//            throws IOException, CRLException {
//        ASN1InputStream dIn = new ASN1InputStream(in, getLimit(in));
//        ASN1Sequence seq = (ASN1Sequence) dIn.readObject();
//
//        if (seq.size() > 1
//                && seq.getObjectAt(0) instanceof DERObjectIdentifier) {
//            if (seq.getObjectAt(0).equals(PKCSObjectIdentifiers.signedData)) {
//                sCrlData = new SignedData(ASN1Sequence.getInstance(
//                        (ASN1TaggedObject) seq.getObjectAt(1), true));
//
//                return new X509CRLObject(
//                        CertificateList.getInstance(
//                                sCrlData.getCRLs().getObjectAt(sCrlDataObjectCount++)));
//            }
//        }
//
//        return new X509CRLObject(
//                CertificateList.getInstance(seq));
//    }
//
//    private CRL readPEMCRL(
//            InputStream in)
//            throws IOException, CRLException {
//        ASN1Sequence seq = PEM_CRL_PARSER.readPEMObject(in);
//
//        if (seq != null) {
//            return createCRL(
//                    CertificateList.getInstance(seq));
//        }
//
//        return null;
//    }
    public X509CRLHolder getCRL(InputStream targetStream) {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
//            int nRead;
//            byte[] data = new byte[16384];
//            while ((nRead = targetStream.read(data, 0, data.length)) != -1) {
//                buffer.write(data, 0, nRead);
//            }
//            buffer.flush();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(targetStream);
            // X509CRLHolder crlHolder = (X509CRLHolder) pemObject;
            JcaX509CRLHolder holder = new JcaX509CRLHolder(crl);
//            CertificateList clist = new CertificateList(ASN1Sequence.getInstance(data));
//            X509CRLHolder crl = new X509CRLHolder(buffer.toByteArray());
            return holder;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
//(jTextFieldCipherFile.getText(), (String) jComboBoxCipherCert.getSelectedItem(),  jTextFieldCipherOutputDirectory.getText(), jTextFieldCipherOutputFilename.getText(), (String) jComboBoxAlgoCipher.getSelectedItem());

    public String cipherFile(String targetFile, String cipherCert, String targetDirectory, String outputFilename, String algorithm) {

        //     Cipher cipher = Cipher.getInstance(algoCipher, "BC");
        Security.addProvider(new BouncyCastleProvider());
        try {
            Integer idCert = getKeyIDFromComboBox(cipherCert);
            InputStream isc = CryptoDAO.getCertFromDB(idCert);
            Certificate certificate = getCertificate(isc);

            Path path = Paths.get(targetFile);
            byte[] data = Files.readAllBytes(path);

            X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());
            X509Certificate x509cert = new JcaX509CertificateConverter().getCertificate(certificateHolder);

            CMSEnvelopedDataGenerator envelopedGen = new CMSEnvelopedDataGenerator();
            envelopedGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(x509cert));
            ASN1ObjectIdentifier algo = null;
            if (algorithm.equals("AES128_CBC")) {
                algo = CMSAlgorithm.AES128_CBC;
            } else if (algorithm.equals("AES192_CBC")) {
                algo = CMSAlgorithm.AES192_CBC;
            } else if (algorithm.equals("AES256_CBC")) {
                algo = CMSAlgorithm.AES256_CBC;
            } else if (algorithm.equals("CAMELLIA128_CBC")) {
                algo = CMSAlgorithm.CAMELLIA128_CBC;
            } else if (algorithm.equals("CAMELLIA192_CBC")) {
                algo = CMSAlgorithm.CAMELLIA192_CBC;
            } else if (algorithm.equals("CAMELLIA256_CBC")) {
                algo = CMSAlgorithm.CAMELLIA256_CBC;
            } else if (algorithm.equals("CAST5_CBC")) {
                algo = CMSAlgorithm.CAST5_CBC;
            } else if (algorithm.equals("DES_CBC")) {
                algo = CMSAlgorithm.DES_CBC;
            } else if (algorithm.equals("DES_EDE3_CBC")) {
                algo = CMSAlgorithm.DES_EDE3_CBC;
            } else if (algorithm.equals("IDEA_CBC")) {
                algo = CMSAlgorithm.IDEA_CBC;
            } else if (algorithm.equals("RC2_CBC")) {
                algo = CMSAlgorithm.RC2_CBC;
            } else if (algorithm.equals("SEED_CBC")) {
                algo = CMSAlgorithm.SEED_CBC;
            }

            CMSEnvelopedData cypheredData = envelopedGen.generate(new CMSProcessableByteArray(data), new JceCMSContentEncryptorBuilder(algo).build());
            ContentInfo outDatas = cypheredData.toASN1Structure();

            final File cihperedFile = new File(targetDirectory + outputFilename);
            final JcaPEMWriter publicPemWriter = new JcaPEMWriter(
                    new FileWriter(cihperedFile));
            publicPemWriter.writeObject(outDatas);
            publicPemWriter.flush();
            publicPemWriter.close();
            System.out.println("org.caulfield.enigma.crypto.CryptoGenerator.cipherFile()" + cypheredData);

            return "File " + outputFilename + " successfuly cyphered.";

        } catch (FileNotFoundException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
            return "Failed to cypher file " + targetFile + " : " + ex.getMessage();

        } catch (IOException | CMSException | CertificateEncodingException ex) {
            Logger.getLogger(CryptoGenerator.class
                    .getName()).log(Level.SEVERE, null, ex);
            return "Failed to cypher file " + targetFile + " : " + ex.getMessage();
        } catch (CertificateException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return "Failed to cypher file " + targetFile + " : " + ex.getMessage();
        }

    }
}
