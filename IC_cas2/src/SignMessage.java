import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.*;



public class SignMessage {

    static final String KEYSTORE_FILE = "keys/certificates.p12";
    static final String KEYSTORE_INSTANCE = "PKCS12";
    static final String KEYSTORE_PWD = "test";
    static final String KEYSTORE_ALIAS = "Key1";

    public static void main(String[] args) throws Exception {

//        String text = "This is a message";
//
//        Security.addProvider(new BouncyCastleProvider());
//
//        KeyStore ks = KeyStore.getInstance(KEYSTORE_INSTANCE);
//        ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PWD.toCharArray());
//        Key key = ks.getKey(KEYSTORE_ALIAS, KEYSTORE_PWD.toCharArray());
//
//        //Sign
//        PrivateKey privKey = (PrivateKey) key;
//        Signature signature = Signature.getInstance("SHA1WithRSA", "BC");
//        signature.initSign(privKey);
//        signature.update(text.getBytes());
//
//        //Build CMS
//        X509Certificate cert = (X509Certificate) ks.getCertificate(KEYSTORE_ALIAS);
//        List certList = new ArrayList();
//        CMSTypedData msg = new CMSProcessableByteArray(signature.sign());
//        certList.add(cert);
//        Store certs = new JcaCertStore(certList);
//        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
//        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey);
//        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));
//        gen.addCertificates(certs);
//        CMSSignedData sigData = gen.generate(msg, false);
//
//        BASE64Encoder encoder = new BASE64Encoder();
//
//        String signedContent = encoder.encode((byte[]) sigData.getSignedContent().getContent());
//        System.out.println("Signed content: " + signedContent + "\n");
//
//        String envelopedData = encoder.encode(sigData.getEncoded());
//        System.out.println("Enveloped data: " + envelopedData);
    }
}