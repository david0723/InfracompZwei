import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import com.google.common.base.Strings;


public class Cliente 
{
	private final static String ALGORITMO_A="RSA";
	private final static String ALGORITMO_S="AES";
	private final static String ALGORITMO_D="HMACSHA256";
	private KeyPair keyPair;
	private BufferedReader br;
	private PrintWriter out;
	
	public Cliente (String xHost, int xPort) throws UnknownHostException, IOException
	{
		final String host = xHost;
		final int portNumber = xPort;
		System.out.println("Creating socket to '" + host + "' on port " + portNumber);


			Socket socket = new Socket(host, portNumber);
			br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(socket.getOutputStream(), true);
	}
	public void init() throws IOException
	{
		System.out.println("client: HOLA");
		out.println("HOLA");
		System.out.println("server:" + br.readLine());
		System.out.println("client:"+"ALGORITMOS:"+ALGORITMO_S+":"+ALGORITMO_A+":"+ALGORITMO_D);
		out.println("ALGORITMOS:"+ALGORITMO_S+":"+ALGORITMO_A+":"+ALGORITMO_D);
		System.out.println("server:" + br.readLine());
		
	}

	public void enviarCertificado() throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException
	{
		out.println("CERTCLNT");
		java.security.cert.X509Certificate cert = generateSelfSignedX509Certificate();
		byte[] mybyte = cert.getEncoded();
		out.println(mybyte);
		out.flush();
System.out.println("esperar 1");
			System.out.println("server says:" + br.readLine());
			System.out.println("esperar 2");
		
	}
	public byte[] cifrar() 
	{
		try 
		{
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO_A);
			generator.initialize(1024);
			keyPair = generator.generateKeyPair();
			Cipher cipher = Cipher.getInstance(ALGORITMO_A);
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			String pwd = stdIn.readLine();
			byte [] clearText = pwd.getBytes();
			String s1 = new String (clearText);
			System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
			long startTime = System.nanoTime();
			byte [] cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			System.out.println("clave cifrada: " + cipheredText);
			System.out.println("Tiempo asimetrico: " + (endTime - startTime));
			return cipheredText;
		}
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	public byte[] calcular() 
	{
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO_A);
			generator.initialize(1024);
			keyPair = generator.generateKeyPair();
			PrivateKey priv = keyPair.getPrivate();
			PublicKey pub = keyPair.getPublic();
			System.out.println(pub);
			Signature firma = Signature.getInstance(priv.getAlgorithm());
			firma.initSign(priv);
			FileInputStream arch = new FileInputStream("");
			BufferedInputStream bufin = new BufferedInputStream(arch);
			byte [] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) 
			{
				len = bufin.read(buffer);
				firma.update(buffer,0,len);
			}
			bufin.close();
			byte [] signature = firma.sign();
			String s1 = new String(signature);
			System.out.println("Firma: " + s1);
			return signature;
		}
		catch (Exception e)
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
    static {
        // adds the Bouncy castle provider to java security
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * <p>
     * Generate a self signed X509 certificate .
     * </p>
     * <p>
     * TODO : do the same with
     * {@link org.bouncycastle.cert.X509v1CertificateBuilder} instead of the
     * deprecated {@link org.bouncycastle.x509.X509V1CertificateGenerator}.
     * </p>
     */
    @SuppressWarnings("deprecation")
    static X509Certificate generateSelfSignedX509Certificate() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException,
            SignatureException, InvalidKeyException, IOException {

        // yesterday
        Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        // in 2 years
        Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);

        // GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024, new SecureRandom());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // GENERATE THE X509 CERTIFICATE
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        X500Principal dnName = new X500Principal("CN=John Doe");

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName); // use the same
        certGen.setNotBefore(validityBeginDate);
        certGen.setNotAfter(validityEndDate);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSA");
 

        X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");

//        // DUMP CERTIFICATE AND KEY PAIR
//        System.out.println(Strings.repeat("=", 80));
//        System.out.println("CERTIFICATE TO_STRING");
//        System.out.println(Strings.repeat("=", 80));
//        System.out.println();
//        System.out.println(cert);
//        System.out.println();
//
//        System.out.println(Strings.repeat("=", 80));
//        System.out.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");
//        System.out.println(Strings.repeat("=", 80));
//        System.out.println();
//        PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
//        pemWriter.writeObject(cert);
//        pemWriter.flush();
//        System.out.println();
//
//        System.out.println(Strings.repeat("=", 80));
//        System.out.println("PRIVATE KEY PEM (to store in a priv-johndoe.pem file)");
//        System.out.println(Strings.repeat("=", 80));
//        System.out.println();
//        pemWriter.writeObject(keyPair.getPrivate());
//        pemWriter.flush();
//        pemWriter.close();
//        System.out.println();
        
        return cert;
    }

}
