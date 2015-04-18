
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.PrintStream;
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
import org.bouncycastle.x509.X509V1CertificateGenerator;



public class Cliente 
{
	private final static String ALGORITMO_A="RSA";
	private final static String ALGORITMO_S="AES";
	private final static String ALGORITMO_D="HMACMD5";
	private KeyPair keyPair;
	private BufferedReader br;
	private PrintWriter out;
	private InputStreamReader in;
	private OutputStream raus;
	private Socket socket;
	
	public Cliente (String xHost, int xPort) throws UnknownHostException, IOException
	{
		final String host = xHost;
		final int portNumber = xPort;
		System.out.println("Creating socket to '" + host + "' on port " + portNumber);


			socket = new Socket(host, portNumber);
			
			br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(socket.getOutputStream(), true);

	}
	public Cliente ()
	{


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
		System.out.println("CERTCLNT");
		
		java.security.cert.X509Certificate cert = generateSelfSignedX509Certificate();
		byte[] mybyte = cert.getEncoded();
		raus = socket.getOutputStream();
		raus.write(mybyte);
		raus.flush();
		
		System.out.println("server says:" + br.readLine());
		
	}
	public void alles(String xHost, int xPort) throws UnknownHostException, IOException, CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException
	{
		final String host = xHost;
		final int portNumber = xPort;
		System.out.println("Creating socket to '" + host + "' on port " + portNumber);


			socket = new Socket(host, portNumber);
			System.out.println("Conectado a: "+socket.getRemoteSocketAddress());
			PrintStream p = new PrintStream(socket.getOutputStream());
			
			br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			
			InputStream input = socket.getInputStream();
//			out = new PrintWriter(socket.getOutputStream(), true);
			
			System.out.println("client: HOLA");
			p.println("HOLA");
			
			System.out.println("server:" + br.readLine());
			System.out.println("client:"+"ALGORITMOS:"+ALGORITMO_S+":"+ALGORITMO_A+":"+ALGORITMO_D);
			
			p.println("ALGORITMOS:"+ALGORITMO_S+":"+ALGORITMO_A+":"+ALGORITMO_D);
			
			System.out.println("server:" + br.readLine());
			
			p.println("CERCLNT");
			System.out.println("client: CERTCLNT");
			
			java.security.cert.X509Certificate cert = generateSelfSignedX509Certificate();
			byte[] mybyte = cert.getEncoded();
			p.write(mybyte);
			p.flush();
			
			byte[] certi = new byte[2000];
			input.read(certi, 0, certi.length);
			
//			try
//			{
//				X509Certificate c = X509Certificate.getInstance(certi);   
//				c.checkValidity();
//				PublicKey pKey = c.getPublicKey();
//			} 
//
//			catch (Exception e)
//			{
//				e.printStackTrace();
//			}

//			byte[] certServidor = new byte[1500];
//			int k = 0;
//			boolean termino = false;
//			
//			while (!termino)
//			{
//				System.out.println("while");
//				String line = br.readLine();
//				System.out.println(line);
//				
//				byte[] by = line.getBytes();
//				
//				
//				for (int i = 0; i<by.length; i++)
//				{
//
//					certServidor[k]= by[i];
//					k++;
//				}
//				System.out.println(k);
//				if(k>1024)
//				{
//					termino = true;
//				}
//				
//			}
//			System.out.println("while OUT");
//			byte[] certificado = new byte[1024];
//			byte[] rest = new byte[k-1024];
//			for (int i = 0; i<k; i++)
//			{
//				if (i<1024)
//				{
//					certificado[i]= certServidor[i];
//				}
//				else
//				{
//					rest[i-1024] = certServidor[i];
//				}
//
//			}
//
//			InputStream ins = new ByteArrayInputStream(certificado);
//			System.out.println("Tamano del certificado: "+certificado.length);
//			X509Certificate certificadoServ=null;
//			try 
//			{
//				CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
//				certificadoServ = (X509Certificate)certFactory.generateCertificate(ins);
//			} 
//			catch (CertificateException e) 
//			{
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//			
			
//			ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(certificado));
//			X509Certificate certificadoServ= cert;
//			try 
//			{
//				certificadoServ = (X509Certificate) stream.readObject();
//			}
//			catch (ClassNotFoundException e1) {e1.printStackTrace();}
//			stream.close();

//	        // DUMP CERTIFICATE AND KEY PAIR
//	        System.out.println(Strings.repeat("=", 80));
//	        System.out.println("CERTIFICATE TO_STRING");
//	        System.out.println(Strings.repeat("=", 80));
//	        System.out.println();
//	        System.out.println(certificadoServ);
//	        System.out.println();
//	
//	        System.out.println(Strings.repeat("=", 80));
//	        System.out.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");
//	        System.out.println(Strings.repeat("=", 80));
//	        System.out.println();
//	        PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
//	        pemWriter.writeObject(certificadoServ);
//	        pemWriter.flush();
//	        System.out.println();
	
//	        System.out.println(Strings.repeat("=", 80));
//	        System.out.println("PRIVATE KEY PEM (to store in a priv-johndoe.pem file)");
//	        System.out.println(Strings.repeat("=", 80));
//	        System.out.println();
//	        pemWriter.writeObject(keyPair.getPrivate());
//	        pemWriter.flush();
			

	}

    /**
     * <p>
     * Generate a self signed X509 certificate .
     * </p>
     * <p>
     * 
     * {@link org.bouncycastle.cert.X509v1CertificateBuilder} instead of the
     * deprecated {@link org.bouncycastle.x509.X509V1CertificateGenerator}.
     * </p>
     */
    public X509Certificate generateSelfSignedX509Certificate() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException,
            SignatureException, InvalidKeyException, IOException {
    	
    	Security.addProvider(new BouncyCastleProvider());

        // yesterday
        Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        // in 2 years
        Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);
        
     // GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024, new SecureRandom());

        keyPair = keyPairGenerator.generateKeyPair();
        

        // GENERATE THE X509 CERTIFICATE
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        X500Principal dnName = new X500Principal("CN=Cliente");

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName); // use the same
        certGen.setNotBefore(validityBeginDate);
        certGen.setNotAfter(validityEndDate);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("MD5WITHRSAENCRYPTION");
        
        X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
        
        return cert;
        
 

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
        
 
    }
    public void descifrar(byte[] cipheredText) 
    {
    	System.out.println("descifrar");
    	try 
    	{
    		Cipher cipher = Cipher.getInstance(ALGORITMO_A);
    		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    		byte [] clearText = cipher.doFinal(cipheredText);
    		String s3 = new String(clearText);
    		System.out.println("clave original: " + s3);
    	}
    	catch (Exception e) 
    	{
    		System.out.println("Excepcion: " + e.getMessage());
    	}
    }
    public Object deserialize(byte[] data) throws IOException, ClassNotFoundException
    {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        return is.readObject();
    }
    
    public void extract(BufferedReader b) throws IOException
    {
    	byte[] certServidor = new byte[1500];
		int k = 0;
		boolean termino = false;
		
		while (!termino)
		{
			System.out.println("while");
			String line = br.readLine();
			System.out.println(line);
			
			byte[] by = line.getBytes();
			
			
			for (int i = 0; i<by.length; i++)
			{

				certServidor[k]= by[i];
				k++;
			}
			System.out.println(k);
			if(k>1024)
			{
				termino = true;
			}
		}
    }
    
    public static int convert(int n) {
    	  return Integer.valueOf(String.valueOf(n), 16);
    	}

}
