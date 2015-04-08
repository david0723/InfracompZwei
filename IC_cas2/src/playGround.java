import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;


public class playGround 
{

	public static void main(String args[]) throws IOException
	{

//		Cliente cliente = new Cliente("localhost", 80);
//		cliente.init();
//		try 
//		{
//			cliente.enviarCertificado();
//		} 
//		catch (CertificateEncodingException e) {e.printStackTrace();}
//		catch (InvalidKeyException e)          {e.printStackTrace();} 
//		catch (NoSuchAlgorithmException e)     {e.printStackTrace();}
//		catch (NoSuchProviderException e)      {e.printStackTrace();}
//		catch (SignatureException e)           {e.printStackTrace();}
//
//			

			Cliente client = new Cliente();
			
			try 
			{
				client.alles("localhost", 80);
			} 
			catch (CertificateEncodingException e) {e.printStackTrace();}
			catch (InvalidKeyException          e) {e.printStackTrace();} 
			catch (NoSuchAlgorithmException     e) {e.printStackTrace();}
			catch (NoSuchProviderException      e) {e.printStackTrace();}
			catch (SignatureException           e) {e.printStackTrace();}



	}
	

}
