import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;


public class playGround 
{

	public static void main(String args[]) throws IOException
	{
		final String host = "localhost";
		final int portNumber = 80;
		System.out.println("Creating socket to '" + host + "' on port " + portNumber);

		while (true) 
		{
			Socket socket = new Socket(host, portNumber);
			BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

			

			out.println("HOLA");
			System.out.println("server says:" + br.readLine());


		}
	}
}
