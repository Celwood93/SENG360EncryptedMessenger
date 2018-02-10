import java.util.*;
import java.lang.*;
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import com.sun.crypto.provider.SunJCE;

public class RecieveAuthorizationRequest{



	public static void recieveChallenge(Cipher cipher, Socket socket){
		try{
			BufferedReader reader = new BufferedReader( new InputStreamReader( socket.getInputStream() ) );
			String challenge = reader.readLine();
			System.out.println(challenge);
			boolean check = true;
			String response = "";
			while(check){
				check = false;
				Scanner console = new Scanner(System.in);
				response = console.nextLine();
				if(!response.matches("[y/n]\\-\\w+\\-.+")){
					System.out.println("Please enter with the correct format\n\n");
					System.out.println(challenge);
					check = true;
				}
			}

			byte [] input = response.getBytes();
			HashByteArray.sendNotHash(input, socket, cipher);
		}catch(Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}
	}	

}
