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

public class SendAuthorizationRequest{

	public static boolean sendChallenge(Socket socket, Cipher cipher){
		String response = "";
		boolean invalid = true;
		try{
			PrintWriter writer = new PrintWriter( new OutputStreamWriter( socket.getOutputStream() ) );
			String challenge = "New User? (y/n)\nUserName: \n PassWord: \n(Example entry: \"y-camElwood-myPassword123\") >";
			writer.println(challenge);
			while(invalid){
				invalid = false;
				DataInputStream reader = new DataInputStream( socket.getInputStream() );
				int length = reader.readInt();
				if( length > 0 ) {
					//System.out.println( "[ReceiveEncryptedComms Object] receiving byte array of size " + length + "...");
					byte [] ciphertext = new byte[length];
					reader.readFully(ciphertext, 0, ciphertext.length);
					byte [] recovered = cipher.doFinal(ciphertext);
					response = new String( recovered );
				}else{
					invalid = true;
				}
			}

			String [] vals = response.split("\\-"); //vals[0] is which VerfiyLogin command to use. vals[1] is username. vals[2] is password
			boolean ok = false;
			if(vals[0].equals("y")){
				ok = VerifyLogin.MakeNewUser(vals[2].getBytes(), vals[1]);
			}else{
				ok = VerifyLogin.CheckPassWordHash(vals[2].getBytes(), vals[1]);
			}
			return ok;


		} catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}
		return false;



	}

}