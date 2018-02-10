import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import com.sun.crypto.provider.SunJCE;

/*
*	SendEncryptedComms
*	Instantiated by Server and Client
*	or any class whicn requires the ability to send
*	a byte array through a socket output stream.
*/
public class SendEncryptedComms implements Runnable {

	/*
	*	Init vars
	*	The socket object which binds a port for IP/UDP comms
	*/
	private Socket socket = null;
	private DataOutputStream writer = null;
	private byte[] cleartext;
	private byte[] ciphertext;
	private byte[] fingerprint;
	private String message;
	private Cipher encryptionCipher;
	private boolean sendFingerprintFirst;
	/*
	*	Set the socket object to the socket parameter which
	*	had been passed in likely by a Server or Client object.
	*	Both the Server and Client utilise regular Socket objects (not ServerSocket's)
	*/
	public SendEncryptedComms( Socket socket, Cipher encryptionCipher, boolean sendFingerprintFirst) {
		this.socket = socket;
		this.encryptionCipher = encryptionCipher;
		this.sendFingerprintFirst = sendFingerprintFirst;
	}

	/*
	*	Here we create a writer to send bytes to the output socket
	* 	and a reader to get user input from the terminal.
	*/
	@Override
	public void run() {

		try {

			BufferedReader userInput = new BufferedReader( new InputStreamReader( System.in ) );
			writer = new DataOutputStream( socket.getOutputStream() );

			while( true ) {
				//Read the user input
				message = userInput.readLine();
				//Convert the user input into a byte array
				cleartext = message.getBytes();
				//encrypt the cleatext into a ciphertext using a passrf in cipher
				ciphertext = encryptionCipher.doFinal(cleartext);
				
				//If we're sending a fingerprint, we send that ahead of the message
				if( sendFingerprintFirst ) {

					//First send an encrypted hashed version of the plaintext
					//HashByteArray.sendHash( HashByteArray.hashString( message ), socket, encryptionCipher );
					HashByteArray.sendHash( cleartext, socket, encryptionCipher );

					//THen send the ciphertext, the receivier will decypt the ciphertext
					//then hash it and make sure the hash values match up
					writer.writeInt( ciphertext.length );
					writer.write( ciphertext );
				}
				else {
					//Write the length of the byte array to the stream
					writer.writeInt( ciphertext.length );
					//Write the actual byte message to the byte stream
					writer.write(ciphertext);	
				}
			}

		} catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}
	}

}