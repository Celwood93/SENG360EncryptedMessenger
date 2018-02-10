import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.Date;
import java.text.SimpleDateFormat;
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
*	ReceiveByteArray is threadwise class
*	which can be instantiated by Server and Client
*	or any class whicn requires the ability to receive
*	byte data through a socket input stream.
*/
public class ReceiveEncryptedComms implements Runnable {
	
	/*
	*	Init vars
	*	The socket object which binds a port for IP/UDP comms
	*/
	private Socket socket = null;
	private DataInputStream reader = null;
	private byte[] ciphertext;
	private byte[] recovered;
	private byte[] decryptedHashFingerprint;
	private byte[] finalHash;
	private byte[] encryptedHashFingerprint;
	private byte[] hashNeverTransmitted;
	private int length;
	private String s;
	private Cipher decryptionCipher;
	private Cipher encryptionCipher;
	private boolean receiveFingerprintFirst;

	/*
	*	Set the socket object to the socket parameter which
	*	had been passed in likely by a Server or Client object.
	*	Set the byte array to that which was passed in by a client or server
	*/
	public ReceiveEncryptedComms( Socket socket, Cipher decryptionCipher, Cipher encryptionCipher, boolean receiveFingerprintFirst ) {
		this.socket = socket;
		this.decryptionCipher = decryptionCipher;
		this.encryptionCipher = encryptionCipher;
		this.receiveFingerprintFirst = receiveFingerprintFirst;
	}

	/*
	*	Implement the run function required classes which implement Runnable.
	*	Here we create a reader to receive messages from the socket input stream,
	*/
	@Override
	public void run() {

		try {
			while( true ) {

				//Receive an encypted hash fingerprint
				//Decrypt the hashed fingerprint
				
				//Receive the actual message
				//Descrypt the actual message
				//Rehash the message

				//Compare the two hashes, if equal good
				//If not equal warn the user

				//Receive an encrypted hash fingerprint
				if( receiveFingerprintFirst ) {
					reader = new DataInputStream( socket.getInputStream() );
					this.length = reader.readInt();
					if( length > 0 ) {
						this.encryptedHashFingerprint = new byte[length];

						reader.readFully(encryptedHashFingerprint, 0, encryptedHashFingerprint.length);
						//Decrypt the has fingerprint
						decryptedHashFingerprint = decryptionCipher.doFinal( encryptedHashFingerprint );
						//finalHash = HashByteArray.decryptHash( decryptedHashFingerprint, decryptionCipher );

						//Receive the actual message
						this.length = reader.readInt();
						this.ciphertext = new byte[length];
						reader.readFully(ciphertext, 0, ciphertext.length);
						recovered = decryptionCipher.doFinal(ciphertext);
						s = new String( recovered );
						
						//Rehash the message
						//hashNeverTransmitted = new byte[ (HashByteArray.encryptHash( recovered, encryptionCipher )).length ];
						hashNeverTransmitted = HashByteArray.hashByteArray( recovered );

						//Compare the two results
						if( !Arrays.equals( hashNeverTransmitted, decryptedHashFingerprint ) ) {
							System.out.println("[WARNING]: Message integrity comprimised. Hash fingerprint varies.");
							System.out.println("HashNeverTransmitted: " + Arrays.toString( hashNeverTransmitted ));
							System.out.println("decryptedHashFingerprint: " + Arrays.toString( decryptedHashFingerprint ));
						}

						//Print the message anyway
						System.out.println("[" + getCurrentTimeStamp() + " Received]: " + s);
					}	
				}
				else {
					reader = new DataInputStream( socket.getInputStream() );
					this.length = reader.readInt();
					if( length > 0 ) {
						//System.out.println( "[ReceiveEncryptedComms Object] receiving byte array of size " + length + "...");
						this.ciphertext = new byte[length];
						reader.readFully(ciphertext, 0, ciphertext.length);
						recovered = decryptionCipher.doFinal(ciphertext);
						s = new String( recovered );
						System.out.println("[" + getCurrentTimeStamp() + " Received]: " + s);
					}	
				}
			}	
		} 
		catch ( EOFException e ) {
			System.out.println("Chat disconnected");
			System.exit(0);
		}
		catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}

	}

	public static String getCurrentTimeStamp() {
	    SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
	    Date now = new Date();
	    String strDate = sdf.format(now);
	    return strDate;
	}
}