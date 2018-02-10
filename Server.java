import java.io.*;
import java.util.*;
import java.net.*;
import java.lang.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import com.sun.crypto.provider.SunJCE;

public class Server {

	private static final int port = 4444;

	private static byte[] clientEncodedPublicKey;
	private static byte[] clientCipherParameters;
	private static byte[] serverSharedSecret;

	private static String paramString = "...";
	private static boolean encrypt_chat = false;
	private static boolean veryify_message_integrity = false;
	private static boolean use_password_authentication = false;

	public static void main( String[] args ) throws Exception {

		
		//Establish sockets for initial chat comms
		System.out.println("[SERVER] Generating serverSocket and clientSocket...");
		ServerSocket serverSocket = new ServerSocket(port);
		Socket clientSocket = serverSocket.accept();


		/* We must first ask the Server what kind of parameters it would like to run
		*  1) Confidentiality: Encrypted chat messages (AES encryption)
		*  2) Integrity: Verifying that the messages received have not been altered (Checksum)
		*  3) Authentication: Both the Client and Server enter have a username and password
		*/
		checkUserChoices();

		//Only if the user choices match do we initiate a session
		if( verifyChatParametersMatch( clientSocket ) ) {
			




			/*	KEYGEN
			*	Here we attempt to create secure communications with the
			*	Java Crypto Architecture example Appendix D:
			*	https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#AppD
			*/
			//Step 1: Server first generates a keypair
			System.out.println("[SERVER] Generating keypair...");
			KeyPairGenerator serverKeypairGen = KeyPairGenerator.getInstance("DH");
	        serverKeypairGen.initialize(2048);
			KeyPair serverKeypair = serverKeypairGen.generateKeyPair();

			//Step 2: Server generates and initializes a KeyAgreement object
			System.out.println("[SERVER] Generating and initializing a KeyAgreement object...");
			KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
	        serverKeyAgree.init(serverKeypair.getPrivate());

			//Step 3: Encode the public key from the keypair
			System.out.println("[SERVER] Generating and initializing a KeyAgreement object...");
			byte[] serversEncodedPublicKey = serverKeypair.getPublic().getEncoded();
			//encodePublicKey( serverKeypair );

			//Step 4: Server sends the ENCODED PUBLIC KEY to the Client with a SendByteArray object
			System.out.println("[SERVER] sends the ENCODED PUBLIC KEY to the Client with a SendByteArray object...");
			SendByteArray sendByteArray = new SendByteArray( clientSocket, serversEncodedPublicKey );
			sendByteArray.run();

			//Step 5: Client now has the encoded public key byte array (see client code for step 5)
			//We wait for the client to generate it's own public key and send it back to server

			//Step 6 - 11 (See Client code)

			//Step 12: Receive encoded PUBLIC KEY from Client...
			System.out.println("[SERVER] Receiveing encoded PUBLIC KEY from Client...");
			ReceiveByteArray receiveByteArray = new ReceiveByteArray( clientSocket );
			receiveByteArray.run();
			clientEncodedPublicKey = new byte[ receiveByteArray.getIncomingByteArraySize() ];
			clientEncodedPublicKey = receiveByteArray.getByteArray();

			//Step 13:
	        //Server uses client's public key for the first (and only) phase
	        //of it's version of the DH protocol. Before it can do so, it
	        //has to instantiate a DH public key from client's encoded key material.
	        KeyFactory serverKeyFactory = KeyFactory.getInstance("DH");
	        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientEncodedPublicKey);
	        PublicKey clientPublicKey = serverKeyFactory.generatePublic(x509KeySpec);
	        System.out.println("[SERVER]: Execute PHASE1 ...");
	        //Note here this means that TRUE means this is the last key agreement phase to be executed
	        serverKeyAgree.doPhase(clientPublicKey, true);
	        System.out.println("[SERVER]: ServerPublicKey AGREES with ClientPublicKey ...");

	        //GENERATE AES KEY
	        serverSharedSecret = serverKeyAgree.generateSecret();
	        System.out.println("[SERVER]: Using shared secret as SecretKey object...");
	        SecretKeySpec serverAesKey = new SecretKeySpec(serverSharedSecret, 0, 16, "AES");

			/*ENCRYPTED COMMUNICATIONS
			*/
	        //TODO: What follows next is just a test....
	        //EVENTUALLY we need to make these steps into a realtime back-and-forth chat.
	        //If the user of the program decides they wish for encrypted chat streams:
	        //	1) Generate SecretKeys for the AES Algorithm with the raw shared secret data
	        //	2) Encrypt a plaintext message using AES/CipherBlockChaining, generating a ciphertext
	        //	3) Encode the parameters based on the ciphertext and TRANSMIT those to the server
	        //	4) TRANSMIT the ciphertext byte array to the server
	        //	5) Now the server has the ciphertext parameters AND the byte array ciphertext
	        //	6) Alice uses the parameters to decrypt the ciphertext into plaintext

	        //RECEIVE CIPHER-PARAMETERS FROM CLIENT
	        System.out.println("[SERVER]: Attempting to receive CIPHER-PARAMETERS from Client...");
	        receiveByteArray = new ReceiveByteArray( clientSocket );
			receiveByteArray.run();
			clientCipherParameters = Arrays.copyOf( receiveByteArray.getByteArray(), receiveByteArray.getIncomingByteArraySize() );


			//SERVER instantiates AlgorithmParameters object from parameter encoding obtained from Client
			AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
	        aesParams.init(clientCipherParameters);
	        Cipher serverDecryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        Cipher serverEncryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        serverEncryptionCipher.init(Cipher.ENCRYPT_MODE, serverAesKey, aesParams);
	        serverDecryptionCipher.init(Cipher.DECRYPT_MODE, serverAesKey, aesParams);
	        /*END KEYGEN SECTION*/







	        /*  ENCRYPTED CHAT
	        *   If the encryption handshake was successful we begin comms with the server
	        */
	        if(use_password_authentication){
	        	System.out.println("[SERVER] past if\n");
	        	boolean which = SendAuthorizationRequest.sendChallenge(clientSocket, serverEncryptionCipher);
	        	if(!which){
	        		System.out.println("[SERVER] Authorization failed, client is not trustworthy\n");
	        	}else{
	        		System.out.println("[SERVER] Authorization passed, client is trustworthy\n");
	        	}
	        	RecieveAuthorizationRequest.recieveChallenge(serverEncryptionCipher, clientSocket);
	        }

	        if( encrypt_chat && veryify_message_integrity) {
		        System.out.println("[SERVER] Beginning ENCRYPTED comms with Client, message INTEGRITY being checked...");
		        ReceiveEncryptedComms encryptedReceive = new ReceiveEncryptedComms( clientSocket, serverDecryptionCipher, serverEncryptionCipher, true );
		        Thread encryptedReceiveThread = new Thread( encryptedReceive );
		        encryptedReceiveThread.start();

		        SendEncryptedComms encryptedSend = new SendEncryptedComms( clientSocket, serverEncryptionCipher, true );
		        Thread encryptedSendThread = new Thread( encryptedSend );
		        encryptedSendThread.start();
	        }

	        else if( encrypt_chat && !veryify_message_integrity )  {
				System.out.println("[SERVER] Beginning ENCRYPTED comms with Client...");
		        ReceiveEncryptedComms encryptedReceive = new ReceiveEncryptedComms( clientSocket, serverDecryptionCipher, serverEncryptionCipher, false );
		        Thread encryptedReceiveThread = new Thread( encryptedReceive );
		        encryptedReceiveThread.start();

		        SendEncryptedComms encryptedSend = new SendEncryptedComms( clientSocket, serverEncryptionCipher, false );
		        Thread encryptedSendThread = new Thread( encryptedSend );
		        encryptedSendThread.start();
	        }

	        /*	UNENCRYPTED CHAT no security
			*/
	        else if( !encrypt_chat && !veryify_message_integrity ) {
				System.out.println("[SERVER] Beginning UNENCRYPTED communications with Client...");
				//Start a thread to send communications
				SendCommunications send = new SendCommunications( clientSocket, serverEncryptionCipher, false );
				Thread sendThread = new Thread( send );
				sendThread.start();

				//Start a thread to receive communications
				ReceiveCommunications receive = new ReceiveCommunications( clientSocket, serverDecryptionCipher, serverEncryptionCipher, false );
				Thread receiveThread = new Thread( receive );
				receiveThread.start();
	        }

	        /*	UNENCRYPTED CHAT no security
			*/
	        else if( !encrypt_chat && veryify_message_integrity ) {
				System.out.println("[SERVER] Beginning UNENCRYPTED communications with Client with INTEGRITY...");
				//Start a thread to send communications
				SendCommunications send = new SendCommunications( clientSocket, serverEncryptionCipher, true );
				Thread sendThread = new Thread( send );
				sendThread.start();

				//Start a thread to receive communications
				ReceiveCommunications receive = new ReceiveCommunications( clientSocket, serverDecryptionCipher, serverEncryptionCipher, true );
				Thread receiveThread = new Thread( receive );
				receiveThread.start();
	        }
	        else {
                System.out.println("Nothing exists for the options you chose");
            }
		}
		else { //The chat security parameters do not match, so don't don't initiate a session
            System.out.println("Security chat parameters do not match. Session terminated");
            System.exit(0);
        }
	}

	//Check user input to ensure chat parameters do match
	public static void checkUserChoices() {
        Scanner in = new Scanner( System.in );
        String choice = "";
        boolean firstChoice = false;
        boolean secondChoice = false;
        boolean thirdChoice = false;
        
        while( !firstChoice ) {
        	System.out.println("Would you like encrypted communication? Type (y) or (n)...");
	        choice = in.nextLine();
	        if( choice.equals("y") ) {
	            encrypt_chat = true;
	            firstChoice = true;
	            paramString = paramString.substring(0,0)+'y'+paramString.substring(1);
	        }
	        else if( choice.equals("n")) {
	        	encrypt_chat = false;
	        	firstChoice = true;	
	        }
	        else {
	        	System.out.println("Response invalid. Try again.");
	        }
        }
        
        while( !secondChoice ) {
	        System.out.println("Would you like message integrity verified? Type (y) or (n)...");
	        choice = in.nextLine();
	        if( choice.equals("y") ) {
	            veryify_message_integrity = true;
				secondChoice = true;
	            paramString = paramString.substring(0,1)+'y'+paramString.substring(2);
	        }	
	        else if( choice.equals("n") ) {
	        	veryify_message_integrity = false;
	        	secondChoice = true;
	        }
	        else {
	        	System.out.println("Response invalid. Try again.");
	        }
        }

        while( !thirdChoice ) {
	        System.out.println("Would you like to use password authentication? Type (y) or (n)...");
	        choice = in.nextLine();
	        if( choice.equals("y") ) {
	            use_password_authentication = true;
				thirdChoice = true;
	            paramString = paramString.substring(0,2)+'y'+paramString.substring(3);
	        }	
	        else if( choice.equals("n") ) {
	        	use_password_authentication = false;
	        	thirdChoice = true;
	        }
	        else {
	        	System.out.println("Response invalid. Try again.");
	        }
        }

        System.out.println("Param choice string looks like: " + paramString );
        System.out.println( "You chose the following parameters for chat:");
        if( encrypt_chat ) System.out.println("Encrypted chat: YES");
        else System.out.println("Encrypted chat: NO");
        if( veryify_message_integrity ) System.out.println("Verify message integrity: YES");
        else System.out.println("Verify message integrity: NO");
        if( use_password_authentication ) System.out.println("Password authentication: YES");
        else System.out.println("Password authentication: NO");
        System.out.println();
    }

    //Returns true or false if the Server and Client's chat security parameters match
    public static boolean verifyChatParametersMatch( Socket clientSocket ) {
    	//Based on the choices made by the user, the server send's it's choices to the client
    	System.out.println("[SERVER] Sending chat parameter choices to client...");
		byte[] paramBytes = paramString.getBytes();
		SendByteArray sendChatParameters = new SendByteArray( clientSocket, paramBytes );
		sendChatParameters.run();

		//Server sent its params now we receive the params from client and verify that they match
		System.out.println("[SERVER] Receiving chat parameter choices from client...");
		ReceiveByteArray receiveChatParameters = new ReceiveByteArray( clientSocket );
        receiveChatParameters.run();
        byte[] clientChatParamsBytes;
        clientChatParamsBytes = Arrays.copyOf( receiveChatParameters.getByteArray(), receiveChatParameters.getIncomingByteArraySize() );
        String clientChatParams = new String( clientChatParamsBytes );

        if( clientChatParams.equals( paramString ) ) {
            System.out.println("[SERVER] Client's chat parameters MATCH Server's chat parameters");
            return true;
        }
        else {
            System.out.println("[SERVER] Client's chat parameters DO NOT MATCH Server's chat parameters");
            return false;
        }
    }
}