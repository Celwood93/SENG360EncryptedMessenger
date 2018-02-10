/*
*	SendByteArray.java
*	Utilizes threads for chat concurrency
*/

import java.io.*;
import java.net.*;
import java.util.Arrays;

/*
*	SendByteArray
*	Instantiated by Server and Client
*	or any class whicn requires the ability to send
*	a byte array through a socket output stream.
*/
public class SendByteArray {

	/*
	*	Init vars
	*	The socket object which binds a port for IP/UDP comms
	*/
	private Socket socket = null;
	private DataOutputStream writer = null;
	private byte[] message;

	/*
	*	Set the socket object to the socket parameter which
	*	had been passed in likely by a Server or Client object.
	*	Both the Server and Client utilise regular Socket objects (not ServerSocket's)
	*/
	public SendByteArray( Socket socket, byte[] message ) {
		this.socket = socket;
		this.message = message;
	}

	/*
	*	Here we create a writer to send bytes to the output socket
	* 	and a reader to get user input from the terminal.
	*/
	public void run() {

		try {

			System.out.println( "[SendByteArray Object] sending byte array of size " + message.length + "...");

			//The writer sends lines to the socket output based on user input
			writer = new DataOutputStream( socket.getOutputStream() );

				//Write the length of the byte array to the stream
				writer.writeInt( message.length );
				//Write the actual byte message to the byte stream
				writer.write(message);

		} catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}
	}

}