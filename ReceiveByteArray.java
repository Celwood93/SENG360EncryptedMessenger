import java.io.*;
import java.net.*;
import java.util.Arrays;

/*
*	ReceiveByteArray is threadwise class
*	which can be instantiated by Server and Client
*	or any class whicn requires the ability to receive
*	byte data through a socket input stream.
*/
public class ReceiveByteArray {
	
	/*
	*	Init vars
	*	The socket object which binds a port for IP/UDP comms
	*/
	private Socket socket = null;
	private DataInputStream reader = null;
	private byte[] message;
	private int length;

	/*
	*	Set the socket object to the socket parameter which
	*	had been passed in likely by a Server or Client object.
	*	Set the byte array to that which was passed in by a client or server
	*/
	public ReceiveByteArray( Socket socket ) {
		this.socket = socket;
	}

	/*
	*	Implement the run function required classes which implement Runnable.
	*	Here we create a reader to receive messages from the socket input stream,
	*/
	public void run() {

		try {
			//Set the reader to the socket input stream
			//Gets the length of the incoming message
			reader = new DataInputStream( socket.getInputStream() );
			this.length = reader.readInt();

				if( length > 0 ) {
					System.out.println( "[ReceiveByteArray Object] receiving byte array of size " + length + "...");
					this.message = new byte[length];
					//Fully read in the byte array to message var
					reader.readFully(message, 0, message.length);
				}
			
		} catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}
	}

	//Return the byte array length
	public int getIncomingByteArraySize() {
		return this.length;
	}

	//Return the actual byte array
	public byte[] getByteArray() {
		return this.message;
	}
}