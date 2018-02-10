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

public class HashByteArray{


	public static byte[] hashByteArray(byte[] input){
		try{
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			byte [] val = sha.digest(input);
			return val;
		}catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}
		return input;
	}

	public static byte[] hashString(String input){
		
			byte [] val = input.getBytes();
		try{
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			byte [] returnVal = sha.digest(val);
			return returnVal;
		}catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}

		return val;
	}

	public static byte[] encryptHash(byte[] input, Cipher encryptionCipher){
		try{
			//Cipher encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			//encryptionCipher.init(Cipher.ENCRYPT_MODE, sks, ap);
			byte [] arr = hashByteArray(input);
			byte [] encryptedHash = encryptionCipher.doFinal(arr);
			return encryptedHash;
		}catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}

		return input;

	}

	public static byte[] decryptHash(byte[] input, Cipher decryptionCipher){
		try{
			//Cipher decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			//decryptionCipher.init(Cipher.DECRYPT_MODE, sks, ap);
			byte [] decryptedHash = decryptionCipher.doFinal(input);
			return decryptedHash;
		}catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}

		return input;
	}

	public static void sendHash(byte [] hash, Socket socket, Cipher cipher){
		try{

			byte [] fingerprint = encryptHash(hash, cipher);
			DataOutputStream writer = new DataOutputStream( socket.getOutputStream() );
			//added this incase you wanted to do the length stuff
			writer.writeInt( fingerprint.length );
			writer.write(fingerprint);

		}catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}
	}

	public static void sendNotHash(byte [] plain, Socket socket, Cipher cipher){
		try{

			byte [] fingerprint = encryptPlain(plain, cipher);
			DataOutputStream writer = new DataOutputStream( socket.getOutputStream() );
			//added this incase you wanted to do the length stuff
			writer.writeInt( fingerprint.length );
			writer.write(fingerprint);

		}catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}
	}

	public static byte[] encryptPlain(byte[] input, Cipher encryptionCipher){
		try{
			//Cipher encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			//encryptionCipher.init(Cipher.ENCRYPT_MODE, sks, ap);
			byte [] encryptedPlain = encryptionCipher.doFinal(input);
			return encryptedPlain;
		}catch (Exception e) {
			System.out.println( e.toString() );
			e.printStackTrace();
		}

		return input;

	}


}