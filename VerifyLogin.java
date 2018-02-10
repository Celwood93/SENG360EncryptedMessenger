import java.util.*;
import java.io.*;

public class VerifyLogin{

	
	public static boolean CheckPassWordHash(byte[] hashedPW, String username){
		try{
				File file;
	   			Scanner console = new Scanner(file = new File("Passwords/loginCredentials.txt"));
	   			
			    do{
			    	String line = console.nextLine();
			    	String hash = new String(hashedPW);
			        if(line.equals(username+ " : "+ hash)){
		        		return true;
		        	}
			    }while (console.hasNextLine());
			    console.close();
			    return false;
			
		}catch(FileNotFoundException ioe){
			System.out.println("error in checkifexists");
			return false;
		}
	}

	public static boolean MakeNewUser(byte[] hashedPW, String username){
		if(checkIfExists(username)){
			return false;
		}
		BufferedWriter fos;
		File file;
		try{
			fos = new BufferedWriter(new FileWriter("Passwords/loginCredentials.txt", true));
			String hash = new String(hashedPW);
			fos.append(username+" : " + hashedPW+"\n");
			//System.out.println(hashedPW.toString());
			fos.close();
		}catch(IOException fnfe){
			System.out.println("errror with files");
		}
		return true;
	}
	

public static void main(String [] args){ //initialize things

		byte [] pw = new byte[] {12, 12, 12};
		System.out.println(true == MakeNewUser(pw, "cam"));
		System.out.println(true == CheckPassWordHash(pw, "cam"));
		byte [] pw2 = new byte[] {120, 121, 122};
		System.out.println(true == MakeNewUser(pw2, "aalex"));
		System.out.println(true == CheckPassWordHash(pw2, "aalex"));




}

	public static boolean checkIfExists(String username){
		try{
			try(BufferedReader br = new BufferedReader(new FileReader("Passwords/loginCredentials.txt"))) {
	   			String line = br.readLine();
			    while (line != null) {
			        if(line.matches("\\b"+username+"\\b.*")){
						br.close();
			        	return true;
			        }
			        line = br.readLine();
			    }
			    br.close();
			    return false;
			}
		}catch(IOException ioe){
			System.out.println("error in checkifexists");
			return true;
		}

	}


}