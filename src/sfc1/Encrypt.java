package sfc1;

import java.awt.List;
import java.util.ArrayList;

public class Encrypt {
	public static void main(String [] args) throws Exception
    {
		
		
		
		
    }
	
	public ArrayList<String> encrypt(String plainText){
		
		int key = 4;
				
		int length = 0;
		
		boolean foundChar = false;
		
		char[] plainTextChar = plainText.toCharArray();
		
		
		for(int i=0;i<plainTextChar.length;i++) {
			
	        if(plainTextChar[i] == ' ' && foundChar){
	        	
	        	break;
	        	
	        }
	        else if(plainTextChar[i] == ' ' && foundChar == false){
	        	
	        	continue;
	        }
	        else{
	        	foundChar = true;
	        	length++;
	        }
	    }
		
		plainText = plainText.replaceAll("[^a-zA-Z]", "");
		
		plainText.trim();
		
		plainTextChar = plainText.toCharArray();
		
		ArrayList<String> encoded = new ArrayList<String>();
		
		
	    for(int i=0;i<plainTextChar.length;i++) {
	        plainTextChar[i] = (char)(((int)plainTextChar[i]+key-65)%26 + 65);
	    }
	    
		//System.out.println(String.valueOf(plainTextChar) + " , " + length);
		
		String temp = "";
		
		
		for(int i=0;i<plainTextChar.length;i++) {
	        if(i % 2 == 0 && i != 0){
	        	
	        	encoded.add(temp);
	        	temp = "";
	        	temp += plainTextChar[i];
	        	
	        }
	        else{
	        	temp += plainTextChar[i];
	        }
	    }
		encoded.add(temp);
		return encoded;
		
		
		
	}
	

}
