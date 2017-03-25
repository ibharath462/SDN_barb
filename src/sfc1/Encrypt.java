package sfc1;

public class Encrypt {
	public static void main(String [] args) throws Exception
    {
		
		
		
		
    }
	
	public void encrypt(String plainText){
		
		int key = 4;
		
		plainText = plainText.replaceAll("[^a-zA-Z]", "");
		
		plainText = plainText.toUpperCase();
	    char[] plainTextChar = plainText.toCharArray();
	    for(int i=0;i<plainTextChar.length;i++) {
	        plainTextChar[i] = (char)(((int)plainTextChar[i]+key-65)%26 + 65);
	    }
	    System.out.println(String.valueOf(plainTextChar));
		
	}
	

}
