package sfc1;

import java.util.ArrayList;
import java.util.Scanner;
import java.net.*;
import java.awt.List;
import java.io.*;

public class Filtering {

	static Scanner scan;
    static Scanner blocked;
    static String inputPage,hostname,address;
    
    public void getUrl()
    {
    	
    	ArrayList<Integer> list = new ArrayList<Integer>();
        try {
            
        	 
        	 InetAddress host = InetAddress.getByName(address);
        	 hostname =host.getCanonicalHostName();
        	 for(int i=0;i<hostname.length();i++){
        		 if(hostname.charAt(i) == '.'){
        			 list.add(i+1);
        		 }
        	 }
        	 if(list.size() > 1)
        	 	 hostname = "www." + hostname.substring(list.get(list.size()-2));
        	 else
        	 	 hostname = "www." + hostname;
        	 System.out.println(hostname);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }
    public boolean isBlocked()
    {
    	
        while(blocked.hasNext())
        {
            String temp=blocked.next();
            if (hostname.equals(temp)){

                return true;
            }
        }
        return false;
    }
    
   
    public static void main(String [] args) throws Exception
    {
    	
    	
        
    	        
    }
    
	public void filter(String destination) throws FileNotFoundException {
		
    	Filtering f = new Filtering();
    	address = destination;
    	System.out.println(address);
        scan = new Scanner(System.in);
        blocked=new Scanner(new FileReader("src/sfc1/blocked.txt"));
        f.getUrl();
        if (f.isBlocked()){
            System.out.println("Access Denied");
        }
        else
        {
            System.out.println("Allowed..");
        }
		// TODO Auto-generated method stub
		
	}

}
