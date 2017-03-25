package sfc1;

import java.util.ArrayList;
import java.util.Scanner;
import java.net.*;
import java.awt.List;
import java.io.*;

import javax.swing.JEditorPane;

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
        	 System.out.println("Resolved hostname:" + hostname);
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
    
	public void filter(String destination) throws MalformedURLException, IOException {
		
		System.out.println("Filtering SF....");
		
    	Filtering f = new Filtering();
    	address = destination;
    	System.out.println("Destination address : " + address);
        scan = new Scanner(System.in);
        blocked=new Scanner(new FileReader("src/sfc1/blocked.txt"));
        f.getUrl();
        if (f.isBlocked()){
            System.out.println("Access Denied to:" + destination);
        }
        else
        {
            System.out.println(destination + " is allowed..");
            URL url = new URL("http://" + hostname);
            URLConnection spoof = url.openConnection();

            //Spoof the connection so we look like a web browser
            spoof.setRequestProperty( "User-Agent", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0;    H010818)" );
            BufferedReader in = new BufferedReader(new InputStreamReader(spoof.getInputStream()));
            String strLine = "";
            String finalHTML = "";
            //Loop through every line in the source
            while ((strLine = in.readLine()) != null){
               finalHTML += strLine;
               finalHTML += "\n";
            }	
            System.out.println(finalHTML);
        }
		// TODO Auto-generated method stub
        return;
		
	}

}
