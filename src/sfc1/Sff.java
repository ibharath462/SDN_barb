package sfc1;

import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class Sff {
	
	
	
	String filename= "/home/bharath/MyLog.log";
    Calendar cal = Calendar.getInstance();
    SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
    
    
	JMemory received;
	int payloadSize;
	public static Tcp tcp = new Tcp();
	public static Udp udp = new Udp();
	public static Ip4 ip = new Ip4();
	PcapPacket receivedPacket;
	List<Byte> receivedBytes;
	List<Byte> nsh;
	ArrayList<String> encoded = new ArrayList<String>();
	
	static char t5;

	public Sff(JMemory t , int size , PcapPacket tPacket){
		
		received = t;
		
		receivedBytes = new ArrayList<Byte>();
		
		payloadSize = size;
		
		for (byte b : ((JBuffer) received).getByteArray(0, received.size())){
			receivedBytes.add(new Byte(b));
		}
		
		nsh = new ArrayList<Byte>();
		
		for(int i=receivedBytes.size() - payloadSize - 8; i<=receivedBytes.size() - payloadSize; i++){
			nsh.add((byte) receivedBytes.get(i).byteValue());	
		}
		
			
		receivedPacket = tPacket;
		
	}
	
	public void forward(String destination) throws MalformedURLException, IOException{
		
		String versionString = String.format("%8s", Integer.toBinaryString(nsh.get(0).byteValue() & 0xFF)).replace(' ', '0');
		
		String version = "" + versionString.charAt(0) + versionString.charAt(1);
		
		String lengthString = String.format("%8s", Integer.toBinaryString(nsh.get(1).byteValue() & 0xFF)).replace(' ', '0');
		
		String length = lengthString.substring(2,8);
				
		String mdType = String.format("%8s", Integer.toBinaryString(nsh.get(2).byteValue() & 0xFF)).replace(' ', '0');
		
		String protocolString = String.format("%8s", Integer.toBinaryString(nsh.get(3).byteValue() & 0xFF)).replace(' ', '0');
		
		String spiString = String.format("%8s", Integer.toBinaryString(nsh.get(4).byteValue() & 0xFF)).replace(' ', '0');
		
		spiString += String.format("%8s", Integer.toBinaryString(nsh.get(5).byteValue() & 0xFF)).replace(' ', '0');
		
		spiString += String.format("%8s", Integer.toBinaryString(nsh.get(6).byteValue() & 0xFF)).replace(' ', '0');
		
		String hopCount = spiString.substring(0,8);
		
		System.out.println("Version : " + version + "\n" + "Length:" + length + "\n" + "MetaData type : " + mdType + "\n" + "Protocol : " + protocolString + "\n" + "Hop Limit : " + hopCount + "\nService Path Identifier : " + spiString);
		
		try
		{
			FileWriter fw = new FileWriter(filename,true); //the true will append the new data
		    fw.write(sdf.format(cal.getTime()) + "\nVersion : " + version + "\n" + "Length:" + length + "\n" + "MetaData type : " + mdType + "\n" + "Protocol : " + protocolString + "\n" + "Hop Limit : " + hopCount + "\nService Path Identifier : " + spiString);
		    fw.close();
		}
		catch(IOException ioe)
		{
		    System.err.println("IOException: " + ioe.getMessage());
		}
		
		int hopCountInt = Integer.parseInt(hopCount,2);
		
		String logWrite;
		
		while(hopCountInt > 0){
			
			
			String serviceIndex = String.format("%8s", Integer.toBinaryString(nsh.get(7).byteValue() & 0xFF)).replace(' ', '0');
			
			int serviceIndexInt = Integer.parseInt(serviceIndex,2);
			
			
			
			
			if(hopCountInt == 2 && receivedPacket.hasHeader(tcp)){
				
				
				if(serviceIndexInt == 1){
					
					System.out.println("Service Index :" + serviceIndexInt);
					
					logWrite = "\nService Index :" + serviceIndexInt;
					
					System.out.println("Hop Count :" + hopCountInt);
					
					logWrite += "\nHop Count :" + hopCountInt;
					
					try
					{
						FileWriter fw = new FileWriter(filename,true); //the true will append the new data
					    fw.write(sdf.format(cal.getTime()) + logWrite);
					    fw.close();
					}
					catch(IOException ioe)
					{
					    System.err.println("IOException: " + ioe.getMessage());
					}
					
					Filtering f1 = new Filtering();
					f1.filter(destination);
					nsh.set(7,(byte) 0x03);
					serviceIndex = String.format("%8s", Integer.toBinaryString(nsh.get(7).byteValue() & 0xFF)).replace(' ', '0');
					serviceIndexInt = Integer.parseInt(serviceIndex,2);
					hopCountInt--;
					
					
					
				}
				
				if(serviceIndexInt == 3){
					
					System.out.println("Service Index :" + serviceIndexInt);
					logWrite = "\nService Index :" + serviceIndexInt;
					
					System.out.println("Hop Count :" + hopCountInt);
					logWrite += "\nHop Count :" + hopCountInt;
					
					NAT n1 = new NAT();
					String modifiedSource = n1.start();
					String t = modifiedSource.substring(0,modifiedSource.indexOf(":")-1);
					logWrite = "\n";
					System.out.println("Network Address Translation:");
					logWrite += "\nNetwork Address Translation:";
					System.out.println("Modifid to public address : " + t);
					logWrite += "\nModifid to public address : " + t;
					//0xCO
					String tt = t.substring(t.lastIndexOf(".")+1);
					int t3 = Integer.parseInt(tt);
					if(t3 > 9){
						t3 += 6;
					}
					receivedBytes.set(26,(byte) 0xC0);
					receivedBytes.set(27,(byte) 0x00);
					receivedBytes.set(28,(byte) 0x00);
					receivedBytes.set(29,(byte) Integer.parseInt(Integer.toHexString(t3)));
					
					byte[] finBytes = new byte[receivedBytes.size()];
					
					for (int i = 0; i < receivedBytes.size(); i++) {
						finBytes[i] = receivedBytes.get(i);
					}
					
					JMemory modifiedNewPacket = new JMemoryPacket(JProtocol.ETHERNET_ID, finBytes);
					
					System.out.println("\nModified packet after NAT : \n" + modifiedNewPacket.toHexdump());
					
					logWrite += "\nModified packet after NAT : \n" + modifiedNewPacket.toHexdump();
					
					//Removal of NSH....
					
					List<Byte> t2 = new ArrayList<Byte>();
					
					for(int i = 0; i<receivedBytes.size() - payloadSize - 8; i++){
							t2.add(receivedBytes.get(i));
					}
					
					for(int i = receivedBytes.size() - payloadSize - 1; i<receivedBytes.size(); i++){
						t2.add(receivedBytes.get(i));
					}

					
					byte[] finBytes2 = new byte[receivedBytes.size()];
					
					for(int i=0; i < t2.size(); i++){
						finBytes2[i] = t2.get(i);
					}
					
					JMemory sendPacket = new JMemoryPacket(JProtocol.ETHERNET_ID, finBytes2);
					
					System.out.print("\nFinal Packets after removing NSH : " + sendPacket.toHexdump());
					
					logWrite += "\nFinal Packets after removing NSH : " + sendPacket.toHexdump();
					
					try
					{
						FileWriter fw = new FileWriter(filename,true); //the true will append the new data
					    fw.write(sdf.format(cal.getTime()) + logWrite);
					    fw.close();
					}
					catch(IOException ioe)
					{
					    System.err.println("IOException: " + ioe.getMessage());
					}
					
				}
				hopCountInt--;
				
			}
			else if(hopCountInt == 1 && receivedPacket.hasHeader(udp)){
				
				Encrypt e = new Encrypt();
				
				logWrite = "\n";
				
				System.out.println("\nAfter encryption...");
				
				logWrite += "\nAfter encryption...";
				
				byte[] finBytes = new byte[receivedBytes.size() - payloadSize];
				
				for(int i=0; i < receivedBytes.size() - payloadSize; i++){
					finBytes[i] = receivedBytes.get(i);
				}
				
				JMemory modifiedNewPacket = new JMemoryPacket(JProtocol.ETHERNET_ID, finBytes);
				
				System.out.print(modifiedNewPacket.toHexdump());
				
				logWrite += "\n" + modifiedNewPacket.toHexdump();
				
				encoded = e.encrypt(destination);
			
				
				
				for(int i=0; i < encoded.size(); i++){
				
					String t = encoded.get(i);
					System.out.print(t + " ");
					logWrite += t + " ";
					
				}
				
				//Removal of NSH....
				
				List<Byte> t = new ArrayList<Byte>();
				
				for(int i = 0; i<=receivedBytes.size() - payloadSize - 8; i++){
						t.add(receivedBytes.get(i));
				}
				
				byte[] finBytes2 = new byte[receivedBytes.size() - 8];
				
				for(int i=0; i < t.size(); i++){
					finBytes2[i] = t.get(i);
				}
				
				JMemory sendPacket = new JMemoryPacket(JProtocol.ETHERNET_ID, finBytes2);
				
				System.out.print("\nFinal Packets after removing NSH : " + sendPacket.toHexdump());
				
				logWrite += "\nFinal Packets after removing NSH : " + sendPacket.toHexdump();
				
				for(int i=0; i < encoded.size(); i++){
					
					String tS = encoded.get(i);
					System.out.print(tS + " ");
					logWrite += tS + " ";
					
				}
				
				try
				{
					FileWriter fw = new FileWriter(filename,true); //the true will append the new data
				    fw.write(sdf.format(cal.getTime()) + logWrite);
				    fw.close();
				}
				catch(IOException ioe)
				{
				    System.err.println("IOException: " + ioe.getMessage());
				}
				
				hopCountInt--;
				
			}

		}
		
		

		
		
	}
	
	
	public static void main(String args[]) throws Exception {
	}
	
	
}
