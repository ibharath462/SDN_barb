package sfc1;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Sff {
	
	
	JMemory received;
	int payloadSize;
	public static Tcp tcp = new Tcp();
	public static Ip4 ip = new Ip4();
	PcapPacket receivedPacket;
	List<Byte> receivedBytes;
	List<Byte> nsh;
	
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
		
		
		int hopCountInt = Integer.parseInt(hopCount,2);
		
		while(hopCountInt > 0){
			
			
			
			if(hopCountInt == 2){
				
				String serviceIndex = String.format("%8s", Integer.toBinaryString(nsh.get(7).byteValue() & 0xFF)).replace(' ', '0');
				
				int serviceIndexInt = Integer.parseInt(serviceIndex,2);
				
				if(serviceIndexInt == 1){
					
					Filtering f1 = new Filtering();
					f1.filter(destination);
					nsh.set(7,(byte) 0x03);
					serviceIndex = String.format("%8s", Integer.toBinaryString(nsh.get(7).byteValue() & 0xFF)).replace(' ', '0');
					serviceIndexInt = Integer.parseInt(serviceIndex,2);
					
				}
				
				if(serviceIndexInt == 3){
					
					NAT n1 = new NAT();
					String modifiedSource = n1.start();
					String t = modifiedSource.substring(0,modifiedSource.indexOf(":")-1);
					System.out.println(t);
					//0xCO
					String tt = t.substring(t.lastIndexOf(".")+1);
					int t3 = Integer.parseInt(tt);
					receivedBytes.set(26,(byte) 0xC0);
					receivedBytes.set(27,(byte) 0x00);
					receivedBytes.set(28,(byte) 0x00);
					receivedBytes.set(29,(byte) Integer.parseInt(Integer.toHexString(t3)));
					
					byte[] finBytes = new byte[receivedBytes.size()];
					
					for (int i = 0; i < receivedBytes.size(); i++) {
						finBytes[i] = receivedBytes.get(i);
					}
					
					JMemory modifiedNewPacket = new JMemoryPacket(JProtocol.ETHERNET_ID, finBytes);
					
					System.out.println("Modified packet after NAT : \n" + modifiedNewPacket.toHexdump());
				}
				
			}
			else if(hopCountInt == 1){
				
			}
			hopCountInt--;
		}
			
		
	}
	
	
	public static void main(String args[]) throws Exception {
	}
	
	public static void hexa(int num) {
	    int m = 0;
	    if( (m = num >>> 4) != 0 ) {
	        hexa( m );
	    }
	    t5 = (char)((m=num & 0x0F)+(m<10 ? 48 : 55));
	}
	
}
