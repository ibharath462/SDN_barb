package sfc1;

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Sff {
	
	
	JMemory received;
	int payloadSize;
	public static Tcp tcp = new Tcp();
	public static Ip4 ip = new Ip4();
	PcapPacket receivedPacket;
	List<Byte> nsh;
	
	

	public Sff(JMemory t , int size , PcapPacket tPacket){
		
		received = t;
		
		List<Byte> receivedBytes = new ArrayList<Byte>();
		
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
	
	public void forward(String destination) throws FileNotFoundException{
		
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
					nsh.add(7,(byte) 0x03);
					serviceIndex = String.format("%8s", Integer.toBinaryString(nsh.get(7).byteValue() & 0xFF)).replace(' ', '0');
					serviceIndexInt = Integer.parseInt(serviceIndex,2);
					
				}
				
				if(serviceIndexInt == 3){
					
					
					
				}
				
			}
			else if(hopCountInt == 1){
				
			}
			hopCountInt--;
		}
			
		
	}
	
	
	public static void main(String args[]) throws Exception {
	}
	
	
}
