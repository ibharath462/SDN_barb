package sfc1;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;

public class Sff {
	
	
	JMemory received;
	int payloadSize;
	
	

	public Sff(JMemory t , int size){
		
		received = t;
		//System.out.println("Sff:\n" + t.toHexdump());
		//System.out.println("String:\n" + t.toString());
		
		List<Byte> receivedBytes = new ArrayList<Byte>();
		
		payloadSize = size;
		
		for (byte b : ((JBuffer) received).getByteArray(0, received.size())){
			receivedBytes.add(new Byte(b));
		}
		
		List<Byte> nsh = new ArrayList<Byte>();
		
		for(int i=receivedBytes.size() - payloadSize - 8; i<=receivedBytes.size() - payloadSize; i++){
			nsh.add((byte) receivedBytes.get(i).byteValue());	
		}
		
		String versionString = String.format("%8s", Integer.toBinaryString(nsh.get(0).byteValue() & 0xFF)).replace(' ', '0');
		
		String version = "" + versionString.charAt(0) + versionString.charAt(1);
		
		String lengthString = String.format("%8s", Integer.toBinaryString(nsh.get(1).byteValue() & 0xFF)).replace(' ', '0');
		
		String length = lengthString.substring(2,8);
		
		System.out.println(length);
		
	}
	
	public void forward(){
		
	}
	
	
	public static void main(String args[]) throws Exception {
	}
	
	
}
