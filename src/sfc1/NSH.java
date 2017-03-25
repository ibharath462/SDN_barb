package sfc1;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

@Header(length=24 , name = "NSH", nicname = "nsh")
public class NSH extends JHeader{
	
	  @Field(offset = 0, length = 8)  
	  public int fieldA() {  
	    return super.getUByte(0);  
	  }  
	  
	  @Bind(from = NSH.class, to = Tcp.class)  
	  public static boolean bindMyClassToEthernet(JPacket packet) {  
	    //return eth.type() == 0x200; // Our dummy protocol number  
		  return true;
	  } 
	  
	  

}
