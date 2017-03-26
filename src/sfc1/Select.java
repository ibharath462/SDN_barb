package sfc1;


import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.network.Ip4;


import java.util.ArrayList;

import java.util.Date;
import java.util.List;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
//For getting host IP address & MAC
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.util.Enumeration;
import java.net.NetworkInterface;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.RegistryHeaderErrors;
//For formatting mac & ip output
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.format.XmlFormatter;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

//General Utils
//import java.util.List;
//import java.util.ArrayList;
import java.util.Arrays;

@Header
public class Select {
	public static Ip4 ip = new Ip4();
	public static Ethernet eth = new Ethernet();
	public static Tcp tcp = new Tcp();
	public static Udp udp = new Udp();
	/*	public static Rip rip = new Rip() {
			void printheader() {
			System.out.println(rip.getHeader());
			}
			}; */
	
	public static Arp arp = new Arp();
	public static Payload payload = new Payload();
	public static byte[] payloadContent;
	public static boolean readdata = false;	public static byte[] myinet = new byte[3];
	public static byte[] mymac = new byte[5];

	public static InetAddress inet;
	public static Enumeration e;
	public static NetworkInterface n;
	public static Enumeration ee;
	
	static String destination,source;

  public static void main(String args[]) throws Exception {
    // chapter 2.2-4
    // initiate packet capture device
	
	final int snaplen = Pcap.DEFAULT_SNAPLEN;
    final int flags = Pcap.MODE_PROMISCUOUS;
    final int timeout = Pcap.DEFAULT_TIMEOUT;
    



    final StringBuilder errbuf = new StringBuilder();
    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
    StringBuilder errbuf1 = new StringBuilder(); // For any error msgs
    int r = Pcap.findAllDevs(alldevs, errbuf1);
    if (r != Pcap.OK || alldevs.isEmpty()) {
        System.err.printf("Can't read list of devices, error is %s",
                errbuf1.toString());
        return;
    }
    System.out.println("Network devices found:");
    int i = 0;
    for (PcapIf device : alldevs) {
        String description = (device.getDescription() != null) ? device
                .getDescription() : "No description available";
        System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
                description);
    }
    PcapIf device = alldevs.get(7); // Get first device in list
    System.out.printf("\nChoosing '%s' on your behalf:\n",
            (device.getDescription() != null) ? device.getDescription()
                    : device.getName());
    Pcap pcap = Pcap.openLive(device.getName(),snaplen, flags, timeout, errbuf1);
    if (pcap == null) {
      System.out.println("Error while opening device for capture: " + errbuf1.toString());  
      return;
    }

		// Get local address
		e = NetworkInterface.getNetworkInterfaces();
		while (e.hasMoreElements()) {
			n = (NetworkInterface)e.nextElement();
			
		}
		// Get IPv4 manually instead of looping through all IP's
		// myinet = inet.getAddress();

		// packet handler for packet capture
		pcap.loop(10, pcappackethandler, "pressure");
		pcap.close();
	}

	public static PcapPacketHandler<String> pcappackethandler = new PcapPacketHandler<String>() {
		public void nextPacket(PcapPacket pcappacket, String user) {
			
			
			PcapPacket packet = pcappacket;
			
			System.out.println("Original packet is : \n" + packet.toHexdump());
			
			
			if (pcappacket.hasHeader(ip)) {
				
				if (FormatUtils.ip(ip.source()) != FormatUtils.ip(myinet) &&
						FormatUtils.ip(ip.destination()) != FormatUtils.ip(myinet)) {
					
					/*System.out.println();
					System.out.println("IP type:\t" + ip.typeEnum());
					System.out.println("IP src:\t-\t" + FormatUtils.ip(ip.source()));
					System.out.println("IP dst:\t-\t" + FormatUtils.ip(ip.destination()));*/
					destination = FormatUtils.ip(ip.destination());					
					source = FormatUtils.ip(ip.source());
					readdata = true;
				}
			}
			if (pcappacket.hasHeader(eth) &&
					readdata == true) {
				/*System.out.println("Ethernet type:\t" + eth.typeEnum());
				System.out.println("Ethernet src:\t" + FormatUtils.mac(eth.source()));
				System.out.println("Ethernet dst:\t" + FormatUtils.mac(eth.destination()));*/
			}
			if (pcappacket.hasHeader(tcp) &&
					readdata == true) {
				
				/*System.out.println("TCP src port:\t" + tcp.source());
				System.out.println("TCP dst port:\t" + tcp.destination());*/
				
			    
				//String hexdump = packet.toHexdump(packet.size(), false, false, true);  
				
				int payloadSize = 0;
				
				System.out.println("TCP packet");
				
				if (pcappacket.hasHeader(payload) && 
						readdata == true) {
					payloadContent = payload.getPayload();
					payloadSize = payload.size();
				}
				
				List<Byte> asBytes = new ArrayList<Byte>();
				
				for (byte b : packet.getByteArray(0, packet.size())){
				    asBytes.add(new Byte(b));
				}	
				
				
				
				byte[] 	finBytes = new byte[asBytes.size() + 8];
				
				byte[] 	data = new byte[payloadSize];
				
				
				//Copying data bytes...
				for (int i = 0 , j=asBytes.size() - payloadSize; i < payloadSize; i++,j++){
				    data[i] = asBytes.get(j).byteValue();
				}

				//Just before NSH.....
				int i;
				for (i = 0; i < asBytes.size() - payloadSize; i++){
				    finBytes[i] = asBytes.get(i).byteValue();
				}
				
				
				
				//Adding NSH...
				
				
				finBytes[i++] = (byte)0x40;
				finBytes[i++] = (byte)0x06;
				finBytes[i++] = (byte)0x01;
				finBytes[i++] = (byte)0x01;
				finBytes[i++] = (byte)0x02;
				finBytes[i++] = (byte)0x00;
				finBytes[i++] = (byte)0x01;
				finBytes[i++] = (byte)0x01;
				
				
				
				
				
				
				
				//Adding back the data.....
				
				for (int j=i , k =0; k < payloadSize; k++,j++){
					
					finBytes[j] = data[k];
					
					
				}
				
				
				
				
				
				JMemory packet2 = new JMemoryPacket(JProtocol.ETHERNET_ID, finBytes);
				
			    //System.out.println("Text:\n" + packet2.toHexdump());
			    //System.out.println("Text:\n" + packet2.toString());
				//System.out.println(packet2.size());
				
				//SFF....
				
				Sff f1 = new Sff(packet2 , payloadSize , packet);
				
				//Forwarding....
				
				try {
					f1.forward(destination);
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (MalformedURLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				
				
				
				
		
			    //System.out.println(JRegistry.toDebugString());
				
			} else if (pcappacket.hasHeader(udp) &&
								 readdata == true) {
				
				int payloadSize = 0;
				
				
				System.out.println("UDP packet..");
				
				String pay = null;
				
				if (pcappacket.hasHeader(payload) && 
						readdata == true) {
					payloadContent = payload.getPayload();
					payloadSize = payload.size();
					pay = payload.toHexdump().toString();
					pay = pay.substring(pay.indexOf(":")+1);
					
				}
				
				List<Byte> asBytes = new ArrayList<Byte>();
				
				for (byte b : packet.getByteArray(0, packet.size())){
				    asBytes.add(new Byte(b));
				}	
				
				
				
				byte[] 	finBytes = new byte[asBytes.size() + 8];
				
				byte[] 	data = new byte[payloadSize];
				
				
				//Copying data bytes...
				for (int i = 0 , j=asBytes.size() - payloadSize; i < payloadSize; i++,j++){
				    data[i] = asBytes.get(j).byteValue();
				}

				//Just before NSH.....
				int i;
				for (i = 0; i < asBytes.size() - payloadSize; i++){
				    finBytes[i] = asBytes.get(i).byteValue();
				}
				
				
				
				//Adding NSH...
				
				
				finBytes[i++] = (byte)0x80;
				finBytes[i++] = (byte)0x06;
				finBytes[i++] = (byte)0x01;
				finBytes[i++] = (byte)0x02;
				finBytes[i++] = (byte)0x01;
				finBytes[i++] = (byte)0x00;
				finBytes[i++] = (byte)0x02;
				finBytes[i++] = (byte)0x02;
				
				
				
				
				
				
				
				//Adding back the data.....
				
				for (int j=i , k =0; k < payloadSize; k++,j++){
					
					finBytes[j] = data[k];
					
					
				}
				
				
				
				
				
				JMemory packet2 = new JMemoryPacket(JProtocol.ETHERNET_ID, finBytes);
				
				
				//SFF....
				
				Sff f1 = new Sff(packet2 , payloadSize , packet);
				
				//Forwarding....
				
				try {
					f1.forward(pay);
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (MalformedURLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				//System.out.println("UDP packet...");


		
		}
			
		}
		
	};
	
	}


