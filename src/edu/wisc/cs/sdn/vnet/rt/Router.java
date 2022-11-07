package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Map.Entry;
import java.util.Timer;
import java.util.TimerTask;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	private static final int ICMP_PADDING_SIZE = 4;
	private static final int GARBAGE_COLLECT_PERIOD = 1000 ; 
	private static final int UNSOLLICITED_PERIOD = 10*1000 ; //10 sec
	private static final int RIP_INFINITY = 32;
	
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	private ArrayList<ArpThread> ArpThreadList;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.ArpThreadList = new ArrayList<ArpThread>();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * @set routing table to be dynamic
	 */
	public void setDynamic(){
		this.routeTable.setDynamic();
		timer_clean = new Timer();
		timer_clean.schedule(garbageCollectTask, 0, GARBAGE_COLLECT_PERIOD);
		timer_send=new Timer();
		timer_send.schedule(unsolicitedResponse,0,UNSOLLICITED_PERIOD);
		RIPInit();
	}
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleARPPacket(etherPacket, inIface);
			break;
			// Ignore all other packet types, for now
		}

		/********************************************************************/
	}
	private void handleIcmpEchoRequest(IPv4 ipPacket, ICMP icmpPacket, Iface inIface){
		System.out.println("handling an ICMP echo request");
		Ethernet echoReply = getCommonEchoReply(ipPacket, icmpPacket, inIface);
		sendPacket(echoReply, inIface);
	}

	private Ethernet getCommonEchoReply(IPv4 ipPacket, ICMP icmpPacket, Iface inIface){
		// 1. set Ethernet header
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		int nextHop = this.routeTable.lookup(ipPacket.getSourceAddress()).getGatewayAddress();
		if (nextHop == 0) {
			nextHop = ipPacket.getSourceAddress();
		}
		ether.setDestinationMACAddress(this.arpCache.lookup(nextHop).getMac().toBytes());

		// 2. set IP header
		IPv4 ip = generateIpPacket(IPv4.PROTOCOL_ICMP, ipPacket.getDestinationAddress(), ipPacket.getSourceAddress());

		// 3. set ICMP header
		ICMP icmp = generateIcmpPacket(0, 0);

		// 4. assemble the Packet
		ether.setPayload(ip);
		ip.setPayload(icmp);
		Data icmpRequestPayload = (Data) icmpPacket.getPayload();
		icmp.setPayload(icmpRequestPayload);
		return ether;
	}
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
		{ return; }

		// Check TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
		if (0 == ipPacket.getTtl())
		{
			// A. Timer expired
			sendICMPPacket((byte)11, (byte)0, inIface, ipPacket);
			return;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// If the packet is RIP
		if(routeTable.isDynamic()==true 
				&& ipPacket.getProtocol()==IPv4.PROTOCOL_UDP
				&& ipPacket.getDestinationAddress()==IPv4.toIPv4Address("224.0.0.9")){
			UDP udpPacket = (UDP) ipPacket.getPayload();
			if(udpPacket.getDestinationPort()==UDP.RIP_PORT){
				System.out.println(" RIP Recieved!");
				RIPv2 rip=(RIPv2)udpPacket.getPayload();
				if(rip.getCommand()==RIPv2.COMMAND_REQUEST){
					Ethernet rip_resp=genRipResp(inIface.getIpAddress(),inIface.getMacAddress());
					return;
				}
				if(rip.getCommand()==RIPv2.COMMAND_RESPONSE){
					updateRouterTable(etherPacket,inIface);
				}
			}
		}

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values())
		{
			if (ipPacket.getDestinationAddress() == iface.getIpAddress())
			{
				// D. Destination port unreachable
				if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP ||
						ipPacket.getProtocol() == IPv4.PROTOCOL_UDP){
					sendICMPPacket((byte)3, (byte)3, inIface, ipPacket);
				}
				else if(ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP){
					ICMP icmp = (ICMP) ipPacket.getPayload();
					if(icmp.getIcmpType() == ICMP.TYPE_ECHO_REQUEST){
						handleIcmpEchoRequest(ipPacket, icmp, inIface);
					}
				}

				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch)
		{
			// B. Destination Unreachable
			sendICMPPacket((byte)3, (byte)0, inIface, ipPacket);

			return; 
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface)
		{ return; }

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = dstAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry)
		{
			// B. Destination Unreachable
			sendICMPPacket((byte)3, (byte)1, inIface, ipPacket);
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}
	private IPv4 generateIpPacket(byte protocol, int sourceAddress, int destAddress){
		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(protocol);
		ip.setSourceAddress(sourceAddress);
		ip.setDestinationAddress(destAddress);
		return ip;
	}

	private ICMP generateIcmpPacket(int type, int code){
		ICMP icmp = new ICMP();
		icmp.setIcmpType((byte) type);
		icmp.setIcmpCode((byte) code);
		return icmp;
	}
	private MACAddress findNextHopMACAddress(int DestIP){
		// 1. loop up the routeTable
		RouteEntry routeEntry = this.routeTable.lookup(DestIP);
		if(routeEntry == null){
			System.err.println("No match Dest IP in routeTable.");
			return null;
		}
		// 2. get the next hop IP address
		int nextHopIP = routeEntry.getGatewayAddress();
		if(nextHopIP == 0){
			nextHopIP = DestIP;
		}
		// 3. find next hop MAC address from arpCache
		ArpEntry arpEntry = this.arpCache.lookup(nextHopIP);
		if(arpEntry == null){
			System.err.println("ICMP: no nuch IP in arpCache");
			return null;
		};
		return arpEntry.getMac();
	}
	private void sendICMPPacket(int type, int code, Iface iface, IPv4 ipPacket){
		// 1. set Ethernet header
		Ethernet ether = new Ethernet();
		// 1.1. set EtherType
		ether.setEtherType(Ethernet.TYPE_IPv4);
		// 1.2. set Source MAC to the MAC address of the out interface
		ether.setSourceMACAddress(iface.getMacAddress().toBytes());

		// 1.3. set Destination MAC: set to the MAC address of the next hop
		int DestIP = ipPacket.getSourceAddress();
		MACAddress nextHopMacAddr = findNextHopMACAddress(DestIP);
		// 1.3.1. if the MAC address associated with an IP address cannot be resolved using ARP.
		//if(destMAC == null) {
		//	RouteEntry rEntry = routeTable.lookup(pktIn.getSourceAddress());
		//	/* Find the next hop IP Address */
		//	int nextHopIPAddress = rEntry.getGatewayAddress();
		//	if(nextHopIPAddress == 0){
		//		nextHopIPAddress = pktIn.getSourceAddress();
		//	}
		//	this.sendARPRequest(ether, inIface, rEntry.getInterface(), nextHopIPAddress);
		//	return;
		//}

		ether.setDestinationMACAddress(nextHopMacAddr.toBytes());
		System.out.println(nextHopMacAddr);

		// 2. set IP header
		IPv4 ip = generateIpPacket(IPv4.PROTOCOL_ICMP, iface.getIpAddress(), ipPacket.getSourceAddress());
		//IPv4 ip = new IPv4();
		// 2.1. TTL—setto64
		//ip.setTtl((byte) 64);
		// 2.2. Protocol — set to IPv4.PROTOCOL_ICMP
		//ip.setProtocol(IPv4.PROTOCOL_ICMP);
		// 2.3. Source IP — set to the IP address of the interface on which the original packet arrived
		//ip.setSourceAddress(iface.getIpAddress());
		// 2.4. Destination IP — set to the source IP of the original packet
		//ip.setDestinationAddress(ipPacket.getSourceAddress());

		// 3. set ICMP header
		ICMP icmp = generateIcmpPacket(type, code);
		//ICMP icmp = new ICMP();
		// 3.1. set ICMP type
		//icmp.setIcmpType((byte)type);
		// 3.2. set ICMP code
		//icmp.setIcmpCode((byte)code);

		// 4. assemble the ICMP payload
		Data data = new Data();
		// 4.1. construct byteArray
		int origialIPHeaderLength = ipPacket.getHeaderLength() * 4;
		byte[] byteArray = new byte[4 + origialIPHeaderLength + 8];
		// 4.2. copy bytes from IpPacket
		byte[] serializedIpPacket = ipPacket.serialize();
		int serializedIpPacketLen = serializedIpPacket.length;
		for(int i = 0; i < origialIPHeaderLength + 8; i++){
			if (i < serializedIpPacketLen) byteArray[4 + i] = serializedIpPacket[i];
			else break;
		}

		// 5. assemble the ICMP Packet
		data.setData(byteArray);
		icmp.setPayload(data);
		ip.setPayload(icmp);
		ether.setPayload(ip);

		// 6. send ICMP Packet
		this.sendPacket(ether, iface);
	}

	private void handleARPRequest(ARP arpPacket,Ethernet etherPacket, Iface inIface){
		ARP arpHeader=new ARP();
		arpHeader.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arpHeader.setProtocolType(ARP.PROTO_TYPE_IP);
		arpHeader.setHardwareAddressLength((byte)(Ethernet.DATALAYER_ADDRESS_LENGTH& 0xff));
		arpHeader.setProtocolAddressLength((byte)4);
		arpHeader.setOpCode(ARP.OP_REPLY);
		arpHeader.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arpHeader.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(inIface.getIpAddress()));
		arpHeader.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
		arpHeader.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
		//create Ethernet header
		Ethernet ethHeader=new Ethernet();
		ethHeader.setEtherType(Ethernet.TYPE_ARP);
		ethHeader.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ethHeader.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		//link the headers
		ethHeader.setPayload(arpHeader);
		//send packet
		sendPacket(ethHeader, inIface);

		return;
	}
	private void handleARPReply(ARP arpPacket, Ethernet etherPacket, Iface inIface, int sourceIP){
		//process arp replies
		System.out.println("\nProcessing the arp replies");
		//Consider only if ARP cache value for this IP is missing
		if(arpCache.lookup(sourceIP)==null)
		{
			//find the thread with respect to the source IP
			for(int i=0;i<ArpThreadList.size();i++){
				if(ArpThreadList.get(i).IP==sourceIP){
					//check if still active
					if(ArpThreadList.get(i).succ==false){
						ArpThreadList.get(i).setReply(etherPacket, inIface);
						arpCache.insert(new MACAddress(arpPacket.getSenderHardwareAddress()), sourceIP);
						break;
					}else{
						//if time out, remove the thread
						ArpThreadList.remove(i);
						break;
					}
				}
			}
			return;
		}
	}
	private void handleARPPacket(Ethernet etherPacket, Iface inIface){
		// Make sure it's an ARP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
		{ return; }

		//get patload
		ARP arpPacket = (ARP)etherPacket.getPayload();
		//get target IP
		int targetIP=ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		//get source IP
		int sourceIP = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();

		if(inIface.getIpAddress()== targetIP) {
			if(arpPacket.getOpCode() == ARP.OP_REQUEST){
				this.handleARPRequest(arpPacket, etherPacket, inIface);
			} else{
				this.handleARPReply(arpPacket, etherPacket, inIface, sourceIP);
			}
		} else{
			System.out.println("\nARP packet not for our inIface: "+inIface.toString());
			System.out.println("\nTarget IP: "+IPv4.fromIPv4Address(targetIP));
			return;
		}
	}

	/** 
	 * Initiate RIP
	 */
	public void RIPInit(){
		for(Entry<String, Iface> entry : this.interfaces.entrySet()){
			Iface iface = entry.getValue();
			routeTable.insert_rip(iface.getIpAddress()&iface.getSubnetMask(),0,iface.getSubnetMask(),1,iface);
		}
		for(Entry<String, Iface> entry : this.interfaces.entrySet()){
			Iface iface = entry.getValue();
			sendPacket(genRipReq(iface.getIpAddress(),iface.getMacAddress()), entry.getValue());
		}
		System.out.println("Initiated dynamic route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	/** 
	 * generate a RIP response packet
	 * 
	 * @param srcIP
	 * @param srcMAC
	 * @return
	 */
	public Ethernet genEthernetIpLayer(Ethernet ether, IPv4 ip, int srcIP, MACAddress srcMAC){
		//ethernet layer
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		ether.setSourceMACAddress(srcMAC.toBytes());

		//ip layer
		ip.setSourceAddress(srcIP);
		ip.setDestinationAddress("224.0.0.9");
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ether.setPayload(ip);
		return ether;
	}

	public Ethernet genRipResp(int srcIP, MACAddress srcMAC){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		ether = this.genEthernetIpLayer(ether, ip, srcIP, srcMAC);
		
		//udp layer
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		rip.setCommand(RIPv2.COMMAND_RESPONSE);

		//link packets together
		ip.setPayload(udp);
		udp.setPayload(rip);

		for(RouteEntry entry : routeTable.getEntries()) {
			RIPv2Entry tmp=new RIPv2Entry(entry.getDestinationAddress(),entry.getMaskAddress(),entry.getDistance());
			tmp.setNextHopAddress(entry.getDestinationAddress());
			rip.addEntry(tmp);
		}
		
		//reset checksums
		udp.resetChecksum();
		ip.resetChecksum();
		ether.resetChecksum();
		
		return ether;
	}
	
	/** 
	 * generate a RIP request packet
	 * @param srcIP
	 * @param srcMAC
	 * @return
	 */
	public Ethernet genRipReq(int srcIP, MACAddress srcMAC){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		ether = this.genEthernetIpLayer(ether, ip, srcIP, srcMAC);

		//udp layer
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		
		rip.setCommand(RIPv2.COMMAND_REQUEST);
		
		//link packets together
		ip.setPayload(udp);
		udp.setPayload(rip);
		
		//reset checksums
		udp.resetChecksum();
		ip.resetChecksum();
		ether.resetChecksum();
		
		return ether;
	}
	
	/**
	 * 
	 */
	public void broadRIPReq(){
		for(Entry<String, Iface> entry : this.interfaces.entrySet()){
			Iface iface = entry.getValue();
			sendPacket(genRipReq(iface.getIpAddress(),iface.getMacAddress()), entry.getValue());
		}
	}

	/**
	 * Update the dynamic route table according to the incoming RIP packet
	 * @param ether
	 * @param inIface
	 */
	public synchronized void updateRouterTable(Ethernet ether,Iface inIface){
		IPv4 packet = (IPv4) ether.getPayload();
		UDP udpPacket = (UDP) packet.getPayload();
		RouteEntry inEntry=routeTable.lookup(packet.getSourceAddress());
		if(inEntry==null){
			return;
		}
		RIPv2 rip= (RIPv2) udpPacket.getPayload();
		for(RIPv2Entry ripEntry : rip.getEntries()){
			RouteEntry routeEntry=routeTable.lookup(ripEntry.getAddress());
			//If the term in RIP is not in the table
			if(routeEntry==null){
				routeTable.insert_rip(ripEntry.getAddress()&ripEntry.getSubnetMask(),packet.getSourceAddress(),ripEntry.getSubnetMask(),ripEntry.getMetric()+1,inIface);
			}else if (routeEntry.getDistance()<=ripEntry.getMetric()+inEntry.getDistance()+1){
				routeTable.update_time(ripEntry.getAddress()&ripEntry.getSubnetMask(),ripEntry.getSubnetMask());
			}else{
				routeTable.update_rip(ripEntry.getAddress()&ripEntry.getSubnetMask(), ripEntry.getSubnetMask(), packet.getSourceAddress() ,Math.max(ripEntry.getMetric()+inEntry.getDistance(),RIP_INFINITY),inIface);
			}
		}
		System.out.println("new route table is");
		System.out.println("<------------------------------------------------>");
		System.out.print(this.routeTable.toString());
		System.out.println("<------------------------------------------------>");
	}
	

	private Timer timer_clean,timer_send;
	private TimerTask garbageCollectTask = new TimerTask() {
		@Override
		public void run() {
			routeTable.cleanTable();
		}
	};
	private TimerTask unsolicitedResponse = new TimerTask() {
		@Override
		public void run() {
			for(Entry<String, Iface> entry : interfaces.entrySet()){
				Iface iface = entry.getValue();
				sendPacket(genRipResp(iface.getIpAddress(),iface.getMacAddress()), entry.getValue());
			}
		}
	};
}
