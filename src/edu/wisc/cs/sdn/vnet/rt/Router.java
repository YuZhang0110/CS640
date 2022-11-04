package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.MACAddress;


import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Queue;
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicReference;
import java.lang.Thread;
import java.util.Timer;
import java.util.TimerTask;
/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/** Hashmap of queues */
	private HashMap<Integer, Queue>  packetQueues;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.packetQueues = new HashMap<Integer, Queue>();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

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
			case Ethernet.TYPE_ARP:
				this.handleArpPacket(etherPacket, inIface);
				break;
			// Ignore all other packet types, for now
		}

		/********************************************************************/
	}
	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	private void handleArpPacket(Ethernet etherPacket, Iface inIface)
	{
		ARP arpPacket = (ARP)etherPacket.getPayload();
		int targetIp =
				ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		// Make sure it's an ARP Request
		if (arpPacket.getOpCode() == ARP.OP_REQUEST){
			System.out.println("REPLY");

			if (targetIp == inIface.getIpAddress()){
				Ethernet ether = new Ethernet();
				ARP arp = new ARP();
				// Set Ehternet header
				ether.setEtherType(ARP.HW_TYPE_ETHERNET);
				ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
				ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
				// Set ARP Header
				arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
				arp.setProtocolType(ARP.PROTO_TYPE_IP);
				arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
				arp.setProtocolAddressLength((byte) 4);
				arp.setOpCode(ARP.OP_REPLY);

				arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
				arp.setSenderProtocolAddress(inIface.getIpAddress());

				arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
				arp.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
				ether.setPayload(arp);
				this.sendPacket(ether, inIface);
			}
		} else if (arpPacket.getOpCode() == ARP.OP_REPLY) {
			// Update arp cache
			ByteBuffer senderProtocol = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress());
			int address = senderProtocol.getInt();
			arpCache.insert(new MACAddress(arpPacket.getSenderHardwareAddress()), address);

			//System.out.println("IP addr we're looking at:" + address);

			Queue packetsToSend = packetQueues.get(new Integer(address));
			while(packetsToSend != null && packetsToSend.peek() != null){
				Ethernet packet = (Ethernet)packetsToSend.poll();
				packet.setDestinationMACAddress(arpPacket.getSenderHardwareAddress());
				this.sendPacket(packet, inIface);
			}

		}

	}
	public void sendRip(Iface inIface, boolean broadcast, boolean isRequest)
	{
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udpPacket = new UDP();
		RIPv2 ripPacket = new RIPv2();
		ether.setPayload(ip);
		ip.setPayload(udpPacket);
		udpPacket.setPayload(ripPacket);

		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress("FF:FF:FF:FF:FF:FF");
		if(broadcast)
			ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		else
			ether.setDestinationMACAddress(inIface.getMacAddress().toBytes());

		ip.setTtl((byte)64);
		ip.setVersion((byte)4);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		if(broadcast)
			ip.setDestinationAddress("224.0.0.9");
		else
			ip.setDestinationAddress(inIface.getIpAddress());

		udpPacket.setSourcePort(UDP.RIP_PORT);
		udpPacket.setDestinationPort(UDP.RIP_PORT);

		ripPacket.setCommand(isRequest ? RIPv2.COMMAND_REQUEST : RIPv2.COMMAND_RESPONSE);

		for (RouteEntry entry : this.routeTable.getAll())
		{
			int address = entry.getDestinationAddress();
			int mask = entry.getMaskAddress();
			int next = inIface.getIpAddress();
			int cost = entry.getCost();

			RIPv2Entry ripEntry = new RIPv2Entry(address, mask, cost);
			ripEntry.setNextHopAddress(next);
			ripPacket.addEntry(ripEntry);
		}

		ether.serialize();
		this.sendPacket(ether, inIface);
		return;
	}
	private void handleRip(Ethernet etherPacket, Iface inIface)
	{
		// Check headers for conformance with RIPv2
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		IPv4 ip = (IPv4)etherPacket.getPayload();
		if (ip.getProtocol() != IPv4.PROTOCOL_UDP)
		{ return; }
		UDP UdpData = (UDP)ip.getPayload();
		// Verify UDP checksum
		short origCksum = UdpData.getChecksum();
		UdpData.resetChecksum();
		byte[] serialized = UdpData.serialize();
		UdpData.deserialize(serialized, 0, serialized.length);
		short calcCksum = UdpData.getChecksum();
		if (origCksum != calcCksum)
		{ return; }
		// Verify UDP port
		if (UdpData.getDestinationPort() != UDP.RIP_PORT)
		{ return; }

		RIPv2 rip = (RIPv2)UdpData.getPayload();
		if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
			if (etherPacket.getDestinationMAC().toLong() == MACAddress.valueOf("FF:FF:FF:FF:FF:FF").toLong() && ip.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9")) {
				this.sendRip(inIface, true, false);
				return;
			}
		}
		boolean updated = false;

		for (RIPv2Entry ripEntry : rip.getEntries()) {
			int address = ripEntry.getAddress();
			int mask = ripEntry.getSubnetMask();
			int cost = ripEntry.getMetric() + 1;
			int next = ripEntry.getNextHopAddress();

			ripEntry.setMetric(cost);
			RouteEntry entry = this.routeTable.lookup(address);

			if (null == entry || entry.getCost() > cost) {
				this.routeTable.insert(address, next, mask, inIface, cost);
				for (Iface ifaces : this.interfaces.values()) {
					this.sendRip(inIface, false, false);
				}
			}
		}
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
			System.out.println("TTL = 0");
			sendICMPPacket(11, 0, inIface, ipPacket);
			return;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values())
		{
			if (ipPacket.getDestinationAddress() == iface.getIpAddress())
			{
				// (1) If a TCP or UDP header comes after the IP header
				if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP || ipPacket.getProtocol() == IPv4.PROTOCOL_UDP){
					sendICMPPacket(3, 3, inIface, ipPacket);
				}
				// (2) If an ICMP header comes after the IP header
				else if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
					ICMP icmpPacket = (ICMP) ipPacket.getPayload();
					//  If the ICMP message is an echo request (used by ping)
					if (icmpPacket.getIcmpType() == (byte) 8){
						// handle ICMP echo request
						handleIcmpEchoRequest(ipPacket, icmpPacket, inIface);
					}
				}
				else if(protocol == IPv4.PROTOCOL_UDP) {
					UDP udpPacket = new UDP();
					udpPacket = (UDP)ipPacket.getPayload();
					if (udpPacket.getDestinationPort() == UDP.RIP_PORT) {
						this.handleRip(etherPacket, inIface);
					} else {
						this.sendICMPPacket(3,3, inIface, ipPacket);
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
			System.out.println("no entry matched in the route table");
			sendICMPPacket(3, 0, inIface, ipPacket);
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface)
		{ return;
		}

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
			ARP arp = new ARP();
			arp = generateArpRequest(etherPacket, inIface, nextHop);

			final AtomicReference<Ethernet> atomicEtherPacket = new AtomicReference(new Ethernet());
			final AtomicReference<Iface> atomicIface = new AtomicReference(outIface);
			final AtomicReference<Ethernet> atomicInPacket = new AtomicReference(etherPacket);

			atomicEtherPacket.get().setEtherType(Ethernet.TYPE_ARP);
			atomicEtherPacket.get().setSourceMACAddress(inIface.getMacAddress().toBytes());

			atomicEtherPacket.get().setPayload(arp);
			atomicEtherPacket.get().setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
			atomicEtherPacket.get().serialize();

			Integer next = new Integer(nextHop);

			if(!packetQueues.containsKey(next)){
				packetQueues.put(next, new LinkedList());
				System.out.println("making new one");
			}
			Queue nextHopQueue = packetQueues.get(next);
			nextHopQueue.add(etherPacket);
			final AtomicReference<Queue> atomicQueue = new AtomicReference(nextHopQueue);

			//System.out.println("Sending packets for: "+nextHop);
			final int nextH = nextHop;

			Thread waitForReply = new Thread(new Runnable(){


				public void run() {

					try {
						System.out.println("Sending ARP PACKET********\n"+atomicEtherPacket.get()+"\n*******************");
						sendPacket(atomicEtherPacket.get(), atomicIface.get());
						//System.out.println("1) Checking for "+nextH);
						Thread.sleep(1000);
						if(arpCache.lookup(nextH) != null){
							System.out.println("Found it!");
							return;
						}
						System.out.println("Sending ARP PACKET********\n"+atomicEtherPacket.get()+"\n*******************");
						sendPacket(atomicEtherPacket.get(), atomicIface.get());
						//System.out.println("2) Checking again for" + nextH);
						Thread.sleep(1000);
						if(arpCache.lookup(nextH) != null){
							System.out.println("Found it!");
							return;
						}
						System.out.println("Sending ARP PACKET********\n"+atomicEtherPacket.get()+"\n*******************");
						sendPacket(atomicEtherPacket.get(), atomicIface.get());
						//System.out.println("3) Checking again for" + nextH);
						Thread.sleep(1000);
						if(arpCache.lookup(nextH) != null){
							System.out.println("Found it!");
							return;
						}

						while(atomicQueue.get() != null && atomicQueue.get().peek() != null){
							atomicQueue.get().poll();
						}
						sendICMPPacket(3,1, inIface, ipPacket);
						return;
					} catch(InterruptedException v) {
						System.out.println(v);
					}
				}
			});
			waitForReply.start();
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}
	private ARP generateArpRequest(Ethernet etherPacket, Iface inIface, int nextHop){
		ARP arp = new ARP();

		// Set ARP Header
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte) 4);
		arp.setOpCode(ARP.OP_REQUEST);

		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());

		arp.setTargetHardwareAddress(ByteBuffer.allocate(8).putInt(0).array());
		arp.setTargetProtocolAddress(nextHop);
		return arp;
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
}
