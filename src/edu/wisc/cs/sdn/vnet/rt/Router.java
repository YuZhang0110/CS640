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
		{ return; }

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values())
		{
			if (ipPacket.getDestinationAddress() == iface.getIpAddress())
			{ return; }
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
}
