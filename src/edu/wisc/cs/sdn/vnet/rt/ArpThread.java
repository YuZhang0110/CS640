package edu.wisc.cs.sdn.vnet.rt;

import java.util.*;

import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.packet.ARP;
import edu.wisc.cs.sdn.vnet.Iface;

class ArpThread implements Runnable{
	private Ethernet arpReq,arpReply;
	private Iface arpRepIface, arpReqIface;
	private Router rt;
	private Queue<QueueElement> waiting;
	
	private class QueueElement{
		public Ethernet eth;
		public byte[] srcMac;
		public Iface iface;
		public QueueElement(Ethernet eth,byte[] srcMac,Iface inface){
			this.eth=eth;
			this.srcMac=srcMac;	
			this.iface=inface;
		}
	}
	
	public boolean succ;
	public int IP;
	
	public ArpThread(Ethernet arpReq, Iface arpReqIface, Router rt,int IP) {
		this.arpReq=arpReq;
		this.arpReqIface=arpReqIface;
		this.rt=rt;
		this.IP=IP;
		succ=false;		
		waiting=new LinkedList<QueueElement>();
	}
	
	public void setReply(Ethernet arpReply, Iface arpRepIface){
		this.arpRepIface=arpRepIface;
		this.arpReply=arpReply;
		succ=true;
	}
	
	public void add(Ethernet eth,byte[] srcMac,Iface iface){
		waiting.add(new QueueElement(eth,srcMac,iface));
	}
	
	public void run() {
		try {
		//Send 3 ARP requests in one second intervals
			if(succ == false){
				rt.sendPacket(arpReq, arpReqIface);
				//wait 1 second, should not be interrupted
				Thread.sleep(1000);
				System.out.println("Sending ARP PACKET IP: "+IP);
			}
			if(succ == false){
				rt.sendPacket(arpReq, arpReqIface);
				//wait 1 second, should not be interrupted
				Thread.sleep(1000);
				System.out.println("Sending ARP PACKET IP: "+IP);
			}
			if(succ == false){
				rt.sendPacket(arpReq, arpReqIface);
				//wait 1 second, should not be interrupted
				Thread.sleep(1000);
				System.out.println("Sending ARP PACKET IP: "+IP);
			}
		} catch(InterruptedException v) {
			System.out.println(v);
		}


		//If the ARP reply made it in time, forward the queued packets to their next hop
		if(arpReply!=null) {
			ARP arp=(ARP) arpReply.getPayload();
			System.out.println("IP: "+IP+" get reply from"+Arrays.toString(arp.getSenderHardwareAddress()));
			while(!waiting.isEmpty())
			{
				QueueElement tmp=waiting.poll();
				Ethernet ether=tmp.eth;
				ether.setDestinationMACAddress(arp.getSenderHardwareAddress());
				//send the packets forward
				rt.sendPacket(ether, arpRepIface);
			}
		} else {//Else reply back with ICMP Dest Host Unreachable to each of the hosts who send a packet for this IP
			while(!waiting.isEmpty()) {
				waiting.poll();
			}
		}
		return;
	}
}