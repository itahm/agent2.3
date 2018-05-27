package com.itahm.util;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Iterator;

public class Network {

	private int network = 0;
	private int mask = 0;
	private int start; 
	private int remains;
	
	public Network(byte [] network, int mask) throws IOException {
		int count = 0;
		
		for (int i=0, _i=network.length; i<_i; i++) {
			this.network = this.network << 8;
			this.network |= 0xff&network[i];
		}
		
		while(count++ < mask) {
			this.mask <<= 1;
			this.mask++;
		}
		
		while(mask++ < 32) {
			this.mask <<= 1;
		}
		
		this.network &= this.mask;
	}
	
	public Network(String network, int mask) throws IOException {
		this(InetAddress.getByName(network).getAddress(), mask);
		
	}
	
	public static void main(String[] args) throws IOException {
		Network n = new Network("192.168.0.0", 24);
		Iterator<String> it = n.iterator();
		
		while(it.hasNext()) {
		}
	}
	
	private String toIPString(long ip) {
		return (0xff&(ip >>> 24))+"."+(0xff&(ip >>> 16))+"."+(0xff&(ip >>> 8))+"."+(0xff&ip);
	}
	
	public Iterator<String> iterator() {
		this.start = this.network +1;
		this.remains = ~this.mask -1;
		
		return new Iterator<String> () {
			
			@Override
			public boolean hasNext() {
				return remains > 0;
			}

			@Override
			public String next() {
				remains--;
				
				return toIPString(start++);
			}
		};
	}
	

}
