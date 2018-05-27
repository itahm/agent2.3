package com.itahm.icmp;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class ICMPNode implements Runnable, Closeable {

	private final ICMPListener listener;
	private final InetAddress target;
	private final Thread thread;
	private final int [] timeouts;
	private final int retry;
	private final BlockingQueue<Long> bq = new LinkedBlockingQueue<>();
	
	public final String ip;
	
	public ICMPNode(ICMPListener listener, String ip, int [] timeouts) throws UnknownHostException {
		this.listener = listener;
		this.ip = ip;
		this.timeouts = timeouts;
		
		target = InetAddress.getByName(ip);
		retry = timeouts.length;
		
		thread = new Thread(this);
		
		thread.setName("ITAhM ICMPNode "+ ip);
		
		thread.start();
	}
	
	@Override
	public void run() {
		long delay, sent;
		
		init: while (!this.thread.isInterrupted()) {
			try {
				try {
					delay = this.bq.take();
					
					if (delay > 0) {
						Thread.sleep(delay);
					}
					else if (delay < 0) {
						throw new InterruptedException();
					}
					
					sent = System.currentTimeMillis();
					
					for (int i=0; i < retry; i++) {
						if (this.thread.isInterrupted()) {
							throw new InterruptedException();
						}
						
						if (this.target.isReachable(timeouts[i])) {
							this.listener.onSuccess(this, System.currentTimeMillis() - sent);
							
							continue init;
						}
					}
					
				} catch (IOException e) {}
				
				this.listener.onFailure(this);
				
			} catch (InterruptedException e) {
				
				break;
			}
		}
	}
	
	public void ping(long delay) {
		try {
			this.bq.put(delay);
		} catch (InterruptedException e) {
		}
	}

	public void close(boolean gracefully) throws IOException {
		close();
		
		if (gracefully) {
			try {
				this.thread.join();
			} catch (InterruptedException e) {}
		}
	}
	
	@Override
	public void close() throws IOException {
		this.thread.interrupt();
		
		try {
			this.bq.put(-1L);
		} catch (InterruptedException ie) {}
	}
	
	public static void main(String [] args) throws IOException {
		ICMPNode node = new ICMPNode(new ICMPListener() {
			@Override
			public void onSuccess(ICMPNode node, long time) {
				System.out.println("success");
			}

			@Override
			public void onFailure(ICMPNode node) {
				System.out.println("failure");
			}
		}, "192.168.0.100", new int [] {1000, 1000, 1000, 1000, 1000});
		
		root: while (true) {
			switch (System.in.read()) {
			case 'p':
				node.ping(0);
				break;
			case 'c':
				node.close();
			case 'x':
				break root;
			}
		}
		
	}
	
}
