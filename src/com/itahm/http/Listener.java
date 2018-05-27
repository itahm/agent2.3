package com.itahm.http;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.Timer;

public abstract class Listener extends Timer implements Runnable, Closeable {
	
	private final static int BUF_SIZE = 2048;
	
	private final ServerSocketChannel channel;
	private final ServerSocket listener;
	private final Selector selector;
	private final ByteBuffer buffer;
	private final Set<Request> connections = new HashSet<Request>();
	
	private Boolean closed = false;
	
	public Listener() throws IOException {
		this("0.0.0.0", 80);
	}  

	public Listener(String ip) throws IOException {
		this(ip, 80);
	}
	
	public Listener(int tcp) throws IOException {
		this("0.0.0.0", tcp);
	}
	
	public Listener(String ip, int tcp) throws IOException {
		this(new InetSocketAddress(InetAddress.getByName(ip), tcp));
	}
	
	public Listener(InetSocketAddress addr) throws IOException {
		channel = ServerSocketChannel.open();
		listener = channel.socket();
		selector = Selector.open();
		buffer = ByteBuffer.allocateDirect(BUF_SIZE);
		
		listener.bind(addr);
		channel.configureBlocking(false);
		channel.register(selector, SelectionKey.OP_ACCEPT);
		
		Thread t = new Thread(this);
		
		t.setName("ITAhM HTTP Listener");
		
		t.start();
		
		onStart();
	}
	
	private void onConnect() throws IOException {
		SocketChannel channel = null;
		Request request;
		
		try {
			channel = this.channel.accept();
			request = new Request(channel, this);
			
			channel.configureBlocking(false);
			channel.register(this.selector, SelectionKey.OP_READ, request);
			
			connections.add(request);
		} catch (IOException ioe) {
			if (channel != null) {
				channel.close();
			}
			
			throw ioe;
		}
	}
	
	private void onRead(SelectionKey key) throws IOException {
		SocketChannel channel = (SocketChannel)key.channel();
		Request request = (Request)key.attachment();
		int bytes = 0;
		
		this.buffer.clear();
		
		bytes = channel.read(buffer);
		
		if (bytes == -1) {
			closeRequest(request);
		}
		else if (bytes > 0) {
			this.buffer.flip();
				
			request.parse(this.buffer);
		}
	}

	public void closeRequest(Request request) throws IOException {
		request.close();
		
		connections.remove(request);
		
		onClose(request);
	}
	
	public int getConnectionSize() {
		return connections.size();
	}
	
	@Override
	public void close() throws IOException {
		synchronized (this.closed) {
			if (this.closed) {
				return;
			}
		
			this.closed = true;
		}
		
		for (Request request : connections) {
			request.close();
		}
			
		connections.clear();
		
		super.cancel();
		
		this.selector.wakeup();
	}

	@Override
	public void run() {
		Iterator<SelectionKey> iterator = null;
		SelectionKey key = null;
		int count;
		
		while(!this.closed) {
			try {
				count = this.selector.select();
			} catch (IOException ioe) {
				ioe.printStackTrace();
				
				continue;
			}
			
			if (count > 0) {
				iterator = this.selector.selectedKeys().iterator();
				while(iterator.hasNext()) {
					key = iterator.next();
					iterator.remove();
					
					if (!key.isValid()) {
						continue;
					}
					
					if (key.isAcceptable()) {
						try {
							onConnect();
						} catch (IOException ioe) {
							ioe.printStackTrace();
						}
					}
					else if (key.isReadable()) {
						try {
							onRead(key);
						}
						catch (IOException ioe) {
							try {
								closeRequest((Request)key.attachment());
							} catch (IOException ioe2) {
								ioe2.printStackTrace();
							}
							
							onException(ioe);
						}
					}
				}
			}
		}
		
		try {
			this.selector.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
		try {
			this.listener.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
	
	abstract protected void onStart();
	abstract protected void onRequest(Request request)  throws IOException;
	abstract protected void onClose(Request request);
	abstract protected void onException(Exception e);
	
	public static void main(String [] args) throws IOException, InterruptedException {
		final Listener server = new Listener(20114) {

			@Override
			protected void onRequest(Request request) {
				
				String uri = request.getRequestURI();
				String method = request.getRequestMethod();
				Response response;
				
				if (!"HTTP/1.1".equals(request.getRequestVersion())) {
					response = Response.getInstance(Response.Status.VERSIONNOTSUP);
				}
				else {
					if (method.toLowerCase().equals("get")) {
						if ("/".equals(uri)) {
							uri = "/index.html";
						}
						
						try {
							response = Response.getInstance(new File("."+ uri));
							if (response == null) {
								throw new IOException();
							}
						} catch (IOException e) {
							response = Response.getInstance(Response.Status.NOTFOUND);
						}
					}
					else {
						response = Response.getInstance(Response.Status.NOTALLOWED);
					}
				}
				
				try {
					request.sendResponse(response);
				} catch (IOException e) {
				}
			}

			@Override
			protected void onClose(Request request) {
			}

			@Override
			protected void onStart() {				
			}

			@Override
			protected void onException(Exception e) {
			}

		};
		
		Socket s = new Socket("127.0.0.1", 20114);
			
			try (OutputStream os = s.getOutputStream()) {
				s.setSoLinger(true, 0);
			}
		s.close();
		
		System.in.read();
		
		server.close();
	}
	
}
