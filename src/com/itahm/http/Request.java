package com.itahm.http;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimerTask;

public class Request implements Closeable {

	public enum Header {
		ORIGIN, COOKIE;
	};
	
	public final static byte CR = (byte)'\r';
	public final static byte LF = (byte)'\n';
	public final static String GET = "GET";
	public final static String POST = "POST";
	public final static String HEAD = "HEAD";
	public final static String OPTIONS = "OPTIONS";
	public final static String DELETE = "DELETE";
	public final static String TRACE = "TRACE";
	public final static String CONNECT = "CONNECT";

	protected final Map<String, String> header = new HashMap<>();
	
	private final SocketChannel channel;
	private final Listener listener;
	private byte [] buffer;
	private TimerTask task;
	private String method;
	private String uri;
	private String version;
	private int length;
	private ByteArrayOutputStream body;
	private boolean initialized = true;
	private Boolean closed = false;
	
	public Request(SocketChannel channel, Listener listener) {
		this.channel = channel;
		this.listener = listener;
		
		setTimeout();
	}
	
	public void parse(ByteBuffer src) throws IOException {
		setTimeout();
		
		if (this.body == null) {
			String line;
			
			while ((line = readLine(src)) != null) {
				if (parseHeader(line)) {
					src.compact().flip();
					
					parseBody(src);
					
					break;
				};
			}
		}
		else {
			parseBody(src);
		}
	}
	
	public byte [] getRequestBody() {
		return this.body.toByteArray();
	}
	
	private void setTimeout() {
		final Request request = this;
		
		if (this.task != null) {
			this.task.cancel();
		}
		
		this.task = new TimerTask() {

			@Override
			public void run() {
				try {
					channel.socket().setSoLinger(true, 0);
				} catch (SocketException se) {
					se.printStackTrace();
				}
				
				try {
					listener.closeRequest(request);
				} catch (IOException ioe) {
					ioe.printStackTrace();
				}
			}
		};
		
		Calendar c = Calendar.getInstance();
		
		c.add(Calendar.HOUR, 1);
		this.listener.schedule(this.task, c.getTime());
	}
	
	private void parseBody(ByteBuffer src) throws IOException {
		byte [] bytes = new byte[src.limit()];
		int length;
		
		src.get(bytes);
		this.body.write(bytes);
		
		length = this.body.size();
		if (this.length == length) {
			this.listener.onRequest(this);
			
			this.body = null;
			this.initialized = true;
		}
		else if (this.length < length){
			throw new IOException("malformed http request");
		}
		
	}
	
	private boolean parseHeader(String line) throws IOException {
		if (this.initialized) {
			parseStartLine(line);
			
			this.initialized = false;
		}
		else {
			if ("".equals(line)) {			
				String length = this.header.get("content-length");
				
				try {
					this.length = Integer.parseInt(length);
				} catch (NumberFormatException nfe) {
					this.length = 0;
				}
				
				this.body = new ByteArrayOutputStream();
				
				return true;
			}
			else {
				int index = line.indexOf(":");
				
				if (index == -1) {
					throw new IOException("malformed http request");
				}
				
				this.header.put(line.substring(0, index).toLowerCase(), line.substring(index + 1).trim());
			}
		}
		
		return false;
	}
	
	private void parseStartLine(String line) throws IOException {
		if (line.length() == 0) {
			//규약에 의해 request-line 이전의 빈 라인은 무시한다.
			return;
		}
		
		String [] token = line.split(" ");
		if (token.length != 3) {
			throw new IOException("malformed http request");
		}
		
		this.method = token[0];
		this.uri = token[1];
		
		int i = this.uri.indexOf("?");
		
		if (i != -1) {
			this.uri = this.uri.substring(0, i);
		}
		
		this.version = token[2];
		
		this.header.clear();
	}
	
	private String readLine(ByteBuffer src) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		if (this.buffer != null) {
			baos.write(this.buffer);
			
			this.buffer = null;
		}
		
		int b;
		
		while(src.hasRemaining()) {
			b = src.get();
			baos.write(b);
			
			if (b == LF) {
				String line = readLine(baos.toByteArray());
				if (line != null) {
					return line;
				}
			}
		}
		
		this.buffer = baos.toByteArray();
		
		return null;
	}
	
	public static String readLine(byte [] src) throws IOException {
		int length = src.length;
		
		if (length > 1 && src[length - 2] == CR) {
			return new String(src, 0, length -2);
		}
		
		return null;
	}
	
	public String getRequestMethod() {
		return this.method;
	}
	
	public String getRequestURI() {
		return this.uri;
	}
	
	public String getRequestVersion() {
		return this.version;
	}
	
	public String getRequestHeader(Header name) {
		return this.header.get(name.toString().toLowerCase());
	}
	
	public boolean sendResponse(Response response) throws IOException {
		synchronized(closed) {
			if (closed) {
				return false;
			}

			ByteBuffer message = response.build();
			
			while(message.remaining() > 0) {			
				this.channel.write(message);
			}
		}
		
		return true;
	}

	@Override
	public void close() throws IOException {
		synchronized(closed) {
			if (closed) {
				return;
			}
			
			closed = true;
		}

		try {
			this.channel.close();
		}
		finally {
			if (this.task != null) {
				this.task.cancel();
			}
		}
	}
	
}
