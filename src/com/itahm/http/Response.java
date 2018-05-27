package com.itahm.http;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Response {

	public final static String CRLF = "\r\n";
	public final static String FIELD = "%s: %s"+ CRLF;
	
	private final Map<String, String> header = new HashMap<String, String>();
	private String startLine;
	private byte [] body;
	
	public enum Status {
		OK(200, "OK"),
		BADREQUEST(400, "Bad request"),
		UNAUTHORIZED(401, "Unauthorized"),
		NOTFOUND(404, "Not found"),
		NOTALLOWED(405, "Method Not Allowed"),
		CONFLICT(409, "Conflict"),
		SERVERERROR(500, "Internal Server Error"),
		UNAVAILABLE(503, "Service Unavailable"),
		VERSIONNOTSUP(505, "HTTP Version Not Supported");
		
		private final int code;
		private final String text;
		
		private Status(int code, String text) {
			this.code = code;
			this.text = text;
		}
		
		public int getCode() {
			return this.code;
		}
		
		public String getText() {
			return this.text;
		}
		
		public static Status valueOf(int code) {
			for (Status status : Status.values()) {
				if (status.getCode() == code) {
					return status;
				}
			}
			
			return null;
		}
	};
	
	private Response(Status status, byte [] body) {
		if (status.equals(Status.NOTALLOWED)) {
			setResponseHeader("Allow", "GET");
		}
		
		this.startLine = String.format("HTTP/1.1 %d %s" +CRLF, status.getCode(), status.getText());
		
		this.body = body;
	}
	
	/**
	 * 
	 * @param request
	 * @param status
	 * @param body
	 * @return
	 * 
	 */
	public static Response getInstance(Status status, String body) {
		try {
			return new Response(status, body.getBytes(StandardCharsets.UTF_8.name()));
		} catch (UnsupportedEncodingException e) {
			return null;
		}
	}
	
	/**
	 * 
	 * @param status
	 * @return
	 */
	public static Response getInstance(Status status) {
		return new Response(status, new byte[0]);
	}
	
	/**
	 * 
	 * @param url
	 * @return
	 * @throws IOException
	 */
	public static Response getInstance(File url) throws IOException {
		Path path = url.toPath();
		
		return new Response(Status.OK, Files.readAllBytes(path))
			.setResponseHeader("Content-type", Files.probeContentType(path));
	}
	
	public Response setResponseHeader(String name, String value) {
		this.header.put(name, value);
		
		return this;
	}
	
	public ByteBuffer build() throws IOException {
		if (this.startLine == null || this.body == null) {
			throw new IOException("malformed http request!");
		}
		
		StringBuilder sb = new StringBuilder();
		Iterator<String> iterator;		
		String key;
		byte [] header;
		byte [] message;
		
		sb.append(this.startLine);
		sb.append(String.format(FIELD, "Content-Length", String.valueOf(this.body.length)));
		
		iterator = this.header.keySet().iterator();
		while(iterator.hasNext()) {
			key = iterator.next();
			
			sb.append(String.format(FIELD, key, this.header.get(key)));
		}
		
		sb.append(CRLF);
		
		header = sb.toString().getBytes(StandardCharsets.US_ASCII.name());
		
		message = new byte [header.length + this.body.length];
		
		System.arraycopy(header, 0, message, 0, header.length);
		System.arraycopy(this.body, 0, message, header.length, this.body.length);
		
		return ByteBuffer.wrap(message);
	}
	
}
