package com.itahm.http;

public class HTTPException extends RuntimeException {

	private static final long serialVersionUID = -968161410566646583L;
	private final int status;

	public HTTPException(int status) {
		this.status = status;
	}
	
	public int getStatus() {
		return this.status;
	}
}
