package com.itahm.command;

import java.io.IOException;

import com.itahm.json.JSONObject;

import com.itahm.http.Request;
import com.itahm.http.Response;

public interface Command {
	public Response execute(Request request, JSONObject data) throws IOException;
}
