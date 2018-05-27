package com.itahm.command;

import java.io.IOException;

import com.itahm.json.JSONObject;

import com.itahm.Agent;
import com.itahm.http.Request;
import com.itahm.http.Response;

public class Listen implements Command {
	
	@Override
	public Response execute(Request request, JSONObject data) throws IOException {
		long index = data.has("index")? data.getInt("index"): -1;
		
		Agent.listen(request, index);
		
		return null;
	}
	
}
