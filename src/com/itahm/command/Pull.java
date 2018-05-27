package com.itahm.command;

import java.io.IOException;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;

import com.itahm.table.Table;
import com.itahm.table.Config;
import com.itahm.Agent;
import com.itahm.http.Request;
import com.itahm.http.Response;

public class Pull implements Command {
	
	@Override
	public Response execute(Request request, JSONObject data) throws IOException {
		try {
			Table table = Agent.getTable(data.getString("database"));
			
			if (table == null) {
				return Response.getInstance(Response.Status.BADREQUEST,
					new JSONObject().put("error", "database not found").toString());
			}
			else {
				JSONObject json = table.getJSONObject();
				String body;
				
				if (table instanceof Config) {
					Agent.getInformation(json);
				}
				
				synchronized(json) {
					body = json.toString();
				}
				
				return Response.getInstance(Response.Status.OK, body);
			}
		}
		catch (JSONException jsone) {
			return Response.getInstance(Response.Status.BADREQUEST,
				new JSONObject().put("error", "invalid json request").toString());
		}
	}
	
}
