package com.itahm.command;

import java.io.IOException;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;

import com.itahm.Agent;
import com.itahm.table.Table;
import com.itahm.http.Request;
import com.itahm.http.Response;

public class Push implements Command {
	
	@Override
	public Response execute(Request request, JSONObject data) throws IOException {
		try {
			Table table = Agent.getTable(data.getString("database"));
			
			if (table == null) {
				return Response.getInstance(Response.Status.BADREQUEST,
					new JSONObject().put("error", "database not found").toString());
			}
			else {
				table.save(data.getJSONObject("data"));
				
				return Response.getInstance(Response.Status.OK);
			}
		}
		catch (JSONException jsone) {
			return Response.getInstance(Response.Status.BADREQUEST,
				new JSONObject().put("error", "invalid json request").toString());
		}
	}
	
}
