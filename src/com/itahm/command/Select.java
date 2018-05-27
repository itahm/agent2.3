package com.itahm.command;

import java.io.IOException;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;

import com.itahm.Agent;
import com.itahm.http.Request;
import com.itahm.http.Response;

public class Select implements Command {
	
	@Override
	public Response execute(Request request, JSONObject data) throws IOException {
		try {
			JSONObject nodeData = Agent.getNodeData(data.getString("ip"), data.has("offline"));
			
			if (nodeData == null) {
				return Response.getInstance(Response.Status.BADREQUEST,
					new JSONObject().put("error", "node not found").toString());
			}
			
			String body;
			
			// nodeData 변경가능성 있기 때문에 동기화
			synchronized(nodeData) {
				body = nodeData.toString();
			}
			
			return Response.getInstance(Response.Status.OK, body);
		}
		catch(NullPointerException npe) {
			return Response.getInstance(Response.Status.UNAVAILABLE);
		}
		catch (JSONException jsone) {
			return Response.getInstance(Response.Status.BADREQUEST,
					new JSONObject().put("error", "invalid json request").toString());
		}
	}
	
}
