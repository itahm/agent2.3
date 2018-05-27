package com.itahm.command;

import java.io.IOException;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.Agent;
import com.itahm.http.Request;
import com.itahm.http.Response;

public class Query implements Command {
	
	@Override
	public Response execute(Request request, JSONObject data) throws IOException {
		
		try {
			data = Agent.getNodeData(data);
			
			if (data == null) {
				return Response.getInstance(Response.Status.BADREQUEST,
					new JSONObject().put("error", "node or data not found").toString());
			}
			
			// data는 새로 만들어진 것이기에 toString시 동기화 불필요
			return Response.getInstance(Response.Status.OK, data.toString());
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
