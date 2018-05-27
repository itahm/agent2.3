package com.itahm.command;

import java.io.IOException;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.Agent;
import com.itahm.http.Request;
import com.itahm.http.Response;

public class Config implements Command {
	
	@Override
	public Response execute(Request request, JSONObject data) throws IOException {
		try {
			final String key = data.getString("key");
			
			switch(key) {
			case "clean":
				Agent.config(key, data.getInt("value"));
				
				Agent.clean();
				
				break;
			
			case "dashboard":
				Agent.config(key, data.getJSONObject("value"));
				
				break;
			case "display":
				Agent.config(key, data.getString("value"));
				
				break;
			case "sms":
			case "menu":
				Agent.config(key, data.getBoolean("value"));
				
				break;
			case "interval":
			case "top":
				Agent.config(key, data.getInt("value"));
			
				break;
			case "iftype":
				String iftype = data.getString("value");
				
				Agent.config(key, iftype);
			
				Agent.setValidIFType(iftype);
				break;
			default:
				Agent.config(key, data.getString("value"));
			}
			
			return Response.getInstance(Response.Status.OK);
		}
		catch (JSONException jsone) {
			return Response.getInstance(Response.Status.BADREQUEST,
				new JSONObject().put("error", "invalid json request").toString());
		}
	}
	
}
