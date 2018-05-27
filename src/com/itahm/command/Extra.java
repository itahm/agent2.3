package com.itahm.command;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Iterator;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.Agent;
import com.itahm.http.Request;
import com.itahm.http.Response;
import com.itahm.util.Network;

public class Extra implements Command {
	
	private static final int DEF_TOP_CNT = 10;
	
	@Override
	public Response execute(Request request, JSONObject data) throws IOException {
		
		try {
			switch(data.getString("extra")) {
			case "reset":
				Agent.resetResponse(data.getString("ip"));
				
				return Response.getInstance(Response.Status.OK);
			case "failure":
				JSONObject json = Agent.getFailureRate(data.getString("ip"));
				
				if (json == null) {
					return Response.getInstance(Response.Status.BADREQUEST,
						new JSONObject().put("error", "node not found").toString());
				}
				
				return Response.getInstance(Response.Status.OK, json.toString());
			case "search":
				Network network = new Network(InetAddress.getByName(data.getString("network")).getAddress(), data.getInt("mask"));
				Iterator<String> it = network.iterator();
				
				while(it.hasNext()) {
					Agent.testSNMPNode(it.next(), null);
				}
				
				return Response.getInstance(Response.Status.OK);
			case "message":
				Agent.sendEvent(data.getString("message"));
				
				return Response.getInstance(Response.Status.OK);
			case "top":
				return Response.getInstance(Response.Status.OK,
					Agent.getTop(data.has("count")? data.getInt("count"): DEF_TOP_CNT).toString());
			
			case "log":
				return Response.getInstance(Response.Status.OK,
					Agent.getLog(data.getLong("date")));
			
			case "syslog":
				return Response.getInstance(Response.Status.OK,
					new JSONObject().put("log", Agent.getSyslog(data.getLong("date"))).toString());
			
			case "report":
				return Response.getInstance(Response.Status.OK,
					Agent.report(data.getLong("start"), data.getLong("end")));
			
			case "backup":
				return Response.getInstance(Response.Status.OK,
					Agent.backup().toString());
				
			case "restore":
				Agent.restore(data.getJSONObject("backup"));
				
				return Response.getInstance(Response.Status.OK);
				
			case "test":
				return Response.getInstance(Response.Status.OK,
					Agent.snmpTest().toString());
			
			case "critical":
				Agent.setCritical(data.has("target")? data.getString("target"): null,
					data.has("resource")? data.getString("resource"): null,
					data.getInt("rate"),
					data.getBoolean("overwrite"));
				
				return Response.getInstance(Response.Status.OK);
				
			default:
				return Response.getInstance(Response.Status.BADREQUEST,
					new JSONObject().put("error", "invalid extra").toString());	
			}
		}
		catch (JSONException jsone) {
			return Response.getInstance(Response.Status.BADREQUEST,
				new JSONObject().put("error", "invalid json request").toString());
		}
		catch (Exception e) {
			return Response.getInstance(Response.Status.UNAVAILABLE,
				new JSONObject().put("error", e.getMessage()).toString());
		}
	}

}
