package com.itahm;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import com.itahm.http.Listener;
import com.itahm.http.Request;
import com.itahm.http.Response;
import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;

public class HTTPServer extends Listener {

	private final Agent agent;
	
	public HTTPServer(Agent agent, int tcp) throws IOException {
		super("0.0.0.0", tcp);
	
		this.agent = agent;
		
		System.out.format("ITAhM communicator started with TCP %d.\n", tcp);
	}

	public static void sendResponse(Request request, Response response) throws IOException {
		String origin = request.getRequestHeader(Request.Header.ORIGIN);
		
		if (origin == null || (Agent.isDemo && !Agent.isDebug) ) {
			origin = "http://itahm.com";
		}
		
		response.setResponseHeader("Access-Control-Allow-Origin", origin);
		response.setResponseHeader("Access-Control-Allow-Credentials", "true");
		
		request.sendResponse(response);
	}
	
	@Override
	protected void onStart() {
		System.out.println("HTTP Server start.");
	}

	@Override
	protected void onRequest(Request request) throws IOException {
		Response response;
		
		if (!"HTTP/1.1".equals(request.getRequestVersion())) {
			response = Response.getInstance(Response.Status.VERSIONNOTSUP);
		}
		else {
			switch(request.getRequestMethod()) {
			case "OPTIONS":
				response = Response.getInstance(Response.Status.OK).setResponseHeader("Allow", "GET, POST");
			
				break;
			case"POST":
				JSONObject data;
				
				try {
					data = new JSONObject(new String(request.getRequestBody(), StandardCharsets.UTF_8.name()));
					
					if (!data.has("command")) {
						response = Response.getInstance(Response.Status.BADREQUEST
							, new JSONObject().put("error", "command not found").toString());
					}
					else {
						response = agent.executeRequest(request, data);
					}
				} catch (JSONException e) {
					response = Response.getInstance(Response.Status.BADREQUEST
						, new JSONObject().put("error", "invalid json request").toString());
				} catch (UnsupportedEncodingException e) {
					response = Response.getInstance(Response.Status.BADREQUEST
						, new JSONObject().put("error", "UTF-8 encoding required").toString());
				}
				
				break;
			case "GET":
				String uri = request.getRequestURI();
				File file = new File(Agent.root, uri);
				
				if (!Pattern.compile("^/data/.*").matcher(uri).matches() && file.isFile()) {
					response = Response.getInstance(file);
				}
				else {
					response = Response.getInstance(Response.Status.NOTFOUND);
				}
				
				break;
			default:
				response = 	Response.getInstance(Response.Status.NOTALLOWED).setResponseHeader("Allow", "OPTIONS, POST, GET");
			}
		}
		 
		if (response != null) { /* listen인 경우 null*/
			sendResponse(request, response);
		}
	}

	@Override
	protected void onClose(Request request) {
		agent.closeRequest(request);
	}

	@Override
	protected void onException(Exception e) {
		//agent.set("log", e.getMessage());
	}

}
