package com.itahm.table;

import java.io.File;
import java.io.IOException;

import com.itahm.json.JSONObject;
import com.itahm.Agent;

public class Critical extends Table {
	
	public Critical(File dataRoot) throws IOException {
		super(dataRoot, Name.CRITICAL);
	}
	
	public JSONObject put(String ip, JSONObject critical) throws IOException {
		Agent.resetCritical(ip, critical);
		
		return super.put(ip, critical);
	}
}
