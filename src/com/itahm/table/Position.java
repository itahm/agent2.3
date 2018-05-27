package com.itahm.table;

import java.io.File;
import java.io.IOException;

import com.itahm.json.JSONObject;

public class Position extends Table {
	
	public Position(File dataRoot) throws IOException {
		super(dataRoot, Name.POSITION);
	}
	
	@Override
	public JSONObject save(JSONObject data) throws IOException {
		for (Object key : data.keySet()) {
			String ip = (String)key;
			
			super.table.put(ip, data.getJSONObject(ip));
		}
		
		return super.save();
	}

}
