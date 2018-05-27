package com.itahm.table;

import java.io.File;
import java.io.IOException;

import com.itahm.Agent;
import com.itahm.json.JSONObject;

public class Profile extends Table {
	
	public Profile(File dataRoot) throws IOException {
		super(dataRoot, Name.PROFILE);
		
		if (isEmpty()) {
			getJSONObject()
				.put("default", new JSONObject()
					.put("udp", 161)
					.put("community", "public")
					.put("version", "v2c"));
		
			super.save();
		}
	}
	
	private void removeProfile(JSONObject profile) {
		if ("v3".equals(profile.getString("version"))) {
			Agent.removeUSM(profile.getString("user"));
		}
	}
	
	public JSONObject put(String name, JSONObject profile) throws IOException {
		boolean success = true;
		
		// 삭제
		if (profile == null) {
			if (super.table.has(name) && Agent.isIdleProfile(name)) {
				removeProfile(super.table.getJSONObject(name));
			}
			else {
				success = false;
			}
		}
		// 변경은 불가
		else if (super.table.has(name)) {
			success = false;
		}
		// v3 추가
		else if ("v3".equals(profile.getString("version"))) {
			success = Agent.addUSM(profile);
			
		}
		// else v1, v2c 추가
		
		return success? super.put(name, profile): super.table;
	}
}
