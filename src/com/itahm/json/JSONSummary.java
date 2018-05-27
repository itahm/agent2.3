package com.itahm.json;

import java.io.File;
import java.io.IOException;

import com.itahm.json.JSONObject;
import com.itahm.util.Util;

public class JSONSummary extends Data {
	
	public JSONSummary(File f) {
		super(f);
	}

	@Override
	public void buildNext(File dir) {
		File file = new File(dir, "summary");
		
		if (file.isFile()) {
			try {	
				JSONObject data = Util.getJSONFromFile(file);
				
				if (data != null) {
					for (Object key : data.keySet()) {
						super.put((String)key, data.getJSONObject((String)key));
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}	
}
