package com.itahm.json;

import java.io.File;
import java.io.IOException;

import com.itahm.json.JSONObject;
import com.itahm.util.Util;

public class JSONData extends Data{

	public JSONData(File f) {
		super(f);
		// TODO Auto-generated constructor stub
	}
	
	@Override
	public void buildNext(File dir) throws IOException {
		File [] fa = dir.listFiles();
		
		if (fa == null) {
			return;
		}
		
		JSONObject data;
		
		for (File f : fa) {
			try {
				Long.valueOf(f.getName());
				
				data = Util.getJSONFromFile(f);
			
				if (data != null) {
					for (Object key : data.keySet()) {
						super.put((String)key, data.getLong((String)key));
					}
				}
			}
			catch (NumberFormatException nfe) {} 
		}
	}
	
	public static void main(String [] args) throws IOException {
		File root = new File(".");
		
		new JSONData(root).buildNext(new File(args[0]));
	}
}
