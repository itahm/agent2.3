package com.itahm.table;

import java.io.File;
import java.io.IOException;

import com.itahm.json.JSONException;
import com.itahm.table.Table;

public class Config extends Table {

	public Config(File dataRoot) throws IOException {
		super(dataRoot, Name.CONFIG);
		
		boolean save = false;
		
		try {
			super.table.getInt("clean");
		}
		catch (JSONException jsone) {
			super.table.put("clean", 0);
		
			save = true;
		}
		
		try {
			super.table.getInt("interval");
		}
		catch (JSONException jsone) {
			super.table.put("interval", 1);
		
			save = true;
		}
		
		
		if (save) {
			super.save();
		}
	}
	
}
