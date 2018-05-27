package com.itahm.table;

import java.io.File;
import java.io.IOException;

import com.itahm.json.JSONObject;
import com.itahm.util.Util;

public class Table {
	public enum Name {
		ACCOUNT("account"),
		CRITICAL("critical"),
		DEVICE("device"),
		MONITOR("monitor"),
		ICON("icon"),
		POSITION("position"),
		PROFILE("profile"),
		CONFIG("config"),
		SMS("sms");
		
		private String name;
		
		private Name(String name) {
			this.name = name;
		}
		
		public String toString() {
			return this.name;
		}
		
		public static Name getName(String name) {
			for (Name value : values()) {
				if (value.toString().equalsIgnoreCase(name)) {
					return value;
				}
			}
			
			return null;
		}
	}
	
	protected JSONObject table;
	private File file;
	
	public Table(File dataRoot, Name name) throws IOException {	
		file = new File(dataRoot, name.toString());
		
		if (file.isFile()) {
			table = Util.getJSONFromFile(file);
			
			if (table == null) {
				throw new IOException("Table ("+ name +") loading failure");
			}
		}
		else {
			table = new JSONObject();
			
			Util.putJSONtoFile(file, table);
		}
	}
	
	protected boolean isEmpty() {
		return this.table.length() == 0;
	}
	
	public JSONObject getJSONObject() {
		return this.table;
	}
	
	public JSONObject getJSONObject(String key) {
		if (this.table.has(key)) {
			return this.table.getJSONObject(key);
		}
		
		return null;
	}
	
	public JSONObject put(String key, JSONObject value) throws IOException {
		if (value == null) {
			this.table.remove(key);
		}
		else {
			this.table.put(key, value);
		}
		
		return save();
	}
	
	public JSONObject save() throws IOException {
		return Util.putJSONtoFile(this.file, this.table);
	}

	public JSONObject save(JSONObject table) throws IOException{
		this.table = table;
		
		return save();
	}
	
}
