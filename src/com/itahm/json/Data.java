package com.itahm.json;

import java.io.File;
import java.io.IOException;
import java.util.Calendar;

import com.itahm.json.JSONObject;

public abstract class Data {

	private final JSONObject data;
	private final File root;
	
	public Data(File f) {
		root = f;
		data = new JSONObject();
	}
	
	public void buildJSON(final long end, Calendar calendar) throws IOException {
		long mills = calendar.getTimeInMillis();
		
		if (end <= mills) {
			return;
		}
		
		buildNext(new File(this.root, Long.toString(mills)));
		
		calendar.add(Calendar.DATE, 1);
		
		buildJSON(end, calendar);
	}
	
	public JSONObject getJSON(long startMills, long endMills) throws IOException {
		Calendar calendar = Calendar.getInstance();
		
		this.data.clear();
		
		calendar.setTimeInMillis(startMills);
		calendar.set(Calendar.MILLISECOND, 0);
		calendar.set(Calendar.SECOND, 0);
		calendar.set(Calendar.MINUTE, 0);
		calendar.set(Calendar.HOUR_OF_DAY, 0);
		
		buildJSON(endMills, calendar);
		
		return this.data;
	}
	
	protected void put(String key, long value) {
		this.data.put(key, value);
	}
	
	protected void put(String key, JSONObject value) {
		this.data.put(key, value);
	}
	
	abstract protected void buildNext(File dir) throws IOException;
}
