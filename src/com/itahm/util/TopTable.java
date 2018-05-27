package com.itahm.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.itahm.json.JSONObject;

public class TopTable <E extends Enum<E>> implements Comparator<String> {
	
	private final Class<E> e;
	private final Map<E, HashMap<String, Value>> map;
	private Map<String, Value> sortTop;
	private boolean sortByRate;
	
	public TopTable(Class<E> e) {
		this.e = e;
		
		map = new HashMap<>();
		
		for (E key : e.getEnumConstants()) {
			map.put(key, new HashMap<String, Value>());
		}
	}
	
	public synchronized void submit(String ip, E resource, Value value) {
		this.map.get(resource).put(ip, value);
	}
	
	public synchronized JSONObject getTop(final int count) {try {
		JSONObject top = new JSONObject();
		String key;
		for (E resource : e.getEnumConstants()) {
			key = resource.toString();
			
			top.put(key.toString(), getTop(this.map.get(resource), count,
				"Rate".equals(key.substring(key.length() -4, key.length()))));
		}
		
		return top;}catch(Exception e) {e.printStackTrace(); }
	
		return null;
	}
	
	private JSONObject getTop(HashMap<String, Value> sortTop, int count, boolean sortByRate) {
		JSONObject top = new JSONObject();
		List<String> list = new ArrayList<String>();
		String ip;
		
		this.sortTop = sortTop;
		this.sortByRate = sortByRate;
		
        list.addAll(sortTop.keySet());
         
        Collections.sort(list, this);
        
        count = Math.min(list.size(), count);
        
        for (int i=0; i< count; i++) {
        	ip = list.get(i);
        	
        	top.put(ip, sortTop.get(ip).toJSONObject());
        }
        
        return top;
	}

	public void remove(String ip) {
		for (E key : e.getEnumConstants()) {
			this.map.get(key).remove(ip);
		}
	}
	
	@Override
	public int compare(String ip1, String ip2) {
		Value v1 = this.sortTop.get(ip1),
			v2 = this.sortTop.get(ip2);
		long l;
		
		if (this.sortByRate) {
			l = v2.getRate() - v1.getRate();
			
			if (l == 0) {
				l = v2.getValue() - v1.getValue();
			}
		}
		else {
			l = v2.getValue() - v1.getValue();
			
			if (l == 0) {
				l = v2.getRate() - v1.getRate();
			}
		}
		
        return l > 0? 1: l < 0? -1: 0;
	}
	
	public final static class Value {
		private final long value;
		private final long rate;
		private final long index;
		
		public Value(long v, long r, String i) {
			value = v;
			rate = r;
			index = Long.parseLong(i);
		}
		
		public long getValue() {
			return this.value;
		}
		
		public long getRate() {
			return this.rate;
		}
		
		public JSONObject toJSONObject() {
			return new JSONObject()
				.put("value", this.value)
				.put("rate", this.rate)
				.put("index", this.index);
		}
	}
}