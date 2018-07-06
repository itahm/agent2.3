package com.itahm;

import java.util.HashMap;
import java.util.Map;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;

abstract public class Critical {

	public enum Resource {
		PROCESSOR,
		MEMORY,
		STORAGE,
		THROUGHPUT;
		
		@Override
		public String toString() {
			return super.toString().toLowerCase();
		}
	}
	
	public static byte NONE = 0x00;
	public static byte CRITICAL = 0x01;
	public static byte DIFF = 0x10;
	
	private final Map<Resource, Map<String, Value>> mapping = new HashMap<>();
	
	public Critical(JSONObject critical) {
		if (critical != null) {
			parse(critical);
		}
	}
	
	private void parse(JSONObject critical) {
		Map<String, Value> map;
		JSONObject jsono, value;
		
		for (Resource resource: Resource.values()) {
			if (critical.has(resource.toString())) {
				mapping.put(resource, map = new HashMap<>()); 
				
				jsono = critical.getJSONObject(resource.toString());
				for (Object index : jsono.keySet()) {
					value = jsono.getJSONObject((String)index);
					
					value.put("critical", false);
					
					try {
						map.put((String)index, new Value(value));
					}
					catch(JSONException jsone) {
						jsone.printStackTrace();
					}
				}
			}
		}
	}
	
	public void analyze(Resource resource, String index, long max, long value) {
		if (resource.equals(Resource.PROCESSOR)) {
			analyze(index, max, value);
			
			return;
		}
		
		Map<String, Value> map = this.mapping.get(resource);
		
		if (map == null) {
			return;
		}
		
		Value data = map.get(index);
		
		if (data == null) {
			return;
		}
		
		long rate = value *100 / max;
		
		if (data.test(rate)) {
			onCritical(data.isCritical(), resource.toString(), index, rate, data.getDescription());
		}
	}
	
	private void analyze(String index, long max, long value) {
		Map<String, Value> map = this.mapping.get(Resource.PROCESSOR);
		
		if (map == null) {
			return;
		}
		
		Value data = map.get(index);
		
		if (data == null) {
			if (map.get("0") == null) {
				return;
			}
			else {
				map.put(index, data = map.get("0").clone());
			}
		}
		
		long rate = value *100 / max;
		
		if (data.test(rate)) {
			for (String i : map.keySet()) {
				if ("0".equals(i) || index.equals(i)) {
					continue;
				}
				
				if (map.get(i).isCritical()) {
					return;
				}
			}
			
			onCritical(data.isCritical(), Resource.PROCESSOR.toString(), "0", rate, null);
		}
	}
	
	public void clear() {
		this.mapping.clear();
	}
	
	public void reset(JSONObject critical) {
		this.mapping.clear();
		
		parse(critical);
	}
	/*
	public void clear() {
		Map<String, Value> map;
		
		for (Resource resource : this.mapping.keySet()) {
			map = this.mapping.get(resource);
			
			if (resource.equals(Resource.PROCESSOR)) {
				for (String index : map.keySet()) {
					if ("0".equals(index)) {
						continue;
					}
					
					if (remove(map.get(index), Resource.PROCESSOR, "0")) {
						break;
					}
				}
			}
			else {
				for (String index : map.keySet()) {
					remove(map.get(index), resource, index);
				}
			}
		}
		
		this.mapping.clear();
	}
	
	public void reset(JSONObject critical) {
		Map<String, Value> map;
		JSONObject jsono;
		
		for (Resource resource : this.mapping.keySet()) {
			map = this.mapping.get(resource);
			jsono = critical.has(resource.toString())? critical.getJSONObject(resource.toString()): null;
			
			if (resource.equals(Resource.PROCESSOR)) {
				if (jsono == null) {
					for (String index : map.keySet()) {
						if ("0".equals(index)) {
							continue;
						}
						
						if (remove(map.get(index), Resource.PROCESSOR, "0")) {
							break;
						}
					}
				}
			}
			else {
				for (String index : map.keySet()) {
					if (jsono == null || !jsono.has(index)) {
						remove(map.get(index), resource, index);
					}
				}
			}
		}
		
		this.mapping.clear();
		
		parse(critical);
	}
	
	private boolean remove(Value value, Resource resource, String index) {
		if (!value.isCritical()) {
			return false;
		}
		
		onCritical(false, resource.toString(), index, -1, value.getDescription());
		
		return true;
	}
	*/
	class Value {
		
		private final int limit;
		private boolean critical = false;
		private String description = null;
		
		private Value(int limit) {
			this.limit = limit;
		}
		
		public Value(JSONObject value) throws JSONException {
			this.limit = value.getInt("limit");
			this.critical = value.getBoolean("critical");
			
			if (value.has("description")) {
				this.description = value.getString("description");
			}
		}
		
		public boolean isCritical() {
			return this.critical;
		}
		
		public String getDescription() {	
			return this.description;
		}
		
		private boolean test(long rate) {
			boolean critical = this.limit <= rate;
			
			if (this.critical == critical) { // 상태가 같으면 none
				return false;
			}
			
			this.critical = critical; // 바뀐 상태 입력
			
			return true;
		}
		
		@Override
		public Value clone() {
			return new Value(this.limit);
		}
		
	}
	
	abstract public void onCritical(boolean isCritical, String resource, String index, long rate, String description);
}
