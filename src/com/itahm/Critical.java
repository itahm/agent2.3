package com.itahm;

import java.util.HashMap;
import java.util.Map;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.util.Util;

abstract public class Critical {

	public enum Resource {
		PROCESSOR("Processor load"),
		MEMORY("Physical memory"),
		STORAGE("Storage usage"),
		THROUGHPUT("Interface throughput");
		
		private final String alias;
		
		private Resource(String alias) {
			this.alias = alias;
		}
		
		@Override
		public String toString() {
			return this.alias;
		}
	}
	
	public static byte NONE = 0x00;
	public static byte CRITIC = 0x01;
	public static byte DIFF = 0x10;
	
	private final Map<Resource, Map<String, Data>> mapping = new HashMap<>();
	
	public Critical(JSONObject criticData) {
		JSONObject list;
		Resource resource;
		Map<String, Data> rscData;
		
		for (Object key : criticData.keySet()) {			
			try {
				resource = Resource.valueOf(((String)key).toUpperCase());
			}
			catch (IllegalArgumentException iae) {
				continue;
			}
			
			list = criticData.getJSONObject((String)key);
			
			for (Object index: list.keySet()) {
				if (!mapping.containsKey(resource)) {
					mapping.put(resource, rscData = new HashMap<>());
				}
				else {
					rscData = mapping.get(resource);
				}
				
				try {
					rscData.put((String)index, new Data(list.getJSONObject((String)index).getInt("limit")));
				}
				catch(JSONException jsone) {
					Agent.syslog(Util.EToString(jsone));
				}
			}
		}
	}
	
	public void analyze(Resource resource, String index, long max, long current) {
		Map<String, Data> rscData = this.mapping.get(resource);
		
		if (rscData == null) {
			return;
		}
		
		Data data = rscData.get(index);
		
		if (data == null) {
			if (resource.equals(Resource.PROCESSOR) && rscData.get("0") != null) {
				rscData.put(index, data = rscData.get("0").clone());
			}
			else {
				return;
			}
		}
		
		long rate = current *100 / max;
		byte flag = data.test(rate);
		
		if (isDiff(flag)) {
			onCritical(isCritical(flag), resource, index, rate);
		}
	}
	
	public static boolean isCritical(byte flag) {
		return (flag & CRITIC) == CRITIC;
	}
	
	public static boolean isDiff(byte flag) {
		return (flag & DIFF) == DIFF;
	}
	
	class Data {

		private final int limit;
		private Boolean status = null;
		
		public Data(int limit) {
			this.limit = limit;
		}
		
		public byte test(long current) {
			boolean isCritic = this.limit <= current;
			
			if (this.status == null) {
				this.status = isCritic;
			}
			
			if (this.status == isCritic) {
				return NONE;
			}
			
			this.status = isCritic;
			
			return (byte)(DIFF | (isCritic? CRITIC : NONE));
		}
		
		@Override
		public Data clone() {
			return new Data(this.limit);
		}
		
	}
	
	abstract public void onCritical(boolean isCritical, Resource resource, String index, long rate);
}
