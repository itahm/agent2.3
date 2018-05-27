package com.itahm.table;

import java.io.File;
import java.io.IOException;

import com.itahm.json.JSONObject;
import com.itahm.Agent;

public class Monitor extends Table {
	
	public Monitor(File dataRoot) throws IOException {
		super(dataRoot, Name.MONITOR);
	}
	
	private void remove(String ip, String protocol) throws IOException {
		if ("snmp".equals(protocol)) {
			if (Agent.removeSNMPNode(ip)) {
				Agent.getTable(Name.CRITICAL).put(ip, null);
			}
		}
		else if ("icmp".equals(protocol)) {
			Agent.removeICMPNode(ip);
		}
		
		super.put(ip, null);
	}
	
	public JSONObject put(String ip, JSONObject monitor) throws IOException {
		// icmp 에서 snmp로 또는 snmp 에서 icmp로 변경되는 상황
		// 기존 모니터는 지워주자.
		if (super.table.has(ip)) {
			remove(ip, super.table.getJSONObject(ip).getString("protocol"));
		}
		
		if (monitor != null) {
			super.put(ip, null);
			
			switch(monitor.getString("protocol")) {
			case "snmp":
				Agent.testSNMPNode(ip, monitor.getString("id"));
				
				break;
			case "icmp":
				Agent.testICMPNode(ip);
				
				break;
			}
		}// else 위에서 처리 되었음.
		
		return super.table;
	}
}
