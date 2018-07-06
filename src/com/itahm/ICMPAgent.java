package com.itahm;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;

import com.itahm.icmp.ICMPListener;
import com.itahm.icmp.ICMPNode;
import com.itahm.table.Table;
import com.itahm.util.Util;

public class ICMPAgent implements ICMPListener, Closeable {
	
	private final static int [] TIMEOUTS = new int [] {2000, 3000, 5000};
	
	private final Map<String, ICMPNode> nodeList = new HashMap<>();
	private final Table monitorTable = Agent.getTable(Table.Name.MONITOR);
	
	public ICMPAgent() throws IOException {
		JSONObject snmpData = monitorTable.getJSONObject();
		
		for (Object ip : snmpData.keySet()) {
			try {
				if ("icmp".equals(snmpData.getJSONObject((String)ip).getString("protocol"))) {
					addNode((String)ip);
				}
			} catch (JSONException jsone) {
				Agent.syslog(Util.EToString(jsone));
			}
		}
		
		System.out.println("ICMP manager start.");
	}
	
	private void addNode(String ip) {
		try {
			ICMPNode node = new ICMPNode(this, ip, TIMEOUTS);
			
			synchronized (this.nodeList) {
				this.nodeList.put(ip, node);
			}
			
			node.ping(0);
		} catch (UnknownHostException uhe) {
			Agent.syslog(Util.EToString(uhe));
		}		
	}
	
	public boolean removeNode(String ip) {
		ICMPNode node;
		
		synchronized (this.nodeList) {
			node = this.nodeList.remove(ip);
		}
		
		if (node == null) {
			return false;
		}
		
		try {
			node.close();
		} catch (IOException ioe) {
			Agent.syslog(Util.EToString(ioe));
		}
		
		return true;
	}
	
	public ICMPNode getNode(String ip) {
		synchronized(this.nodeList) {
			return this.nodeList.get(ip);
		}
	}
	
	public void testNode(final String ip) {
		new Thread(new Runnable() {

			@Override
			public void run() {
				boolean isReachable = false;
				
				try {
					isReachable = InetAddress.getByName(ip).isReachable(Agent.DEF_TIMEOUT);
				} catch (IOException e) {
					Agent.syslog(Util.EToString(e));
				}
				
				if (!isReachable) {
					Agent.log(new JSONObject()
						.put("origin", "test")
						.put("ip", ip)
						.put("test", false)
						.put("protocol", "icmp")
						.put("message", String.format("%s ICMP 등록 실패", ip)), false);
				}
				else {
					monitorTable.getJSONObject().put(ip, new JSONObject()
						.put("protocol", "icmp")
						.put("ip", ip)
						.put("shutdown", false));
					
					try {
						monitorTable.save();
					} catch (IOException ioe) {
						Agent.syslog(Util.EToString(ioe));
					}
					
					addNode(ip);
					
					Agent.log(new JSONObject()
						.put("origin", "test")
						.put("ip", ip)
						.put("test", true)
						.put("protocol", "icmp")
						.put("message", String.format("%s ICMP 등록 성공", ip)), false);
				}
			}
			
		}).start();
	}
	
	public void onSuccess(ICMPNode node, long time) {
		JSONObject monitor = this.monitorTable.getJSONObject(node.ip);
		
		if (monitor == null) {
			return;
		}
		
		if (monitor.getBoolean("shutdown")) {
			monitor.put("shutdown", false);
			
			try {
				this.monitorTable.save();
			} catch (IOException ioe) {
				Agent.syslog(Util.EToString(ioe));
			}
			
			Agent.log(new JSONObject()
				.put("origin", "shutdown")
				.put("ip", node.ip)
				.put("shutdown", false)
				.put("protocol", "icmp")
				.put("message", String.format("%s ICMP 응답 정상", node.ip)), true);
		}
		
		node.ping(1000);
	}
	
	public void onFailure(ICMPNode node) {
		JSONObject monitor = this.monitorTable.getJSONObject(node.ip);
		
		if (monitor == null) {
			return;
		}
		
		if (!monitor.getBoolean("shutdown")) {
			monitor.put("shutdown", true);
			
			try {
				this.monitorTable.save();
			} catch (IOException ioe) {
				Agent.syslog(Util.EToString(ioe));
			}
			
			Agent.log(new JSONObject()
				.put("origin", "shutdown")
				.put("ip", node.ip)
				.put("shutdown", true)
				.put("protocol", "icmp")
				.put("message", String.format("%s ICMP 응답 없음", node.ip)), true);
		}
		
		node.ping(0);
	}
	
	/**
	 * ovverride
	 */
	@Override
	public void close() {
		Exception e = null;
		
		synchronized (this.nodeList) {
			for (ICMPNode node : this.nodeList.values()) {
				try {
					node.close();
				} catch (IOException ioe) {
					e = ioe;
				}
			}
		}
		
		this.nodeList.clear();
		
		System.out.format("ICMP manager stop.\n");
		
		if (e != null) {
			Agent.syslog(Util.EToString(e));
		}
	}
	
}
