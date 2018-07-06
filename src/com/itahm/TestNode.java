package com.itahm;

import java.io.IOException;

import com.itahm.json.JSONObject;

import com.itahm.snmp.TmpNode;
import com.itahm.table.Table;
import com.itahm.table.Device;
import com.itahm.util.Util;

public class TestNode extends TmpNode {

	private final SNMPAgent agent;
	// onFailure : 정상 테스트인경우 true, 자동탐색일 경우 false
	private String id;
	
	public TestNode(SNMPAgent agent, String ip, String id) {
		super(agent, ip, Agent.MAX_TIMEOUT);
		
		this.agent = agent;
		
		this.id = id;
		// TODO Auto-generated constructor stub
	}

	@Override
	public void onSuccess(String profileName) {
		if (!this.agent.registerNode(this.ip, profileName)) {
			return;
		}			
		
		final Table deviceTable = Agent.getTable(Table.Name.DEVICE);
		final Table monitorTable = Agent.getTable(Table.Name.MONITOR);
		
		// 자동탐색인 경우 device정보가 없으니 생성해 준다.
		if (this.id == null) {
			this.id = ((Device)deviceTable).createID(false);
			
			try {
				deviceTable.put(this.id,
					new JSONObject()
						.put("ip", super.ip)
						.put("name", "")
						.put("type", "unknown")
						.put("label", "")
						.put("ifSpeed", new JSONObject()));
			} catch (IOException ioe) {
				Agent.syslog(Util.EToString(ioe));
			}
		}
		
		Agent.removeICMPNode(super.ip);
		
		monitorTable.getJSONObject().put(super.ip, new JSONObject()
			.put("id", this.id)
			.put("protocol", "snmp")
			.put("ip", super.ip)
			.put("profile", profileName)
			.put("shutdown", false)
			.put("critical", false));
		
		try {
			monitorTable.save();
		} catch (IOException ioe) {
			Agent.syslog(Util.EToString(ioe));
		}
		
		Agent.log(new JSONObject()
			.put("origin", "test")
			.put("id", this.id)
			.put("ip", super.ip)
			.put("test", true)
			.put("protocol", "snmp")
			.put("profile", profileName)
			.put("message", String.format("%s SNMP 등록 성공", super.ip))
			, false);
	}

	@Override
	public void onFailure(int status) {
		if (this.id != null) {
			Agent.log(new JSONObject()
				.put("origin", "test")
				.put("ip", super.ip)
				.put("test", false)
				.put("protocol", "snmp")
				.put("status", status)
				.put("message", String.format("%s SNMP 등록 실패", super.ip))
				, false);
		}
	}
}
