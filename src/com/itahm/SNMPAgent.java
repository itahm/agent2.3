package com.itahm;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;

import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import com.itahm.snmp.RequestOID;
import com.itahm.snmp.TmpNode;
import com.itahm.table.Table;
import com.itahm.util.DataCleaner;
import com.itahm.util.TopTable;
import com.itahm.util.Util;

public class SNMPAgent extends Snmp implements Closeable {
	
	private final static long REQUEST_INTERVAL = 10000;
	private boolean isClosed = false;
	private DataCleaner cleaner;
	
	public enum Resource {
		RESPONSETIME("responseTime"),
		FAILURERATE("failureRate"),
		PROCESSOR("processor"),
		MEMORY("memory"),
		MEMORYRATE("memoryRate"),
		STORAGE("storage"),
		STORAGERATE("storageRate"),
		THROUGHPUT("throughput"),
		THROUGHPUTRATE("throughputRate"),
		THROUGHPUTERR("throughputErr");
		
		private String string;
		
		private Resource(String string) {
			this.string = string;
		}
		
		public String toString() {
			return this.string;
		}
	};
	
	public final File nodeRoot;
	
	private final Map<String, SNMPNode> nodeList = new ConcurrentHashMap<String, SNMPNode>();
	private final Table monitorTable;
	private final Table profileTable;
	private final Table criticalTable;
	private final TopTable<Resource> topTable;
	private final Map<String, JSONObject> ifMap = new HashMap<>();
	private final Timer timer;
	
	public SNMPAgent(File root) throws IOException {
		super(new DefaultUdpTransportMapping());
		
		System.out.println("SNMP manager start.");
		
		monitorTable = Agent.getTable(Table.Name.MONITOR);
		
		profileTable = Agent.getTable(Table.Name.PROFILE);
		
		criticalTable = Agent.getTable(Table.Name.CRITICAL);
		
		topTable = new TopTable<>(Resource.class);
		
		timer = new Timer();
		 
		nodeRoot = new File(root, "node");
		nodeRoot.mkdir();
		
		_initialize();
	}
	
	public void _initialize() throws IOException {
		JSONObject deviceData = Agent.getTable(Table.Name.DEVICE).getJSONObject(),
			device, ifSpeed;
		
		for (Object id : deviceData.keySet()) {
			device = deviceData.getJSONObject((String)id);
			
			if (device.has("ifSpeed")) {
				ifSpeed = device.getJSONObject("ifSpeed");
				
				if (ifSpeed.length() > 0 && device.has("ip")) {
					this.ifMap.put(device.getString("ip"), ifSpeed);
				}
			}
		}
		
		initUSM();
		
		super.listen();
		
		initNode();
	}
	
	public void setRequestOID(PDU pdu) {
		pdu.add(new VariableBinding(RequestOID.sysDescr));
		pdu.add(new VariableBinding(RequestOID.sysObjectID));
		pdu.add(new VariableBinding(RequestOID.sysName));
		pdu.add(new VariableBinding(RequestOID.sysServices));
		pdu.add(new VariableBinding(RequestOID.ifDescr));
		pdu.add(new VariableBinding(RequestOID.ifType));
		pdu.add(new VariableBinding(RequestOID.ifSpeed));
		pdu.add(new VariableBinding(RequestOID.ifPhysAddress));
		pdu.add(new VariableBinding(RequestOID.ifAdminStatus));
		pdu.add(new VariableBinding(RequestOID.ifOperStatus));
		pdu.add(new VariableBinding(RequestOID.ifName));
		pdu.add(new VariableBinding(RequestOID.ifInOctets));
		pdu.add(new VariableBinding(RequestOID.ifInErrors));
		pdu.add(new VariableBinding(RequestOID.ifOutOctets));
		pdu.add(new VariableBinding(RequestOID.ifOutErrors));
		pdu.add(new VariableBinding(RequestOID.ifHCInOctets));
		pdu.add(new VariableBinding(RequestOID.ifHCOutOctets));
		pdu.add(new VariableBinding(RequestOID.ifHighSpeed));
		pdu.add(new VariableBinding(RequestOID.ifAlias));
		pdu.add(new VariableBinding(RequestOID.hrSystemUptime));
		pdu.add(new VariableBinding(RequestOID.hrProcessorLoad));
		pdu.add(new VariableBinding(RequestOID.hrSWRunName));
		pdu.add(new VariableBinding(RequestOID.hrStorageType));
		pdu.add(new VariableBinding(RequestOID.hrStorageDescr));
		pdu.add(new VariableBinding(RequestOID.hrStorageAllocationUnits));
		pdu.add(new VariableBinding(RequestOID.hrStorageSize));
		pdu.add(new VariableBinding(RequestOID.hrStorageUsed));
	}
	
	public boolean  registerNode(String ip, String profileName) {
		if (Agent.limit > 0 && this.nodeList.size() >= Agent.limit) {
			Agent.log("ITAhM", String.format("라이선스 초과 %d", Agent.limit), Log.Type.SYSTEM, false, true);
			
			return false;
		}
		else {
			try {
				addNode(ip, profileName);
			} catch (IOException ioe) {
				Agent.syslog(Util.EToString(ioe));
				
				Agent.log(ip, "시스템에 심각한 오류가 있습니다.", Log.Type.SYSTEM, false, false);
			}
			
			return true;
		}
	}
	
	private void addNode(String ip, String profileName) throws IOException {		
		final JSONObject profile = profileTable.getJSONObject(profileName);
		
		if (profile == null) {
			Agent.syslog(String.format("%s profile not found %s", ip, profileName));
			
			return ;
		}
		
		SNMPNode node;
		
		try {
			switch(profile.getString("version")) {
			case "v3":
				node = SNMPNode.getInstance(this, ip, profile.getInt("udp"),
					profile.getString("user"),
					(profile.has("md5") || profile.has("sha"))?
						(profile.has("des")) ?
							SecurityLevel.AUTH_PRIV: SecurityLevel.AUTH_NOPRIV : SecurityLevel.NOAUTH_NOPRIV,
					this.criticalTable.getJSONObject(ip),
					this.ifMap.containsKey(ip)? this.ifMap.get(ip): new JSONObject()
					);
				
				break;
			
			case "v2c":
				node = SNMPNode.getInstance(this, ip, profile.getInt("udp"),
					SnmpConstants.version2c,
					profile.getString("community"),
					this.criticalTable.getJSONObject(ip),
					this.ifMap.containsKey(ip)? this.ifMap.get(ip): new JSONObject());
				
				break;
				
			default:
				node = 	SNMPNode.getInstance(this, ip, profile.getInt("udp"),
					SnmpConstants.version1,
					profile.getString("community"),
					this.criticalTable.getJSONObject(ip),
					this.ifMap.containsKey(ip)? this.ifMap.get(ip): new JSONObject());
			}
			
			this.nodeList.put(ip, node);
			
			node.request();
		}
		catch (JSONException jsone) {
			Agent.syslog(Util.EToString(jsone));
		}
	}
	
	private void initUSM() {
		JSONObject profileData = profileTable.getJSONObject();
		JSONObject profile;
		
		SecurityModels.getInstance().addSecurityModel(new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0));
		
		for (Object key : profileData.keySet()) {
			profile = profileData.getJSONObject((String)key);
			try {
				if ("v3".equals(profile.getString("version"))) {
					addUSM(profile);
				}
			}
			catch (JSONException jsone) {
				Agent.syslog(Util.EToString(jsone));
			}
		}
	}
	
	/**
	 * table.Profile 로부터 호출.
	 * @param profile
	 * @return
	 */
	public boolean addUSM(JSONObject profile) {
		String user = profile.getString("user");
		
		if (user.length() == 0) {
			return false;
		}
		
		String authentication = profile.has("md5")? "md5": profile.has("sha")? "sha": null;
		
		if (authentication == null) {
			return addUSM(new OctetString(user)
				, null, null, null, null);
		}
		else {
			String privacy = profile.has("des")? "des": null;
		
			if (privacy == null) {
				return addUSM(new OctetString(user)
					, "sha".equals(authentication)? AuthSHA.ID: AuthMD5.ID, new OctetString(profile.getString(authentication))
					, null, null);
			}
			
			return addUSM(new OctetString(user)
				, "sha".equals(authentication)? AuthSHA.ID: AuthMD5.ID, new OctetString(profile.getString(authentication))
				, PrivDES.ID, new OctetString(profile.getString(privacy)));
		}
	}
	
	private boolean addUSM(OctetString user, OID authProtocol, OctetString authPassphrase, OID privProtocol, OctetString privPassphrase) {		
		if (super.getUSM().getUserTable().getUser(user) != null) {
			
			return false;
		}
		
		super.getUSM().addUser(new UsmUser(user, authProtocol, authPassphrase, privProtocol, privPassphrase));
		
		return true;
	}
	
	public void removeUSM(String user) {
		super.getUSM().removeAllUsers(new OctetString(user));
	}
	
	public boolean isIdleProfile(String name) {
		JSONObject monitor;
		try {
			for (Object key : this.monitorTable.getJSONObject().keySet()) {
				monitor = this.monitorTable.getJSONObject((String)key);
				
				if (monitor.has("profile") && monitor.getString("profile").equals(name)) {
					return false;
				}
			}
		}
		catch (JSONException jsone) {
			Agent.syslog(Util.EToString(jsone));
			
			return false;
		}
		
		return true;
	}

	public boolean removeNode(String ip) {
		if (this.nodeList.remove(ip) == null) {
			return false;
		}
		
		this.topTable.remove(ip);
		
		return true;
	}
	
	private void initNode() throws IOException {
		JSONObject monitorData = this.monitorTable.getJSONObject();
		JSONObject monitor;
		String ip;
		
		for (Object key : monitorData.keySet()) {
			ip = (String)key;
			
			monitor = monitorData.getJSONObject(ip);
		
			if ("snmp".equals(monitor.getString("protocol"))) {
				addNode(ip, monitor.getString("profile"));
			}
		}
	}
	
	public void resetResponse(String ip) {
		SNMPNode node = this.nodeList.get(ip);
		
		if (node == null) {
			return;
		}
		
		node.resetResponse();
	}
	
	public void resetCritical(String ip, JSONObject critical) {
		SNMPNode node = this.nodeList.get(ip);
		
		if (node == null) {
			return;
		}
			
		node.setCritical(critical);
	}
	
	private void setCritical(JSONObject critical, String index, int rate, String description, boolean overwrite) {
		if (critical.has(index) && !overwrite) {
			return;
		}
		
		JSONObject value = new JSONObject();
		
		value.put("limit", rate);
		
		if (description != null) {
			value.put("description", description);
		}
		
		critical.put(index, value);
	}
	
	private void setCritical(JSONObject data, String resource, JSONObject critical, int rate, boolean overwrite) {
		switch(resource) {
		case "processor":
			if (data.has("hrProcessorEntry")) {
				setCritical(critical, "0", rate, null, overwrite);
			}
			
			break;
		case "memory":				
			if (data.has("hrStorageEntry")) {
				JSONObject entry = data.getJSONObject("hrStorageEntry"),
					strgData;
				
				for (Object index: entry.keySet()) {
					strgData = entry.getJSONObject((String)index);
					
					if (!strgData.has("hrStorageType") || strgData.getInt("hrStorageType") != 2) {
						continue;
					}
					
					setCritical(critical, (String)index, rate, 
						strgData.has("hrStorageDescr")? strgData.getString("hrStorageDescr"): null, overwrite);
				}
			}
			
			break;
		case "storage":
			if (data.has("hrStorageEntry")) {
				JSONObject entry = data.getJSONObject("hrStorageEntry"),
					strgData;
				
				for (Object index: entry.keySet()) {
					strgData = entry.getJSONObject((String)index);
					
					if (!strgData.has("hrStorageType") || strgData.getInt("hrStorageType") != 4) {
						continue;
					}
					
					setCritical(critical, (String)index, rate, 
						strgData.has("hrStorageDescr")? strgData.getString("hrStorageDescr"): null, overwrite);
				}
			}
			
			break;
		case "throughput":
			if (data.has("ifEntry")) {
				JSONObject entry = data.getJSONObject("ifEntry"),
					ifData;
				
				for (Object index: entry.keySet()) {
					ifData = entry.getJSONObject((String)index);
					
					setCritical(critical, (String)index, rate, 
						ifData.has("ifName")? ifData.getString("ifName"):
						ifData.has("ifAlias")? ifData.getString("ifAlias"):null, overwrite);
				}
			}
			
			break;
		}
	}
	
	private void setCritical(JSONObject data, JSONObject criticalCondition, String resource, int rate, boolean overwrite) {
		JSONObject critical;
		
		if (criticalCondition.has(resource)) {
			critical = criticalCondition.getJSONObject(resource);
		}
		else {
			criticalCondition.put(resource, critical = new JSONObject());
		}
		
		setCritical(data, resource, critical, rate, overwrite);
	}
	
	private void setCritical(SNMPNode node, JSONObject criticalCondition, String resource, int rate, boolean overwrite) {
		final JSONObject data = node.getData();
		
		if (data == null) {
			return;
		}
		
		if (resource == null) {
			setCritical(data, criticalCondition, "processor", rate, overwrite);
			setCritical(data, criticalCondition, "memory", rate, overwrite);
			setCritical(data, criticalCondition, "storage", rate, overwrite);
			setCritical(data, criticalCondition, "throughput", rate, overwrite);
		}
		else {
			setCritical(data, criticalCondition, resource, rate, overwrite);
		}
		
		node.setCritical(criticalCondition);
	}
	
	public void setCritical(String target, String resource, int rate, boolean overwrite) {
		JSONObject criticalData = Agent.getTable(Table.Name.CRITICAL).getJSONObject();
		JSONObject criticalCondition;
		
		if (target == null) {	
			for (String ip : this.nodeList.keySet()) {
				target = ip;
				
				if (criticalData.has(target)) {
					criticalCondition = criticalData.getJSONObject(target);
				}
				else {
					criticalData.put(target, criticalCondition = new JSONObject());
				}
				
				setCritical(this.nodeList.get(ip), criticalCondition, resource, rate, overwrite);
			}
		}
		else {
			final SNMPNode node = this.nodeList.get(target);
			
			if (node != null) {
				if (criticalData.has(target)) {
					criticalCondition = criticalData.getJSONObject(target);
				}
				else {
					criticalData.put(target, criticalCondition = new JSONObject());
				}
				
				setCritical(node, criticalCondition, resource, rate, overwrite);
			}
		}
	}
	
	public void testNode(final String ip, String id) {
		if (this.nodeList.containsKey(ip)) {
			if(id != null) {
				Agent.log(ip, "이미 등록된 노드 입니다.", Log.Type.SYSTEM, false, false);
			}
			
			return;
		}
		
		final JSONObject profileData = this.profileTable.getJSONObject();
		JSONObject profile;
		
		TmpNode node = new TestNode(this, ip, id);
		
		for (Object name : profileData.keySet()) {
			profile = profileData.getJSONObject((String)name);
			
			try {
				switch(profile.getString("version")) {
				case "v3":
					node.addV3Profile((String)name, profile.getInt("udp"), new OctetString(profile.getString("user"))
							, (profile.has("md5") || profile.has("sha"))? (profile.has("des")) ? SecurityLevel.AUTH_PRIV: SecurityLevel.AUTH_NOPRIV : SecurityLevel.NOAUTH_NOPRIV);
					break;
				case "v2c":
					node.addProfile((String)name, profile.getInt("udp"), new OctetString(profile.getString("community")), SnmpConstants.version2c);
					
					break;
				case "v1":
					node.addProfile((String)name, profile.getInt("udp"), new OctetString(profile.getString("community")), SnmpConstants.version1);
					
					break;
				}
			} catch (UnknownHostException | JSONException e) {
				Agent.syslog(Util.EToString(e));
			}
		}
		
		node.test();
	}
	
	public SNMPNode getNode(String ip) {
		return this.nodeList.get(ip);
	}
	
	public JSONObject getNodeData(String ip) {
		SNMPNode node = this.nodeList.get(ip);
		
		if (node == null) {
			return null;
		}
		
		JSONObject data = node.getData();
		
		if (data != null) {
			return data;
		}
		
		File f = new File(new File(this.nodeRoot, ip), "node");
		
		if (f.isFile()) {
			try {
				data = Util.getJSONFromFile(f);
			} catch (IOException e) {
				Agent.syslog("SNMPAgent "+ e.getMessage());
			}
		}
		
		if (data != null) {
			data.put("failure", 100);
		}
		
		return data;
	}
	
	public JSONObject getNodeData(String ip, boolean offline) {
		return getNodeData(ip);
	}
	
	public JSONObject getTop(int count) {
		return this.topTable.getTop(count);		
	}
	
	public void clean(int day) {
		Calendar date = Calendar.getInstance();
					
		date.set(Calendar.HOUR_OF_DAY, 0);
		date.set(Calendar.MINUTE, 0);
		date.set(Calendar.SECOND, 0);
		date.set(Calendar.MILLISECOND, 0);
		
		date.add(Calendar.DATE, -1* day);
		
		this.cleaner = new DataCleaner(nodeRoot, date.getTimeInMillis(), 3) {

			@Override
			public void onDelete(File file) {
			}
			
			@Override
			public void onComplete(long count) {
				if (count > 0) {
					Agent.syslog(String.format("데이터 정리 %d 건 완료.", count));
				}
			}
		};
	}
	
	public JSONObject getFailureRate(String ip) {
		SNMPNode node = this.nodeList.get(ip);
		
		if (node == null) {
			return null;
		}
		
		JSONObject json = new JSONObject().put("failure", node.getFailureRate());
		
		return json;
	}
	
	public void onResponse(String ip, boolean success) {
		SNMPNode node = this.nodeList.get(ip);

		if (node == null) {
			return;
		}
		
		if (success) {
			try {
				Util.putJSONtoFile(new File(new File(this.nodeRoot, ip), "node"), node.getData());
			} catch (IOException ioe) {
				Agent.syslog(Util.EToString(ioe));
			}
			
			sendNextRequest(node);
		}
		else {
			sendRequest(node);
		}
	}
	
	/**
	 * 
	 * @param ip
	 * @param timeout
	 * ICMP가 성공하는 경우 후속 SNMP 결과에 따라 처리하도록 하지만
	 * ICMP가 실패하는 경우는 바로 다음 Request를 처리하도록 해야한다.
	 */
	public void onTimeout(String ip, boolean timeout) {
		if (timeout) {
			onFailure(ip);
		}
		else {
			onSuccess(ip);
		}
	}
	
	/**
	 * ICMP 요청에 대한 응답
	 */
	private void onSuccess(String ip) {
		SNMPNode node = this.nodeList.get(ip);
		
		// 그 사이 삭제되었으면
		if (node == null) {
			return;
		}
		
		JSONObject monitor = this.monitorTable.getJSONObject(ip);
		
		if (monitor == null) {
			return;
		}
		
		if (monitor.getBoolean("shutdown")) {	
			JSONObject nodeData = node.getData();
			
			monitor.put("shutdown", false);
			
			try {
				this.monitorTable.save();
			} catch (IOException ioe) {
				Agent.syslog(Util.EToString(ioe));
			}
			
			Agent.log(ip,
				(nodeData != null && nodeData.has("sysName"))? String.format("%s [%s] 정상.", ip, nodeData.getString("sysName")): String.format("%s 정상.", ip),
						Log.Type.SHUTDOWN, true, true);
		}
	}
	
	/**
	 * ICMP 요청에 대한 응답
	 */
	private void onFailure(String ip) {
		SNMPNode node = this.nodeList.get(ip);

		if (node == null) {
			return;
		}
		
		JSONObject monitor = this.monitorTable.getJSONObject(ip);
		
		if (monitor == null) {
			return;
		}
		
		if (!monitor.getBoolean("shutdown")) {
			JSONObject nodeData = node.getData();
			
			monitor.put("shutdown", true);
			
			try {
				this.monitorTable.save();
			} catch (IOException ioe) {
				Agent.syslog(Util.EToString(ioe));
			}
			
			Agent.log(ip,
				(nodeData != null && nodeData.has("sysName"))? String.format("%s [%s] 응답 없음.", ip, nodeData.getString("sysName")): String.format("%s 응답 없음.", ip),
				Log.Type.SHUTDOWN, false, true);
		}
		
		sendRequest(node);
	}

	/**
	 * snmp 요청에 대한 응답
	 * @param ip
	 */
	public void onException(String ip) {
		SNMPNode node = this.nodeList.get(ip);

		if (node == null) {
			return;
		}
		
		sendNextRequest(node);
	}
	
	public void onCritical(String ip, boolean critical, String message) {
		SNMPNode node = this.nodeList.get(ip);
		
		if (node == null) {
			return;
		}
		
		JSONObject monitor = this.monitorTable.getJSONObject(ip);
		
		if (monitor == null) {
			return;
		}
		
		JSONObject nodeData = node.getData();
		
		monitor.put("critical", critical);
		
		try {
			this.monitorTable.save();
		} catch (IOException ioe) {
			Agent.syslog(Util.EToString(ioe));
		}
		
		Agent.log(ip,
			nodeData.has("sysName")? String.format("%s [%s] %s", ip, nodeData.getString("sysName"), message): String.format("%s %s", ip, message),
			Log.Type.CRITICAL, !critical, true);
		
	}
	
	public void onSubmitTop(String ip, Resource resource, TopTable.Value value) {
		if (!this.nodeList.containsKey(ip)) {
			return;
		}
		
		this.topTable.submit(ip, resource, value);
	}
	
	private void sendNextRequest(final SNMPNode node) {
		if (this.isClosed) {
			return;
		}
		
		this.timer.schedule(
			new TimerTask() {

				@Override
				public void run() {
					sendRequest(node);
				}
				
			}, REQUEST_INTERVAL);
	}
	
	private final void sendRequest(SNMPNode node) {
		try {
			node.request();
		} catch (IOException ioe) {
			Agent.syslog(Util.EToString(ioe));
			
			sendNextRequest(node);
		}
	}
	
	public final long calcLoad() {
		BigInteger bi = BigInteger.valueOf(0);
		long size = 0;
		
		for (String ip : this.nodeList.keySet()) {
			bi = bi.add(BigInteger.valueOf(this.nodeList.get(ip).getLoad()));
			
			size++;
		}
		
		return size > 0? bi.divide(BigInteger.valueOf(size)).longValue(): 0;
	}
	
	public final JSONObject test() {
		JSONObject jsono = new JSONObject();
		
		for (String ip : this.nodeList.keySet()) {
			jsono.put(ip,this.nodeList.get(ip).test());
		}
		
		return jsono;
	}
	public long getResourceCount() {
		long count = 0;
		
		for (String ip : this.nodeList.keySet()) {
			count += this.nodeList.get(ip).getResourceCount();
		}
		
		return count;
	}
	
	/**
	 * ovverride
	 */
	@Override
	public void close() {
		this.isClosed = true;
		
		try {
			super.close();
		} catch (IOException ioe) {
			Agent.syslog(Util.EToString(ioe));
		}
		
		for (SNMPNode node: this.nodeList.values()) {
			try {
				node.close();
			} catch (IOException ioe) {
				Agent.syslog(Util.EToString(ioe));
			}
		}
		
		this.timer.cancel();
		
		if (this.cleaner != null) {
			this.cleaner.cancel();
		}
		
		System.out.format("SNMP manager stop.\n");
	}
	
}
