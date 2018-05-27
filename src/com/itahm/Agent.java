package com.itahm;

import java.io.File;
import java.io.IOException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeSet;

import com.itahm.Log;
import com.itahm.SNMPAgent;
import com.itahm.ICMPAgent;
import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.command.Command;
import com.itahm.command.Commander;
import com.itahm.http.HTTPException;
import com.itahm.http.Request;
import com.itahm.http.Response;
import com.itahm.http.Session;
import com.itahm.table.Account;
import com.itahm.table.Config;
import com.itahm.table.Critical;
import com.itahm.table.Device;
import com.itahm.table.Monitor;
import com.itahm.table.Position;
import com.itahm.table.Profile;
import com.itahm.table.Table;
import com.itahm.enterprise.Enterprise;

public class Agent {

	/* Configuration */
	
	// args로 debug가 넘어오면 true로 변경됨
	public static boolean isDebug = false;
	// 30일 데모 버전 출시용 true, itahm.com의 요청만 처리함
	public static boolean isDemo = false;
	// node 제한 0: 무제한
	public static int limit = 0;
	// 라이센스 mac address null: 데모 버전에만 적용할것
	private static final byte [] license = null; // new byte [] {(byte)0x6c, (byte)0x3b, (byte)0xe5, (byte)0x51, (byte)0x2D, (byte)0x80};
	// 라이선스 만료일 0: 무제한, isDemo true인 경우 자동 set
	private static long expire = 0; // 1546268400000L;
	
	/* Configuration */
	
	public final static String VERSION = "2.0.3.2";
	private final static long DAY1 = 24 *60 *60 *1000;
	private final static String DATA = "data";
	public final static int MAX_TIMEOUT = 10000;
	public final static int ICMP_INTV = 1000;
	public final static int MID_TIMEOUT = 5000;
	public final static int DEF_TIMEOUT = 3000;
	
	private static Map<Table.Name, Table> tables = new HashMap<>();
	private static TreeSet<Integer> validIFType = null;
	private static Log log;
	private static SNMPAgent snmp;
	private static ICMPAgent icmp;
	public final static Enterprise enterprise = new Enterprise();
	private final HTTPServer server;
	private static JSONObject config;
	private static Batch batch;
	public static File root;
	private static File dataRoot;
	
	public Agent(int tcp) throws IOException {
		System.out.format("ITAhM Agent version %s ready.\n", VERSION);
		
		tables.put(Table.Name.CONFIG, new Config(dataRoot));
		tables.put(Table.Name.ACCOUNT, new Account(dataRoot));
		tables.put(Table.Name.PROFILE, new Profile(dataRoot));
		tables.put(Table.Name.DEVICE, new Device(dataRoot));
		tables.put(Table.Name.POSITION, new Position(dataRoot));
		tables.put(Table.Name.MONITOR, new Monitor(dataRoot));
		tables.put(Table.Name.ICON, new Table(dataRoot, Table.Name.ICON));
		tables.put(Table.Name.CRITICAL, new Critical(dataRoot));
		tables.put(Table.Name.SMS, new Table(dataRoot, Table.Name.SMS));
		
		config = getTable(Table.Name.CONFIG).getJSONObject();
		
		if (config.has("iftype")) {
			setValidIFType(config.getString("iftype"));
		}
		
		log = new Log(dataRoot);
		
		initialize();
		
		batch = new Batch(dataRoot);
		
		server = new HTTPServer(this, tcp);
	}
	
	public static void initialize() throws IOException {
		try {
			snmp = new SNMPAgent(dataRoot);
			icmp = new ICMPAgent();
		} catch (IOException ioe) {
			close();
			
			throw ioe;
		}
	}
	
	private Session signIn(JSONObject data) {
		String username = data.getString("username");
		String password = data.getString("password");
		JSONObject accountData = getTable(Table.Name.ACCOUNT).getJSONObject();
		
		if (accountData.has(username)) {
			 JSONObject account = accountData.getJSONObject(username);
			 
			 if (account.getString("password").equals(password)) {
				return Session.getInstance(new JSONObject()
					.put("username", username)
					.put("level", account.getInt("level")));
			 }
		}
		
		return null;
	}

	public static Session getSession(Request request) {
		String cookie = request.getRequestHeader(Request.Header.COOKIE);
		
		if (cookie == null) {
			return null;
		}
		
		String [] cookies = cookie.split("; ");
		String [] token;
		Session session = null;
		
		for(int i=0, length=cookies.length; i<length; i++) {
			token = cookies[i].split("=");
			
			if (token.length == 2 && "SESSION".equals(token[0])) {
				session = Session.find(token[1]);
				
				if (session != null) {
					session.update();
				}
			}
		}
		
		return session;
	}
	
	public static Table getTable(Table.Name name) {
		return tables.get(name);
	}
	
	public static Table getTable(String name) {
		try {
			return tables.get(Table.Name.getName(name));
		}
		catch (IllegalArgumentException iae) {
			return null;
		}
	}
	
	public static JSONObject backup() {
		JSONObject backup = new JSONObject();
		
		for (Table.Name name : Table.Name.values()) {
			backup.put(name.toString(), getTable(name).getJSONObject());
		}
		
		return backup;
	}
	
	public static boolean clean() {
		int day = config.getInt("clean");
		
		if (day > 0) {
			snmp.clean(day);
		}
		
		return true;
	}
	
	public static int getRollingInterval() {
		return config.getInt("interval");
	}
	
	public static void config(String key, Object value) throws IOException {
		config.put(key, value);
		
		getTable(Table.Name.CONFIG).save();
	}
	
	public static void setValidIFType(String iftype) {
		TreeSet<Integer> ts = new TreeSet<>();
		
		for (String type : iftype.split(",")) {
			try {
				ts.add(Integer.parseInt(type));
			}
			catch (NumberFormatException nfe) {}
		}
		
		validIFType = ts.size() == 0? null: ts;
	}
	
	public static boolean isValidIFType(int type) {
		if (validIFType == null) {
			return true;
		}
		
		return validIFType.contains(type);
	}
	
	public static void log(String ip, String message, Log.Type type, boolean status, boolean broadcast) {
		log.write(ip, message, type.toString().toLowerCase(), status, broadcast);
	}
	
	public static void sendEvent(String message) {
		if (config.has("sms") && config.getBoolean("sms")) {
			enterprise.sendEvent(message);
		}
	}
	
	public static void syslog(String msg) {
		Calendar c = Calendar.getInstance();
	
		log.sysLog(String.format("%04d-%02d-%02d %02d:%02d:%02d %s"
			, c.get(Calendar.YEAR)
			, c.get(Calendar.MONTH) +1
			, c.get(Calendar.DAY_OF_MONTH)
			, c.get(Calendar.HOUR_OF_DAY)
			, c.get(Calendar.MINUTE)
			, c.get(Calendar.SECOND), msg));
	}
	
	public static void restore(JSONObject backup) throws Exception {
		Table.Name name;
		Table table;
		
		close();
		
		for (Object key : backup.keySet()) {
			name = Table.Name.getName((String)key);
			
			if (name != null) {
				table = Agent.getTable(name);
				
				if (table != null) {
					table.save(backup.getJSONObject(name.toString()));
				}
			}
		}
		
		initialize();
	}
	
	public static long calcLoad() {
		return snmp.calcLoad();
	}
	
	public static boolean removeSNMPNode(String ip) {
		return snmp.removeNode(ip);
	}
	
	/**
	 * 
	 * @param ip
	 * @param id search로부터 오면 nulle, monitor로부터 오면 device id
	 */
	public static void testSNMPNode(String ip, String id) {
		snmp.testNode(ip, id);
	}
	
	public static boolean removeICMPNode(String ip) {
		return icmp.removeNode(ip);
	}
	
	public static void testICMPNode(String ip) {
		icmp.testNode(ip);
	}
	
	public static void resetCritical(String ip, JSONObject critical) {
		snmp.resetCritical(ip, critical);
	}
	
	public static boolean addUSM(JSONObject usm) {
		return snmp.addUSM(usm);
	}
	
	public static void removeUSM(String usm) {
		snmp.removeUSM(usm);
	}
	
	public static boolean isIdleProfile(String name) {
		return snmp.isIdleProfile(name);
	}
	
	public static JSONObject getNodeData(JSONObject data) {
		SNMPNode node = snmp.getNode(data.getString("ip"));
		
		if (node == null) {
			return null;
		}
		
		return node.getData(data.getString("database"),
			String.valueOf(data.getInt("index")),
			data.getLong("start"),
			data.getLong("end"),
			data.has("summary")? data.getBoolean("summary"): false); 
	}
	
	public static void setInterface(JSONObject device) {
		if (!device.has("ip")) {
			return;
		}
		
		SNMPNode node = snmp.getNode(device.getString("ip"));
		
		if (node == null) {
			return;
		}
		
		node.setInterface(device.has("ifSpeed")? device.getJSONObject("ifSpeed"): new JSONObject());
	}
	
	public static JSONObject getNodeData(String ip, boolean offline) {
		return snmp.getNodeData(ip, offline);
	}
	
	public static JSONObject snmpTest() {
		return snmp.test();
	}
	
	public static JSONObject getTop(int count) {
		return snmp.getTop(count);
	}
	
	public static String report(long start, long end) throws IOException {
		return log.read(start, end);
	}
	
	public static void setCritical(String target, String resource, int rate, boolean overwrite) {
		snmp.setCritical(target, resource, rate, overwrite);
	}
	
	public static void resetResponse(String ip) {
		snmp.resetResponse(ip);
	}
	
	public static JSONObject getFailureRate(String ip) {
		return snmp.getFailureRate(ip);
	}
	
	public static String getLog(long date) throws IOException {
		return log.read(date);
	}
	
	public static String getSyslog(long date) throws IOException {
		return log.getSysLog(date);
	}
	
	public static void listen(Request request, long index) throws IOException {
		log.listen(request, index);
	}
	
	public static void close() {
		if (snmp != null) {
			snmp.close();
		}
		
		if (icmp != null) {
			icmp.close();
		}
	}
	
	public Response executeRequest(Request request, JSONObject data) {		
		String cmd = data.getString("command");
		Session session = getSession(request);
		
		if ("signin".equals(cmd)) {
			if (session == null) {
				try {
					session = signIn(data);
					
					if (session == null) {
						return Response.getInstance(Response.Status.UNAUTHORIZED);
					}
				} catch (JSONException jsone) {
					return Response.getInstance(Response.Status.BADREQUEST
						, new JSONObject().put("error", "invalid json request").toString());
				}
			}
			
			return Response.getInstance(Response.Status.OK, ((JSONObject)session.getExtras()).toString())
				.setResponseHeader("Set-Cookie", String.format("SESSION=%s; HttpOnly", session.getCookie()));
		}
		else if ("signout".equals(cmd)) {
			if (session != null) {
				session.close();
			}
			
			return Response.getInstance(Response.Status.OK);
		}
		
		Command command = Commander.getCommand(cmd);
		
		if (command == null) {
			return Response.getInstance(Response.Status.BADREQUEST
				, new JSONObject().put("error", "invalid command").toString());
		}
		
		try {
			if (session != null) {
				return command.execute(request, data);
			}
		}
		catch (IOException ioe) {
			return Response.getInstance(Response.Status.UNAVAILABLE
				, new JSONObject().put("error", ioe).toString());
		}
		catch (HTTPException httpe) {
			return Response.getInstance(Response.Status.valueOf(httpe.getStatus()));
		}
			
		return Response.getInstance(Response.Status.UNAUTHORIZED);
	}

	public void closeRequest(Request request) {
		log.cancel(request);
	}

	public void stop() {
		close();
		
		batch.stop();
		
		enterprise.close();
		
		try {
			this.server.close();
		} catch (IOException e) {
		}
		
		System.out.println("ITAhM agent down.");
	}

	public static void getInformation(JSONObject jsono) {
		jsono.put("space", root == null? 0: root.getUsableSpace())
		.put("version", VERSION)
		.put("load", batch.load)
		.put("resource", snmp.getResourceCount())
		.put("usage", batch.lastDiskUsage)
		.put("java", System.getProperty("java.version"))
		.put("path", root.getAbsoluteFile().toString())
		.put("license", license == null? false: true)
		.put("demo", isDemo)
		.put("expire", expire);
	}
	
	public static boolean hasMAC(byte [] mac) throws SocketException {
		if (mac == null) {
			return true;
		}
		
		Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();
		NetworkInterface ni;
		byte [] ba;
		
		while(e.hasMoreElements()) {
			ni = e.nextElement();
			
			if (ni.isUp() && !ni.isLoopback() && !ni.isVirtual()) {
				 ba = ni.getHardwareAddress();
				 
				 if(ba!= null) {
					 if (Arrays.equals(mac, ba)) {
						 return true; 
					 }
				 }
			}
		}
		
		return false;
	}
	
	public static void main(String[] args) throws IOException {
		if (!hasMAC(license)) {
			System.out.println("Check your License.");
			
			return;
		}
		
		int tcp = 2014;
		Calendar c = Calendar.getInstance();
		File path = null;
		
		for (int i=0, _i=args.length; i<_i; i++) {
			if (args[i].indexOf("-") != 0) {
				continue;
			}
			
			switch(args[i].substring(1).toUpperCase()) {
			case "DEBUG":
				isDebug = true;
				
				break;
			case "PATH":
				path = new File(args[++i]);
				
				break;
			case "TCP":
				try {
					tcp = Integer.parseInt(args[++i]);
				}
				catch (NumberFormatException nfe) {}
				
				break;
			}
			
		}
		
		try {
			root = path == null? new File(Agent.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParentFile(): path;
			dataRoot = new File(root, DATA);
			
			if (!dataRoot.exists()) {
				if (!dataRoot.mkdir()) {
					System.out.println("데이터베이스를 초기화 할 수 없습니다[1].");
					
					return;
				} 
			}
			else if (!dataRoot.isDirectory()) {
				System.out.println("데이터베이스를 초기화 할 수 없습니다[2].");
				
				return;
			}

			if (isDemo) {
				try {
					c.setTimeInMillis(Files.readAttributes(dataRoot.toPath(), BasicFileAttributes.class).creationTime().toMillis());
				} catch (IOException e) {
					System.out.println("데이터베이스를 초기화 할 수 없습니다[3].");
					
					return;
				}
				
				c.set(Calendar.MONTH, c.get(Calendar.MONTH) +1);
				c.set(Calendar.HOUR_OF_DAY, 0);
				c.set(Calendar.MINUTE, 0);
				c.set(Calendar.SECOND, 0);
				c.set(Calendar.MILLISECOND, 0);
				
				expire = c.getTimeInMillis();
			}
			
			if (expire > 0 && Calendar.getInstance().getTimeInMillis() > expire) {
				System.out.println("라이선스가 만료되었습니다.");
				
				return;
			}
		} catch (URISyntaxException urise) {
			System.out.println("데이터베이스를 초기화 할 수 없습니다[4].");
			
			return;
		}
		
		System.out.format("ITAhM Agent, since 2014.\n");
		System.out.format("Directory : %s\n", root.getAbsoluteFile());
		
		System.out.format("Agent loading...\n");
		
		final Agent agent = new Agent(tcp);
		
		System.out.println("ITAhM agent has been successfully started.");
		
		final Timer timer = new Timer();
		
		timer.schedule(new TimerTask() {	
			
			@Override
			public void run() {
				if (expire > 0 && Calendar.getInstance().getTimeInMillis() > expire) {
					System.out.println("라이선스가 만료되었습니다.");
					
					agent.stop();
					
					timer.cancel();
				}
			}
		}, DAY1);

		try {
			
			Runtime.getRuntime().addShutdownHook(
				new Thread() {
					public void run() {
						agent.stop();
						
						timer.cancel();
					}
				});
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}