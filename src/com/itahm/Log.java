package com.itahm;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Set;

import com.itahm.json.JSONObject;
import com.itahm.http.Request;
import com.itahm.http.Response;
import com.itahm.util.Util;

public class Log {

	public enum Type {
		SYSTEM, SHUTDOWN, CRITICAL;
	};

	public final static String SHUTDOWN = "shutdown";
	public final static String CRITICAL = "critical";
	
	private final Set<Request> waiter = new HashSet<Request> ();
	private LogFile dailyFile;
	private SysLogFile sysLog;
	
	public Log(File root) throws IOException {
		File logRoot = new File(root, "log");
		File systemRoot = new File(logRoot, "system");
		
		logRoot.mkdir();
		systemRoot.mkdir();
		
		dailyFile = new LogFile(logRoot);
		sysLog = new SysLogFile(systemRoot);
	}
	
	public String getSysLog(long mills) throws IOException {
		byte [] sysLog = this.sysLog.read(mills);
		
		if (sysLog == null) {
			sysLog = new byte [0];
		}
		
		return new String(sysLog, StandardCharsets.UTF_8.name());
	}
	
	public void write(String ip, String message, String type, boolean status, boolean broadcast) {
		JSONObject logData = new JSONObject();
		
		logData
			.put("ip", ip)
			.put("type", type)
			.put("status", status)
			.put("message", message)
			.put("date", Calendar.getInstance().getTimeInMillis());
			
		try {
			this.dailyFile.write(logData);
		} catch (IOException ioe) {
			sysLog(Util.EToString(ioe));
		}
		
		synchronized(this.waiter) {
			Response response = Response.getInstance(Response.Status.OK, logData.toString());
			
			for (Request request : this.waiter) {
				try {
					HTTPServer.sendResponse(request, response);
				} catch (IOException ioe) {
					sysLog(Util.EToString(ioe));
				}
			}
			
			waiter.clear();
		}
		
		if(broadcast) {
			Agent.sendEvent(message);
		}
	}
	
	public void sysLog(String log) {
		try {
			this.sysLog.write((log + System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public String read(long mills) throws IOException {
		byte [] bytes = this.dailyFile.read(mills);
		
		if (bytes != null) {
			return new String(bytes, StandardCharsets.UTF_8.name());
		}
		
		return new JSONObject().toString();
	}
	
	public String read(long start, long end) throws IOException {
		JSONObject jsono = new JSONObject();
		Calendar c = Calendar.getInstance();
		
		c.setTimeInMillis(start);
		
		for (; start <= end; c.set(Calendar.DATE, c.get(Calendar.DATE) +1), start = c.getTimeInMillis()) {
			byte [] bytes = this.dailyFile.read(start);
		
			if (bytes == null) {
				continue;
			}
			
			jsono.put(Long.toString(start), new JSONObject(new String(bytes, StandardCharsets.UTF_8.name())));
		}
		
		return jsono.toString();
	}
	
	/**
	 * waiter가 원하는 이벤트 있으면 돌려주고 없으면 waiter 큐에 추가  
	 * @param waiter
	 * @throws IOException 
	 */
	public void listen(Request request, long l) throws IOException {
		String index = Long.toString(l);
		JSONObject log = this.dailyFile.getLog(index);
		
		if (log == null) {
			synchronized(this.waiter) {
				this.waiter.add(request);
			}
		}
		else {
			HTTPServer.sendResponse(request, Response.getInstance(Response.Status.OK, log.toString()));
		}
	}
	
	public void cancel(Request request) {
		synchronized(this.waiter) {
			this.waiter.remove(request);
		}
	}
	
}
