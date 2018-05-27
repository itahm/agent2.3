package com.itahm.http;

import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class Session {

	private static final Map<String, Session> sessions = new ConcurrentHashMap<>();
	private static final Timer timer = new Timer(true);
	
	private static long timeout = 30*60*1000;
	//static long timeout = 60 * 1000;
	
	private final String cookie;
	private final Object extras;
	private TimerTask task;
	
	private Session() {
		cookie = null;
		this.extras = null;
	}
	
	private Session(String uuid, Object extras) {
		cookie = uuid;
		this.extras = extras;
		
		update();
	}
	
	public static Session getInstance(Object extras) {
		String uuid = UUID.randomUUID().toString();
		Session session = new Session(uuid, extras);
		
		sessions.put(uuid, session);
		
		return session;
	}
	
	public static Session getInstance() {
		
		return new Session();
	}
	
	public static int count() {
		return sessions.size();
	}
	
	public static Session find(String cookie) {
		return sessions.get(cookie);
	}
	
	public static void setTimeout(long newTimeout) {
		timeout = newTimeout;
	}
	
	public String getCookie() {
		return this.cookie;
	}
	
	public Object getExtras() {
		return this.extras;
	}
	
	public void update() {
		final String cookie = this.cookie;
		
		if (this.task != null) {
			this.task.cancel();
		}
		
		this.task = new TimerTask() {

			@Override
			public void run() {
				sessions.remove(cookie);
			}
		};
		
		timer.schedule(this.task, timeout);
	}
	
	public void close() {
		this.task.cancel();
		
		sessions.remove(cookie);
	}
	
}
