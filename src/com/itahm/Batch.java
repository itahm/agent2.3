package com.itahm;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import com.itahm.json.JSONObject;

public class Batch {
	private final static int QUEUE_SIZE = 24;
	private final static long MINUTE1 = 60 *1000;
	private final static long MINUTE10 = MINUTE1 *10;
	private final static long HOUR1 = MINUTE1 *60;
	private final static long DAY1 = 24 * HOUR1;
	
	private final Timer timer = new Timer();;
	
	public long lastDiskUsage = 0;
	public JSONObject load = new JSONObject();
	
	public Batch(final File dataRoot) {
		System.out.println("Batch scheduling...");
		
		scheduleDiskMonitor(dataRoot);
		System.out.println("Free space monitor up.");
		
		scheduleUsageMonitor(new File(dataRoot, "node"));
		System.out.println("Disk usage monitor up.");
		
		scheduleLoadMonitor();
		System.out.println("Server load monitor up.");
		
		scheduleDiskCleaner();
		System.out.println("Disk cleaner up.");
	}
	
	public void stop() {
		this.timer.cancel();
	}
	
	private final void scheduleUsageMonitor(final File nodeRoot) {
		Calendar c = Calendar.getInstance();
		
		c.set(Calendar.DATE, c.get(Calendar.DATE) +1);
		c.set(Calendar.HOUR_OF_DAY, 0);
		c.set(Calendar.MINUTE, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MILLISECOND, 0);
		
		this.timer.schedule(new TimerTask() {

			@Override
			public void run() {
				Calendar c = Calendar.getInstance();
				File dir;
				long size = 0;
				
				c.set(Calendar.DATE, c.get(Calendar.DATE) -1);
				c.set(Calendar.HOUR_OF_DAY, 0);
				c.set(Calendar.MINUTE, 0);
				c.set(Calendar.SECOND, 0);
				c.set(Calendar.MILLISECOND, 0);
				
				if (nodeRoot.isDirectory()) {
					for (File node: nodeRoot.listFiles()) {
						try {
							InetAddress.getByName(node.getName());
							
							if (node.isDirectory()) {
								for (File rsc : node.listFiles()) {
									if (rsc.isDirectory()) {
										for (File index : rsc.listFiles()) {
											if (index.isDirectory()) {
												dir = new File(index, Long.toString(c.getTimeInMillis()));
												
												if (dir.isDirectory()) {
													
													for (File file : dir.listFiles()) {
														size += file.length();
													}
												}
											}
										}
									}
								}
							}
						} catch (UnknownHostException uhe) {
						}
					}
				}
				
				lastDiskUsage = size;
			}
		}, c.getTime(), 24 * 60 * 60 * 1000);
	}
	
	private final void scheduleDiskCleaner() {
		Calendar c = Calendar.getInstance();
		
		c.set(Calendar.DATE, c.get(Calendar.DATE) +1);
		c.set(Calendar.HOUR_OF_DAY, 0);
		c.set(Calendar.MINUTE, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MILLISECOND, 0);
		
		Agent.clean();
		
		this.timer.schedule(new TimerTask() {

			@Override
			public void run() {
				Agent.clean();
			}
			
		}, c.getTime(), DAY1);
	}
	
	private final void scheduleDiskMonitor(final File root) {
		this.timer.schedule(new TimerTask() {
			private final static long MAX = 100;
			private final static long CRITICAL = 10;
			
			private long lastFreeSpace = MAX;
			private long freeSpace;
			
			@Override
			public void run() {
					freeSpace = MAX * root.getUsableSpace() / root.getTotalSpace();
					
					if (freeSpace < lastFreeSpace && freeSpace < CRITICAL) {
						Agent.log("ITAhM", String.format("저장 여유공간 %d%%", freeSpace), Log.Type.SYSTEM, false, true);
					}
					
					lastFreeSpace = freeSpace;
					
			}
		}, 0, MINUTE1);
	}

	private final void scheduleLoadMonitor() {
		
		this.timer.schedule(new TimerTask() {
			private Long [] queue = new Long[QUEUE_SIZE];
			private Map<Long, Long> map = new HashMap<>();
			private Calendar c;
			private int position = 0;
			
			@Override
			public void run() {
				long key;
				
				c = Calendar.getInstance();
				
				c.set(Calendar.MINUTE, 0);
				c.set(Calendar.SECOND, 0);
				c.set(Calendar.MILLISECOND, 0);
				
				key = c.getTimeInMillis();
				
				if (this.map.put(key, Agent.calcLoad()) == null) {
					if (this.queue[this.position] != null) {
						this.map.remove(this.queue[this.position]);
					}
					
					this.queue[this.position++] = key;
					
					this.position %= QUEUE_SIZE;
					
					load = new JSONObject(this.map);
				}
				
			}}, MINUTE10, MINUTE10);
	}
}
