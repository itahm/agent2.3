package com.itahm.json;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Calendar;

import com.itahm.json.JSONObject;
import com.itahm.util.Util;

/**
 * The Class RollingFile.
 */
public class RollingFile {
	
	private long load;
	
	/** The lastHour. */
	private long lastHour = -1;
	private long lastDay = -1;
	
	/** rollingRoot, itahm/snmp/ip address/resource/index */
	private final File root;
	
	private File summaryFile;
	private JSONObject summaryData;
	private JSONObject summary;
	private String summaryHour;
	
	private File dayDirectory;
	private File hourFile;
	private JSONObject hourData;
	private long max;
	private long min;
	private BigInteger summarySum = BigInteger.valueOf(0);
	private int summaryCount = 0;
	private BigInteger valueSum = BigInteger.valueOf(0);
	private long valueCount = 0;
	
	public RollingFile(File rscRoot, String index) throws IOException {
		Calendar c = Calendar.getInstance();
		
		c.set(Calendar.MILLISECOND, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MINUTE, 0);
		
		root = new File(rscRoot, index);
		root.mkdir();
		
		this.lastHour = c.getTimeInMillis();
		this.summaryHour = Long.toString(this.lastHour);
				
		c.set(Calendar.HOUR_OF_DAY, 0);
		
		this.lastDay = c.getTimeInMillis();
		
		this.dayDirectory = new File(this.root, Long.toString(this.lastDay));
		this.dayDirectory.mkdir();
		
		// summary file 생성
		this.summaryFile = new File(this.dayDirectory, "summary");
		
		// 존재하면 load
		if (this.summaryFile.isFile()) {
			this.summaryData = Util.getJSONFromFile(this.summaryFile);
		}
		
		// 존재하지 않거나 파일에 문제가 있는 경우
		if (this.summaryData == null) {
			Util.putJSONtoFile(this.summaryFile, this.summaryData = new JSONObject());
		}
		
		if (this.summaryData.has(this.summaryHour)) {
			summary = this.summaryData.getJSONObject(this.summaryHour);
		}
		else {
			this.summaryData.put(this.summaryHour, summary = new JSONObject());
		}
		
		// hourly file 생성
		this.hourFile = new File(this.dayDirectory, this.summaryHour);
		
		// 존재하면 load
		if (this.hourFile.isFile()) {
			this.hourData = Util.getJSONFromFile(this.hourFile);
		}
		
		// 존재하지 않거나 파일에 문제가 있는 경우
		if (this.hourData == null) {
			Util.putJSONtoFile(this.hourFile, this.hourData = new JSONObject());
		}
	}
	
	public void roll(long value, int interval) throws IOException {
		Calendar c = Calendar.getInstance();
		String minString;
		long hourMills, dayMills, elapse;

		c.set(Calendar.MILLISECOND, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MINUTE, c.get(Calendar.MINUTE) /interval * interval);
		
		minString = Long.toString(c.getTimeInMillis());
		
		c.set(Calendar.MINUTE, 0);
		hourMills = c.getTimeInMillis();
		
		if (this.lastHour != hourMills) {
			// 시간마다 summary 파일과 시간파일 저장
			
			calcSummary();
			
			elapse = System.currentTimeMillis();
			
			Util.putJSONtoFile(this.summaryFile, this.summaryData);
			Util.putJSONtoFile(this.hourFile, this.hourData);
			
			this.load = System.currentTimeMillis() - elapse;
			
			c.set(Calendar.HOUR_OF_DAY, 0);
			dayMills = c.getTimeInMillis();
			
			if (this.lastDay != dayMills) {
				this.lastDay = dayMills;
				
				// day directory 생성
				this.dayDirectory = new File(this.root, Long.toString(dayMills));
				this.dayDirectory.mkdir();
				
				// summary file 생성
				this.summaryFile = new File(this.dayDirectory, "summary");
				this.summaryData = new JSONObject();
			}
			
			// hourly file 생성
			this.lastHour = hourMills;
			this.summaryHour = Long.toString(hourMills);
			this.hourFile = new File(this.dayDirectory, this.summaryHour);
			this.hourData = new JSONObject();
			this.summaryCount = 0;
			this.summaryData.put(this.summaryHour, this.summary = new JSONObject());
		}
		
		if (this.hourData.has(minString)) {
			this.valueSum = this.valueSum.add(BigInteger.valueOf(value));
		}
		else {
			this.valueSum = BigInteger.valueOf(value);
			this.valueCount = 0;
		}
		
		this.valueCount++;
		
		this.hourData.put(minString, this.valueSum.divide(BigInteger.valueOf(this.valueCount)));
		
		if (this.summaryCount == 0) {
			this.summarySum = BigInteger.valueOf(value);
			this.max = value;
			this.min = value;
		}
		else {
			this.summarySum = this.summarySum.add(BigInteger.valueOf(value));
			this.max = Math.max(this.max, value);
			this.min = Math.min(this.min, value);
		}
		
		this.summaryCount++;

		// summarize
		long avg = this.summarySum.divide(BigInteger.valueOf(this.summaryCount)).longValue();

		this.summary
			.put("max", Math.max(avg, this.max))
			.put("min", Math.min(avg, this.min));
	}
	
	public JSONObject getData(long start, long end, boolean summary) throws IOException {
		JSONObject data;
		final long now = Calendar.getInstance().getTimeInMillis();
		
		if (summary) {
			data = new JSONSummary(this.root).getJSON(start, end);

			if (start < now && now < end) {
				calcSummary();
				
				for (Object key : this.summaryData.keySet()) {
					data.put((String)key, this.summaryData.getJSONObject((String)key));
				}
			}
		}
		else {
			data = new JSONData(this.root).getJSON(start, end);
			
			if (start < now && now < end) {
				for (Object key : this.hourData.keySet()) {
					data.put((String)key, this.hourData.getLong((String)key));
				}
			}
		}
			
		return data;
	}
	
	private void calcSummary() {
		BigInteger sum = BigInteger.valueOf(0);
		int count = 0;
		
		for (Object key : this.hourData.keySet()) {
			sum = sum.add(BigInteger.valueOf(this.hourData.getLong((String)key)));
			
			count++;
		}
		
		this.summary.put("avg", count > 0? sum.divide(BigInteger.valueOf(count)).longValue(): 0);
	}
	
	public long getLoad() {
		return this.load;
	}
	
}

