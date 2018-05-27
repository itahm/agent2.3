package com.itahm;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Calendar;

import com.itahm.json.JSONObject;
import com.itahm.util.DailyFile;
import com.itahm.util.Util;

public class LogFile extends DailyFile {

	private final File backup;
	private JSONObject log;
	private int index = 0;
	
	public LogFile(File root) throws IOException {
		super(root);
		
		backup = new File(root, "backup");
		
		if (!super.file.isFile() || ((log = Util.getJSONFromFile(super.file)) == null && !restore())) {
			log = new JSONObject();
			
			write();
		}
		
		for (Object key : log.keySet()) {
			index = Math.max(index, Integer.parseInt((String)key));
		}
	}
	
	public JSONObject getLog(String index) {
		if (this.log.has(index)) {
			return this.log.getJSONObject(index);
		}
		
		return null;
	}
	
	public synchronized void write(JSONObject log) throws IOException {
		String index = Long.toString(this.index++ & 0xffffffffL);
		
		log.put("index", index);
		
		if (super.roll()) {
			this.log.clear();
		}
		
		this.log.put(index, log);
		
		write();
	}
	
	private void write() throws IOException {
		// dailyFile 은 쓰기와 읽기가 별개임 (읽기는 파일로부터 직접) 동기화 불필요.
		byte [] ba = this.log.toString().getBytes(StandardCharsets.UTF_8);
		
		super.write(ba);
		
		DailyFile.write(this.backup, ba);
	}
	
	private boolean restore() throws IOException {
		if (!this.backup.isFile()) {
			return false;
		}
		
		Calendar c = Calendar.getInstance();
		long today = Util.trimDate(c).getTimeInMillis();
		
		c.setTimeInMillis(this.backup.lastModified());
		
		if (Util.trimDate(c).getTimeInMillis() != today) {
			return false;
		}
		
		try (FileOutputStream fos = new FileOutputStream(super.file)) {
			fos.write(Files.readAllBytes(this.backup.toPath()));
			
			this.log = Util.getJSONFromFile(super.file);
			
			if (this.log == null) {
				return false;
			}
		}
		
		return true;
	}
}
