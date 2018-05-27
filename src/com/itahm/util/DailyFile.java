package com.itahm.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Calendar;

public class DailyFile {

	private final File root;
	protected File file;
	private int day = 0;
	
	public DailyFile(File root) throws IOException {
		this.file = new File(root, Long.toString(Util.trimDate(Calendar.getInstance()).getTimeInMillis()));
		
		this.root = root;
	}
	
	public boolean roll() throws IOException {
		Calendar c = Calendar.getInstance();
		int day = c.get(Calendar.DAY_OF_YEAR);
		boolean roll = false;
		
		if (this.day != day) {
			Util.trimDate(c);
			
			file = new File(this.root, Long.toString(c.getTimeInMillis()));
			
			if (this.day != 0) {
				roll = true;
			}
			
			this.day = day;
		}
		
		return roll;
	}
	
	public long size() {
		return this.file.length();
	}
	
	public byte [] read() throws IOException {
		return Files.readAllBytes(this.file.toPath());
	}
	
	public byte [] read(long mills) throws IOException {
		File f = new File(this.root, Long.toString(mills));
		
		if (!f.isFile()) {
			return null;
		}
		
		return Files.readAllBytes(f.toPath());
	}
	
	public void write(byte [] data) throws IOException {
		write(this.file, data);
	}
	
	public static void write(File file, byte [] data) throws IOException {
		try(FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(data);
		}
	}
	
}
