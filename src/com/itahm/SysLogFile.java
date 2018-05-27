package com.itahm;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import com.itahm.util.DailyFile;

public class SysLogFile extends DailyFile {

	public SysLogFile(File root) throws IOException {
		super(root);
	}

	public void write(byte [] data) throws IOException {
		super.roll();
		
		try(FileOutputStream fos = new FileOutputStream(super.file, true)) {
			fos.write(data);
		}
	}
	
}
