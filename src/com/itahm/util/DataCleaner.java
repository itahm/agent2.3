package com.itahm.util;

import java.io.File;
import java.util.Calendar;

abstract public class DataCleaner implements Runnable{

	private final long minDateMills;
	private File dataRoot;
	private int depth;
	private Thread thread;
	
	public DataCleaner(File dataRoot, long minDateMills) {
		this(dataRoot, minDateMills, 0);
	}
	
	public DataCleaner(File dataRoot, long minDateMills, int depth) {
		this.dataRoot = dataRoot;
		this.minDateMills = minDateMills;
		this.depth = depth;
		
		thread = new Thread(this);
		
		thread.start();
	}

	private long emptyLastData(File directory, int depth) {
		File [] files = directory.listFiles();
		long count = 0;
		
		for (File file: files) {
			if (this.thread.isInterrupted()) {
				break;
			}
			
			if (file.isDirectory()) {
				if (depth > 0) {
					count += emptyLastData(file, depth -1);
				}
				else {
					try {
						if (minDateMills > Long.parseLong(file.getName())) {
							if (deleteDirectory(file)) {
								count++;
								
								onDelete(file);
							}
						}
					}
					catch (NumberFormatException nfe) {
					}
				}
			}
		}
		
		return count;
	}
	
	public static boolean deleteDirectory(File directory) {
        if(!directory.exists() || !directory.isDirectory()) {
            return false;
        }
        
        File[] files = directory.listFiles();
        
        for (File file : files) {
            if (file.isDirectory()) {
                deleteDirectory(file);
            } else {
                file.delete();
            }
        }
         
        return directory.delete();
    }
	
	abstract public void onDelete(File file);
	abstract public void onComplete(long count);
	
	public void run() {
		long count = -1;
		
		if (this.dataRoot.isDirectory()) {
			count = emptyLastData(this.dataRoot, this.depth);
		}
		
		onComplete(count);
	}
	
	public void cancel() {
		this.thread.interrupt();
	}
	
	public static void main(String[] args) {
		Calendar date = Calendar.getInstance();
		
		date.set(Calendar.MONTH, date.get(Calendar.MONTH) -1);
		
		new DataCleaner(new File("."), date.getTimeInMillis(), 1) {
			
			@Override
			public void onDelete(File file) {
			}
			
			@Override
			public void onComplete(long count) {
			}
		};
	}

}
