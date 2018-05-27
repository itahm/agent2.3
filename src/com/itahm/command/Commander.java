package com.itahm.command;

public enum Commander {
	PULL("com.itahm.command.Pull"),
	PUSH("com.itahm.command.Push"),
	PUT("com.itahm.command.Put"),
	QUERY("com.itahm.command.Query"),
	SELECT("com.itahm.command.Select"),
	LISTEN("com.itahm.command.Listen"),
	CONFIG("com.itahm.command.Config"),
	EXTRA("com.itahm.command.Extra");
	
	private String className;
	
	private Commander(String s) {
		className = s;
	}
	
	private Command getCommand() {
		try {
			return (Command)Class.forName(this.className).newInstance();
		} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
		}
		
		return null;
	}
	
	public static Command getCommand(String command) {
		try {
			return valueOf(command.toUpperCase()).getCommand();
		}
		catch (IllegalArgumentException iae) {
		}
	
		return null;
	}
}
