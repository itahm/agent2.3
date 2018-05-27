package com.itahm.table;

import java.io.File;
import java.io.IOException;

import com.itahm.json.JSONObject;

import com.itahm.table.Table;

public class Account extends Table {

	public Account(File dataRoot) throws IOException {
		super(dataRoot, Name.ACCOUNT);
		
		if (isEmpty()) {
			getJSONObject()
				.put("root", new JSONObject()
					.put("username", "root")
					.put("password", "63a9f0ea7bb98050796b649e85481845")
					.put("level", 0));
		
			super.save();
		}
	}
}
