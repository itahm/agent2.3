package com.itahm.enterprise;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Calendar;

import com.itahm.Agent;
import com.itahm.json.JSONObject;
import com.itahm.table.Table;

public class KIER extends Enterprise {

	public final String KEY = "01F10774-7EDA-409A-A545-117228B4E3B2";
	public static final int LICENSE = 100;
	
	private static final String URL = "jdbc:oracle:thin:@203.241.220.20:1522:portal";
	private static final String USER = "KIERWEB";
	private static final String PASSWD = "KIERWEBpw";
	
	public static String getDateString() {
		Calendar c = Calendar.getInstance();
		
		return String.format("%04d%02d%02d%02d%02d%02d",
				c.get(Calendar.YEAR),
				c.get(Calendar.MONTH) +1,
				c.get(Calendar.DATE),
				c.get(Calendar.HOUR_OF_DAY),
				c.get(Calendar.MINUTE),
				c.get(Calendar.SECOND));
	}
	
	public static void sendEvent(Statement s, String date, String event, String to) throws SQLException {
		s.executeUpdate(String.format("insert into SMSLIST (M_INDEX, TO_NUM, TRS_TIME, MSG, SENDER_ID)"
			+" values (NEXT_SMSLIST_SEQ.nextval, '%s', '%s', '%s', 'NMS')"
			, to /* 수신 */
			, date /* 송신 시간 */
			, event /* 메세지 */ ));
	}
	
	@Override
	public void sendEvent(String event) {
		try (Connection connection = DriverManager.getConnection(URL, USER, PASSWD)) {
			try (Statement s = connection.createStatement()) {
				JSONObject smsData = Agent.getTable(Table.Name.SMS).getJSONObject();
				String date = KIER.getDateString();
				
				for (Object id : smsData.keySet()) {
					sendEvent(s, date, event, smsData.getJSONObject((String)id).getString("number"));
				}
			}
		} catch (SQLException sqle) {
			sqle.printStackTrace();
		}
	}
	
}
