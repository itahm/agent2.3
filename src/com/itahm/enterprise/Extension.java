package com.itahm.enterprise;

import org.snmp4j.PDU;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;

import com.itahm.SNMPNode;
import com.itahm.http.Request;
import com.itahm.http.Response;
import com.itahm.json.JSONObject;

public interface Extension {
	
	/**
	 * 
	 * @param pdu
	 * set enterprise specific variable bindings
	 */
	
	public void setRequestOID(PDU pdu);
	/**
	 * 
	 * @param node
	 * @param response
	 * @param variable
	 * @param request
	 * @return true if next request available.
	 */
	
	public boolean parseRequest(SNMPNode node, OID response, Variable variable, OID request);
	/**
	 * 
	 * @param node
	 * @param response
	 * @param variable
	 * @return false if this trap is not enterprise specific.
	 */
	
	public boolean parseTrap(SNMPNode node, OID response, Variable variable);
	
	/**
	 * 
	 * @param request
	 * @param data
	 * @return
	 */
	public Response execute(Request request, JSONObject data);
	
}
