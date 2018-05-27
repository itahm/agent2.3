package com.itahm.icmp;

public interface ICMPListener {
	public void onSuccess(ICMPNode node, long time);
	public void onFailure(ICMPNode node);
}
