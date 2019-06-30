package com.qx.back.io.ssl.inbound;

import com.qx.back.io.ssl.outbound.SSL_Outbound;

public class RequestWrapping extends SSL_InboundMode {

	private SSL_Outbound outbound;
	
	public RequestWrapping(SSL_Inbound inbound) {
		super(inbound);
	}
	
	
	@Override
	public void bind() {
		outbound = inbound.endpoint.outbound;
	}

	
	@Override
	public SSL_InboundMode run() {
		
		/* 
		 * Keep track of SSL_Inbound being stop with NO CALLBACK setup. 
		 * Waiting for outboud to wake up.
		 */
		inbound.stop();
		
		/* resume the other side */
		outbound.resume();
		
		// stop and wait to be awaken again by the other side
		return null;
	}
	
}
