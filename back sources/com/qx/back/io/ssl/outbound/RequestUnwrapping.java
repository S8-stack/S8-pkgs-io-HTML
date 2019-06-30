package com.qx.back.io.ssl.outbound;

import com.qx.back.io.ssl.inbound.SSL_Inbound;

public class RequestUnwrapping extends SSL_OutboundMode {

	private SSL_Inbound inbound;

	public RequestUnwrapping(SSL_Outbound outbound) {
		super(outbound);
	}

	@Override
	public void bind() {
		inbound = outbound.endpoint.inbound;
	}

	@Override
	public SSL_OutboundMode run() {

		outbound.stop();
		
		/* Resume inbound operation if not active */
		inbound.resume();
		
		// stop and wait to be awaken again
		return null;
	}

}
