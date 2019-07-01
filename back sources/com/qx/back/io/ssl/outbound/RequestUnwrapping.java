package com.qx.back.io.ssl.outbound;

import com.qx.back.io.ssl.inbound.SSL_Inbound;

public class RequestUnwrapping extends SSL_OutboundMode {

	private SSL_Outbound outbound;
	private SSL_Inbound inbound;

	public RequestUnwrapping() {
		super();
	}

	@Override
	public void bind(SSL_Outbound outbound) {
		this.outbound = outbound;
		inbound = outbound.endpoint.inbound;
	}
	
	public class Task extends SSL_OutboundMode.Task {
	
		@Override
		public SSL_OutboundMode.Task run() {

			outbound.stop();
			
			/* Resume inbound operation if not active */
			inbound.resume();
			
			// stop and wait to be awaken again
			return null;
		}
	}

	

}
