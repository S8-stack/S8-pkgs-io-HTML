package com.qx.io.ssl.outbound;

import com.qx.io.ssl.inbound.SSL_Inbound;

public class UnwrapRequesting extends SSL_OutboundMode {

	private SSL_Outbound outbound;
	private SSL_Inbound inbound;
	private String name;
	private boolean isVerbose;

	public UnwrapRequesting() {
		super();
	}

	
	public class Task extends SSL_OutboundMode.Task {
	
		@Override
		public SSL_OutboundMode.Task run() {

			if(isVerbose) {
				System.out.println("\t--->"+name+" is requesting unwrap...");	
			}

			outbound.stop();
			
			/* Resume inbound operation if not active */
			inbound.resume();
			
			// stop and wait to be awaken again
			return null;
		}
	}


	@Override
	public void bind(SSL_Outbound outbound) {
		this.outbound = outbound;
		inbound = outbound.endpoint.inbound;
		name = outbound.name;
		isVerbose = outbound.isVerbose;
	}	

}
