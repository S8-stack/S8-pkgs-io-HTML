package com.qx.back.io.ssl.inbound;

import com.qx.back.io.ssl.outbound.SSL_Outbound;

public class WrapRequesting extends SSL_InboundMode {

	private SSL_Inbound inbound;
	
	private SSL_Outbound outbound;
	
	private boolean isVerbose;
	
	private String name;
	
	public WrapRequesting() {
		super();
	}
	
	
	
	public class Task extends SSL_InboundMode.Task {
	

		@Override
		public SSL_InboundMode.Task run() {
			
			if(isVerbose) {
				System.out.println("\t--->"+name+" is requesting wrap...");	
			}
			
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
	

	@Override
	public void bind(SSL_Inbound inbound) {
		this.inbound = inbound;
		outbound = inbound.endpoint.outbound;
		name = inbound.name;
		isVerbose = inbound.isVerbose;
	}

	
}
