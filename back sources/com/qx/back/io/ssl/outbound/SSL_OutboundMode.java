package com.qx.back.io.ssl.outbound;

public abstract class SSL_OutboundMode {

	
	public SSL_OutboundMode() {
		super();
	}

	
	/**
	 * 
	 */
	public abstract void bind(SSL_Outbound outbound);
	
	
	public abstract class Task {
	
		/**
		 * 
		 * @return
		 */
		public abstract Task run();
		
	}
	
	
}
