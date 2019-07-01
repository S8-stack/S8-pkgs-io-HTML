package com.qx.back.io.ssl.inbound;

abstract class SSL_InboundMode {
	
	public SSL_InboundMode() {
		super();
	}

	
	/**
	 * 
	 */
	public abstract void bind(SSL_Inbound inbound);
	
	
	public abstract class Task {
		
		/**
		 * 
		 * @return
		 */
		public abstract SSL_InboundMode.Task run();		
	}
	

	
}
