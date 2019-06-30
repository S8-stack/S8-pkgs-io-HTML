package com.qx.back.io.ssl.outbound;

public abstract class SSL_OutboundMode {

	public SSL_Outbound outbound;
	
	public SSL_OutboundMode(SSL_Outbound outbound) {
		super();
		this.outbound = outbound;
	}

	
	/**
	 * 
	 */
	public abstract void bind();
	
	
	/**
	 * 
	 * @return
	 */
	public abstract SSL_OutboundMode run();
	
}
