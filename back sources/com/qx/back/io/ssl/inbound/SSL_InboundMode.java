package com.qx.back.io.ssl.inbound;

public abstract class SSL_InboundMode {

	public SSL_Inbound inbound;
	
	public SSL_InboundMode(SSL_Inbound inbound) {
		super();
		this.inbound = inbound;
	}

	
	/**
	 * 
	 */
	public abstract void bind();
	
	
	/**
	 * 
	 * @return
	 */
	public abstract SSL_InboundMode run();
	
}
