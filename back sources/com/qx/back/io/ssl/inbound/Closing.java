package com.qx.back.io.ssl.inbound;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

import com.qx.back.io.ssl.SSL_Endpoint;

public class Closing extends SSL_InboundMode {
	
	private SSL_Endpoint endpoint;
	
	private SSLEngine engine;

	public Closing(SSL_Inbound inbound) {
		super(inbound);
		
	}

	@Override
	public void bind() {
		engine = inbound.engine;
		endpoint = inbound.endpoint;
	}

	@Override
	public SSL_InboundMode run() {
		
		try {
			engine.closeInbound();
		} 
		catch (SSLException e) {
			e.printStackTrace();
		}
		engine.closeOutbound();
		
		endpoint.close();
		
		return null;
	}

}
