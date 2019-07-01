package com.qx.back.io.ssl.inbound;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

import com.qx.back.io.ssl.SSL_Endpoint;

public class Closing extends SSL_InboundMode {
	
	private SSL_Endpoint endpoint;
	
	private SSLEngine engine;
	
	
	public Closing() {
		super();
		
	}

	@Override
	public void bind(SSL_Inbound inbound) {
		engine = inbound.engine;
		endpoint = inbound.endpoint;
	}

	
	public class Task extends SSL_InboundMode.Task {
	
		public Task() {
			super();
		}
		
		@Override
		public SSL_InboundMode.Task run() {
			
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
	
	

}
