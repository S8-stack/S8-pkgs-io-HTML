package com.qx.io.ssl.tests;

import java.io.IOException;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import javax.net.ssl.SSLContext;

import com.qx.io.ssl.SSL_Endpoint;
import com.qx.io.ssl.inbound.SSL_Inbound;
import com.qx.io.ssl.outbound.SSL_Outbound;

public class SSL_Endpoint_Impl02 extends SSL_Endpoint {

	
	private SSL_Inbound inbound;
	
	
	private SSL_Outbound outbound;
	
	
	public SSL_Endpoint_Impl02(
			Selector selector, 
			SocketChannel socketChannel, 
			SSL_Inbound inbound,
			SSL_Outbound outbound,
			String name, 
			SSLContext context,
			boolean isServerSide, 
			boolean isVerbose) throws IOException {
		super(selector, socketChannel, name, context, isServerSide, isVerbose);
		
		this.inbound = inbound;
		this.outbound = outbound;
		
		SSL_bind();
	}


	@Override
	public SSL_Inbound getInbound() {
		return inbound;
	}


	@Override
	public SSL_Outbound getOutbound() {
		return outbound;
	}

}
