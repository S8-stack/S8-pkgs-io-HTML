package com.qx.back.io.ssl.tests;

import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLContext;

import com.qx.back.io.ssl.SSL_Endpoint;
import com.qx.back.io.ssl.SSL_EndpointConfig;
import com.qx.back.io.ssl.SSL_Inbound;
import com.qx.back.io.ssl.SSL_Outbound;

public class SSL_TestEndpoint extends SSL_Endpoint {
	
	
	private SSL_Inbound inbound;

	private SSL_Outbound outbound;
	

	public SSL_TestEndpoint(
			SSL_Inbound inbound,
			SSL_Outbound outbound,
			SSLContext context, 
			AsynchronousSocketChannel channel,
			ExecutorService executor,
			SSL_EndpointConfig config) {
		super(channel, executor, config);
		
		this.inbound = inbound;
		this.outbound = outbound;
		
		start(context, inbound, outbound);
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
