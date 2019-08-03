package com.qx.io.ssl.tests;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import com.qx.io.ssl.SSL_Module;

public class SSL_Test01 {

	public static void main(String[] args) throws Exception {

		SSLContext context = SSL_Module.createContext("config/server/SSL_config.xml");
		SSLEngine engine = context.createSSLEngine();
		SSLParameters params = engine.getSSLParameters();
		params.setApplicationProtocols(new String[] {"h2"});
		params.setMaximumPacketSize(4096);
		engine.setSSLParameters(params);
		
		System.out.println(engine.getSSLParameters().getMaximumPacketSize());
		System.out.println(engine.getSession().getPacketBufferSize());
		System.out.println(engine.getSession().getApplicationBufferSize());
		System.out.println(context.getSupportedSSLParameters().getMaximumPacketSize());
		System.out.println(context.getDefaultSSLParameters().getMaximumPacketSize());
	}
}
