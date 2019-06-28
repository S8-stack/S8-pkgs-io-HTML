package com.qx.back.io.ssl;

import java.io.File;

import com.qx.back.lang.xml.XML_Context;
import com.qx.back.lang.xml.annotation.XML_SetElement;
import com.qx.back.lang.xml.annotation.XML_Type;

@XML_Type(name="SSL_EndpointConfig", sub= {})
public class SSL_EndpointConfig {

	private String name = "NotNamed";

	private boolean isServerSide = true;
	
	private boolean isSSLVerbose = false;

	private long timeout = 10;

	public String getName() {
		return name;
	}


	public boolean isServerSide() {
		return isServerSide;
	}

	public long getTimeout() {
		return timeout;
	}
	
	

	public boolean isSSLVerbose() {
		return isSSLVerbose;
	}

	@XML_SetElement(name="SSL-verbose")
	public void setSSLVerbose(boolean isVerbose) {
		this.isSSLVerbose = isVerbose;
	}
	
	@XML_SetElement(name="server-side")
	public void setServerSide(boolean isServerSide) {
		this.isServerSide = isServerSide;
	}

	@XML_SetElement(name="timeout")
	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}

	@XML_SetElement(name="name")
	public void setName(String name) {
		this.name = name;
	}
	
	public static SSL_EndpointConfig load(String pathname) throws Exception {
		XML_Context context = new XML_Context(SSL_EndpointConfig.class);
		return (SSL_EndpointConfig) context.deserialize(new File(pathname));
	}
	
}
