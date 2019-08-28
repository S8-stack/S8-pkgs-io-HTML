package com.qx.io.ssl.inbound;

import javax.net.ssl.SSLException;

public class Closing extends SSL_Inbound.Mode {


	public Closing(SSL_Inbound inbound) {
		inbound.super();
	}



	@Override
	public String declare() {
		return "is closing";
	}


	@Override
	public void run(SSL_Inbound.Process process) {

		try {
			getEngine().closeInbound();
		} 
		catch (SSLException e) {
			e.printStackTrace();
		}
		getEngine().closeOutbound();

		getEndpoint().close();
		process.isRunning = false;

	}


}
