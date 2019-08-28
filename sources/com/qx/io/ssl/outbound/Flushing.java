package com.qx.io.ssl.outbound;

import java.nio.ByteBuffer;

public class Flushing extends SSL_Outbound.Mode {


	public Flushing(SSL_Outbound outbound) {
		outbound.super();
	}

	@Override
	public String declare() {
		return "is flushing...";
	}
	

	@Override
	public void run(SSL_Outbound.Process process) {

		ByteBuffer networkBuffer = getNetworkBuffer();

		// if there is actually new bytes, send them
		if(networkBuffer.position()>0) {

			// stop this process here (trigger sending)
			process.isRunning = false;

			// setup callback as this to continue on this mode asynchronously
			setCallback(this);

			push(); // trigger another write attempt
		}
		else {
			// stop this process here (trigger sending)
			process.isRunning = false;
		}
	}

}