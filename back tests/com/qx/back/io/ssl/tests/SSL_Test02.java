package com.qx.back.io.ssl.tests;

import javax.net.ssl.SSLContext;

import com.qx.back.io.ssl.SSL_Module;

public class SSL_Test02 {

	public static void main(String[] args) throws Exception {

		SSLContext context = SSL_Module.createContext("config/server/SSL_config.xml");
		
		// create end points
		SSL_EndpointUnitTest02 server = new SSL_EndpointUnitTest02.Server(context);
		SSL_EndpointUnitTest02 client = new SSL_EndpointUnitTest02.Client(context);

		// connect end points together
		server.transportInput = client.transportOutput;
		client.transportInput = server.transportOutput;

		/*
		 * Examining the SSLEngineResults could be much more involved,
		 * and may alter the overall flow of the application.
		 *
		 * For example, if we received a BUFFER_OVERFLOW when trying
		 * to write to the output pipe, we could reallocate a larger
		 * pipe, but instead we wait for the peer to drain it.
		 */
		boolean isTransferred = false;
		while (!isTransferred && (!client.isClosed() || !server.isClosed())) {

			System.out.println("[loop] ================");

			client.send();
			server.send();

			server.transportInput.flip();
			client.transportInput.flip();

			System.out.println("----");

			client.receive();
			server.receive();

			server.transportInput.compact();
			client.transportInput.compact();
			
			if(client.isSent() && server.isSent()) {
				System.out.println(" **** Done **** ");
				if(client.isReceived() && server.isReceived()) {
					isTransferred = true;
					System.out.println(" **** Successfully transferred **** ");
				}
			}
		}
	}
}
