package com.qx.io.ssl.tests;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import javax.net.ssl.SSLContext;

import com.qx.io.ssl.SSL_Module;
import com.qx.io.ssl.inbound.SSL_Inbound;
import com.qx.io.ssl.outbound.SSL_Outbound;
import com.qx.io.web.rx.RxWebClient;
import com.qx.io.web.rx.RxWebEndpoint;
import com.qx.io.web.rx.RxWebServer;

public class SSL_RoundTrip02 {

	public static void main(String[] args) throws Exception {

		System.out.println("Starting...");
		SSLContext context = SSL_Module.createContext("config/SSL_config.xml");


		RxWebServer server = new RxWebServer(1336) {

			@Override
			public RxWebEndpoint createEndpoint(Selector selector, SocketChannel socketChannel) throws IOException {

				return new SSL_Endpoint_Impl02(
						selector, socketChannel, 
						new SSL_Inbound() {

							@Override
							public void SSL_onReceived(ByteBuffer buffer) {
								int n = buffer.limit();
								byte[] bytes = new byte[n];
								buffer.get(bytes);
								System.out.println("[SSL_Test03] "+new String(bytes));
							}
						},
						new SSL_Outbound() {
							private int count = 0;

							@Override
							public void SSL_onSending(ByteBuffer buffer) {
								if(count<4) {
									buffer.put("Hi! this is server side!!".getBytes());
									count++;	
								}
							}
						},
						"server", context, true, true);
			}
		};
		

		RxWebClient client = new RxWebClient("localhost", 1336) {

			@Override
			public RxWebEndpoint createEndpoint(Selector selector, SocketChannel socketChannel) throws IOException {
				return new SSL_Endpoint_Impl02(
						selector, socketChannel, 
						new SSL_Inbound() {

							@Override
							public void SSL_onReceived(ByteBuffer buffer) {
								int n = buffer.limit();
								byte[] bytes = new byte[n];
								buffer.get(bytes);
								System.out.println("[SSL_Test03] "+new String(bytes));
							}
						},
						new SSL_Outbound() {
							private int count = 0;

							@Override
							public void SSL_onSending(ByteBuffer buffer) {

								byte[] messageBytes = "Hi this is client!!".getBytes();
								if(count<4 && buffer.remaining()>messageBytes.length) {
									buffer.put(messageBytes);
								}
								count++;	
							}
						},
						"client", context, false, true);
			}
		};
		
		// lauching sequence
		
		server.start();

		client.start();
		client.send();

	}

}
