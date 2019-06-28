package com.qx.back.io.ssl.tests;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLContext;

import com.qx.back.io.ssl.SSL_Endpoint;
import com.qx.back.io.ssl.SSL_EndpointConfig;
import com.qx.back.io.ssl.SSL_Inbound;
import com.qx.back.io.ssl.SSL_Module;
import com.qx.back.io.ssl.SSL_Outbound;


public class SSL_Test03 {

	public static void main(String[] args) throws Exception {

		System.out.println("Starting...");
		SSLContext context = SSL_Module.createContext("config/server/SSL_config.xml");
		InetSocketAddress address = new InetSocketAddress("localhost", 1024);

		SSL_EndpointConfig serverConfig = SSL_EndpointConfig.load("config/server/ssl-test-config.xml");
		SSL_EndpointConfig clientConfig = SSL_EndpointConfig.load("config/client/ssl-test-config.xml");
		

		/* server part */
		AsynchronousChannelGroup group = 
				AsynchronousChannelGroup.withThreadPool(Executors.newFixedThreadPool(2));

		AsynchronousServerSocketChannel server = AsynchronousServerSocketChannel.open(group)
				.bind(address, 64);

		Thread thread = new Thread(new Runnable() {

			@Override
			public void run() {
				while(true){
					try {
						AsynchronousSocketChannel channel = server.accept().get();
						ExecutorService internal = Executors.newSingleThreadExecutor();


						SSL_Endpoint serverEndPoint = new SSL_TestEndpoint(
								
								new SSL_Inbound() {
									@Override
									public boolean onReceived(ByteBuffer buffer) {
										int n = buffer.limit();
										byte[] bytes = new byte[n];
										buffer.get(bytes);
										System.out.println("[SSL_Test03] "+new String(bytes));
										return true; // always receiving
									}
								},
								new SSL_Outbound() {
									
									private int count = 0;

									@Override
									public boolean onSending(ByteBuffer buffer) {
										if(count<4) {
											buffer.put("Hi! this is server side!!".getBytes());
											count++;	
										}
										return false;
									}
								},
								context, channel, internal, serverConfig);

						// start
						serverEndPoint.receive();
					}
					catch (InterruptedException | ExecutionException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
		});
		thread.start();


		/*
		 * client part
		 */

		AsynchronousChannelGroup group2 = 
				AsynchronousChannelGroup.withThreadPool(Executors.newFixedThreadPool(2));

		AsynchronousSocketChannel channel = AsynchronousSocketChannel.open(group2);
		channel.connect(address).get();

		ExecutorService internal2 = Executors.newSingleThreadExecutor();



		SSL_Endpoint client = new SSL_TestEndpoint(
				new SSL_Inbound() {
					@Override
					public boolean onReceived(ByteBuffer buffer) {
						int n = buffer.limit();
						byte[] bytes = new byte[n];
						buffer.get(bytes);
						System.out.println("[SSL_Test03] "+new String(bytes));
						return true; // only receiving after emitting
					}
				},
				new SSL_Outbound() {

					private int count = 0;

					@Override
					public boolean onSending(ByteBuffer buffer) {
						byte[] messageBytes = "Hi this is client!!".getBytes();
						if(count<4 && buffer.remaining()>messageBytes.length) {
							buffer.put(messageBytes);
						}
						count++;
						return true; // ignored
					}
				},
				context, channel, internal2, clientConfig);


		new Thread(new Runnable() {

			@Override
			public void run() {
				client.send();
			}
		}).start();
	}
}
