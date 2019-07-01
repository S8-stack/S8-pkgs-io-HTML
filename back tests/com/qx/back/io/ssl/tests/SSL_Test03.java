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

import com.qx.back.base.reactive.QxIOReactive;
import com.qx.back.io.ssl.SSL_Endpoint;
import com.qx.back.io.ssl.SSL_Module;


public class SSL_Test03 {

	public static void main(String[] args) throws Exception {

		System.out.println("Starting...");
		SSLContext context = SSL_Module.createContext("config/SSL_config.xml");
		InetSocketAddress address = new InetSocketAddress("localhost", 1024);
		

		/* server part */
		AsynchronousChannelGroup group = 
				AsynchronousChannelGroup.withThreadPool(Executors.newFixedThreadPool(2));

		AsynchronousServerSocketChannel server = AsynchronousServerSocketChannel.open(group)
				.bind(address, 64);

		
		QxIOReactive serverInbound = new QxIOReactive() {
			
			@Override
			public void on(ByteBuffer buffer) {
				int n = buffer.limit();
				byte[] bytes = new byte[n];
				buffer.get(bytes);
				System.out.println("[SSL_Test03] "+new String(bytes));
			}
		};
		
		
		QxIOReactive serverOutbound = new QxIOReactive() {
			
			private int count = 0;

			@Override
			public void on(ByteBuffer buffer) {
				if(count<4) {
					buffer.put("Hi! this is server side!!".getBytes());
					count++;	
				}
			}
		};
		
		
		Thread thread = new Thread(new Runnable() {

			@Override
			public void run() {
				while(true){
					try {
						AsynchronousSocketChannel channel = server.accept().get();
						ExecutorService internal = Executors.newSingleThreadExecutor();


						SSL_Endpoint serverEndPoint = new SSL_Endpoint("server", 
								serverInbound, serverOutbound, context, 
								channel, 1000000,
								internal, true, true);

						// start
						serverEndPoint.start();
					}
					catch (InterruptedException | ExecutionException e) {
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

		
		QxIOReactive clientInbound = new QxIOReactive() {
			
			@Override
			public void on(ByteBuffer buffer) {
				int n = buffer.limit();
				byte[] bytes = new byte[n];
				buffer.get(bytes);
				System.out.println("[SSL_Test03] "+new String(bytes));
			}
		};

		QxIOReactive clientOutbound = new QxIOReactive() {
			private int count = 0;

			@Override
			public void on(ByteBuffer buffer) {
				byte[] messageBytes = "Hi this is client!!".getBytes();
				if(count<4 && buffer.remaining()>messageBytes.length) {
					buffer.put(messageBytes);
				}
				count++;
			}
		};

		SSL_Endpoint client = new SSL_Endpoint("client",
				clientInbound, clientOutbound, context, 
				channel, 1000000,
				internal2, false, true);


		new Thread(new Runnable() {

			@Override
			public void run() {
				client.start();
			}
		}).start();
	}
}
