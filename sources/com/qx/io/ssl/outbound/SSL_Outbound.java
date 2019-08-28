package com.qx.io.ssl.outbound;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;

import com.qx.io.ssl.SSL_Endpoint;
import com.qx.io.ssl.inbound.SSL_Inbound;
import com.qx.io.ssl.inbound.Unwrapping;
import com.qx.io.web.rx.RxOutbound;


/**
 * <p>
 * SSL_Outbound
 * </p>
 * <p>
 * SSL_Outbound is a state machine. States are called <code>Mode</code>
 * </p>
 * 
 * @author pc
 *
 */
public abstract class SSL_Outbound extends RxOutbound {

	private String name;

	private SSL_Endpoint endpoint;

	private SSLEngine engine;

	private ByteBuffer applicationBuffer;

	private SSL_Inbound inbound;



	/**
	 * Typical required NETWORK_OUTPUT_STARTING_CAPACITY is 16709. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int NETWORK_OUTPUT_STARTING_CAPACITY = 17408;


	/**
	 * Typical required APPLICATION_OUTPUT_STARTING_CAPACITY is 16704. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408.
	 * Replace by 2^15 (for beauty purposes)
	 */
	public final static int APPLICATION_OUTPUT_STARTING_CAPACITY = 17408;


	private boolean isVerbose;

	private Mode callback;

	/**
	 * 
	 * @param channel
	 */
	public SSL_Outbound() {
		super(NETWORK_OUTPUT_STARTING_CAPACITY);


		/* <buffers> */

		/* 
		 * Left in read mode outside retrieve state. So initialize with nothing to read
		 */
		applicationBuffer = ByteBuffer.allocate(APPLICATION_OUTPUT_STARTING_CAPACITY);
		applicationBuffer.position(0);
		applicationBuffer.limit(0);

		/* </buffer> */
	}

	@Override
	public void onRxSending() {
		Mode startMode = callback!=null?callback:new Wrapping(SSL_Outbound.this);
		callback = null; // reset callback
		new Process(startMode).launch();
	}

	@Override
	public void onRxRemotelyClosed() {
		endpoint.isClosed = true;
		new Process(new Closing(SSL_Outbound.this)).launch();
	}

	@Override
	public void onRxFailed() {
		if(isVerbose) {
			exception.printStackTrace();
		}
		endpoint.isClosed = true;
		new Process(new Closing(SSL_Outbound.this)).launch();
	}



	public void SSL_bind(SSL_Endpoint endpoint, SSLEngine engine) {
		
		// bind 0
		this.endpoint = endpoint;
		this.engine = engine;
		
		this.isVerbose = endpoint.isVerbose();	
		this.inbound = endpoint.getInbound();
		name = endpoint.getName()+".outbound";
	}


	/**
	 * 
	 * @param buffer
	 */
	public abstract void SSL_onSending(ByteBuffer buffer);





	public class Process {

		// Next mode to be played
		public Mode mode;

		//Must be reset after use
		public boolean isRunning = false;

		public Process(Mode mode) {
			super();
			this.mode = mode;
		}

		public void launch() {

			// reset pushing flag
			isRunning = true;

			/*
			 * Note: Even if nothing has been written, we'll add so new bytes before retrying
			 */
			while(isRunning) {
				
				mode.advertise();
				
				mode.run(this);
			}
			
			if(isVerbose) {
				System.out.println(name+": is exiting process...");
			}
		}
	}


	/**
	 * External access handle
	 * 
	 * @author pc
	 *
	 */
	public abstract class Mode {


		public Mode() {
			super();
		}

		public void advertise() {
			if(isVerbose) {
				System.out.println("\t--->"+getName()+": "+declare());
			}
		}
		
		/**
		 * 
		 * @return
		 */
		public abstract String declare();
		
		/**
		 * 
		 */
		public abstract void run(Process process);


		public void pump() {
			/* Application buffer is left in read mode (to be able to perform wrap). */
			applicationBuffer.compact();

			/* peform the "pumping" operation */
			SSL_onSending(applicationBuffer);

			/* return to read mode */
			applicationBuffer.flip();
		}


		/**
		 * <p>
		 * <b>Important notice</b>: ByteBuffer buffer (as retrieved by
		 * <code>getNetworkBuffer()</code> method) is passed in write mode state.
		 * </p>
		 * 
		 * @return the network buffer
		 */
		public ByteBuffer getNetworkBuffer() { 
			return getBuffer();
		}

		/**
		 * Resize 
		 * @param capacity
		 * @return
		 */
		public ByteBuffer resizeNetworkBuffer(int capacity) {
			return resizeBuffer(capacity);
		}

		public ByteBuffer getApplicationBuffer() { 
			return applicationBuffer;
		}

		public String getName() { 
			return name; 
		}

		public SSLEngine getEngine() { 
			return engine; 
		}

		public SSL_Endpoint getEndpoint() { 
			return endpoint;
		}

		public boolean isVerbose() { 
			return isVerbose;
		}




		public Mode runDelegates(Mode callback) {
			return new RunningDelegates(SSL_Outbound.this, callback);
		}

		public Mode wrap() {
			return new Wrapping(SSL_Outbound.this);
		}

		public Mode flush() {
			return new Flushing(SSL_Outbound.this);
		}

		public Mode close() {
			return new Closing(SSL_Outbound.this);
		}

		public void setCallback(Mode mode) {
			callback = mode;
		}
		
		public void push() {
			send();
		}
		
		public void unwrap() {
			if(isVerbose) {
				System.out.println("\t--->"+name+" is requesting unwrap...");	
			}

			// trigger unwrapping
			inbound.new Process(new Unwrapping(inbound)).launch();
		}
	}
}
