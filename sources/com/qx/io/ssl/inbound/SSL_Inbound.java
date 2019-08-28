package com.qx.io.ssl.inbound;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;

import com.qx.io.ssl.SSL_Endpoint;
import com.qx.io.ssl.outbound.SSL_Outbound;
import com.qx.io.ssl.outbound.Wrapping;
import com.qx.io.web.rx.RxInbound;


/**
 * Inbound part of the SSL_Endpoint
 * 
 * @author pc
 *
 */
public abstract class SSL_Inbound extends RxInbound {


	/**
	 * Typical required NETWORK_INPUT_STARTING_CAPACITY is 16709. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int NETWORK_INPUT_STARTING_CAPACITY = 17408;


	/**
	 * Typical required APPLICATION_INPUT_STARTING_CAPACITY is 16704. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int APPLICATION_INPUT_STARTING_CAPACITY = 17408;


	//private RxInbound base;

	private String name;

	private SSL_Endpoint endpoint;

	private SSLEngine engine;

	private ByteBuffer applicationBuffer;

	private SSL_Outbound outbound;

	private boolean isVerbose;

	private Mode callback;


	/**
	 * 
	 * @param channel
	 */
	public SSL_Inbound() {
		super(NETWORK_INPUT_STARTING_CAPACITY);

		/* <buffers> */

		applicationBuffer = ByteBuffer.allocate(APPLICATION_INPUT_STARTING_CAPACITY);
		// left in write mode

		/* </buffer> */
	}

	@Override
	public void onRxReceived() {
		Mode startMode = callback!=null?callback:new Unwrapping(SSL_Inbound.this);
		callback = null; // reset callback
		new Process(startMode).launch();
	}

	public abstract void SSL_onReceived(ByteBuffer buffer);

	
	public void SSL_bind(SSL_Endpoint endpoint, SSLEngine engine) {

		// bind 0
		this.endpoint = endpoint;
		this.engine = engine;

		this.isVerbose = endpoint.isVerbose();	
		this.outbound = endpoint.getOutbound();
		name = endpoint.getName()+".inbound";
	}


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
				System.out.println("exiting process...");
			}

		}

		/*
		public void then(Mode nextMode) {
			isRunning = true;
			mode = nextMode;
		}

		public void stop() {
			isRunning = false;
			mode = unwrap();
		}

		public void pullThenStop() {
			isRunning = false;
			receive();
			mode = unwrap();
		}

		public void pullThen(Mode nextMode) {
			isRunning = false;
			receive();
			mode = nextMode;
		}
		 */

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

		public abstract String declare();

		/**
		 * 
		 */
		public abstract void run(Process process);


		/**
		 * ALWAYS drain to supply the upper layer with app data
		 * as EARLY as possible
		 */
		public void drain() {

			// flip buffer to prepare reading (see SSL_EndPoint.onReceived contract).
			/* application input buffer -> WRITE */
			applicationBuffer.flip();

			// apply
			// we ignore the fact that receiver can potentially read more bytes
			SSL_onReceived(applicationBuffer);

			// since endPoint.onReceived read ALL data, nothing left, so clear
			/* application input buffer -> READ */
			applicationBuffer.clear();	

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


		public ByteBuffer resizeNetworkBuffer(int capacity) {
			return resizeBuffer(capacity);
		}

		public ByteBuffer getApplicationBuffer() { 
			return applicationBuffer;
		}

		public ByteBuffer resizeApplicationBuffer(int increasedCapacity) {
			return (applicationBuffer = ByteBuffer.allocate(increasedCapacity));
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
			return new RunningDelegates(SSL_Inbound.this, callback);
		}

		public Mode unwrap() {
			return new Unwrapping(SSL_Inbound.this);
		}

		public Mode close() {
			return new Closing(SSL_Inbound.this);
		}

		/**
		 * trigger another reception
		 * @param mode the callback mode
		 */
		public void pull(Mode mode) {
			callback = mode;
			receive();
		}

		public void wrap() {
			if(isVerbose) {
				System.out.println("\t--->"+name+" is requesting wrap...");	
			}

			// trigger unwrapping
			outbound.new Process(new Wrapping(outbound)).launch();
		}
	}

}
