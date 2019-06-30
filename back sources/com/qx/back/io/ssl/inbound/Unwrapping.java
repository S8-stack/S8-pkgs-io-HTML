package com.qx.back.io.ssl.inbound;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

import com.qx.back.base.reactive.QxIOReactive;
import com.qx.back.io.ssl.outbound.SSL_Outbound;

public class Unwrapping extends SSL_InboundMode {

	
	private QxIOReactive receiver;
	
	private SSL_InboundMode pull, closing, requestWrapping, delegatesRunning;

	private SSLEngine engine;

	private ByteBuffer networkBuffer;

	private ByteBuffer applicationBuffer;

	private String name;

	private boolean isVerbose;

	private SSL_Outbound outbound;


	public Unwrapping(SSL_Inbound inbound) {
		super(inbound);
	}


	public void bind() {
		this.name = inbound.name;
		this.engine = inbound.engine;
		this.networkBuffer = inbound.networkBuffer;
		this.applicationBuffer = inbound.applicationBuffer;

		this.receiver = inbound.receiver;
		
		this.outbound = inbound.endpoint.outbound;
		
		// link to other actions
		this.closing = inbound.closing;
		this.requestWrapping = inbound.requestWrapping;
		this.delegatesRunning = inbound.delegatesRunning;
		this.pull = inbound.pull;

		isVerbose = inbound.isVerbose;


	}



	@Override
	public SSL_InboundMode run() {

		try {

			if(isVerbose) {
				System.out.println("\t--->"+name+" is unwrapping... ");
			}
			 
			SSLEngineResult	result = engine.unwrap(networkBuffer, applicationBuffer);
			
			if(isVerbose) {
				System.out.println(name+": "+result);
			}
	
			switch(result.getStatus()) {

			/* 
			 * The SSLEngine was not able to unwrap the incoming data because there 
			 * were not enough source bytes available to make a complete packet. Since
			 * applicationInput
			 */
			case BUFFER_OVERFLOW:

				/* networkInput seems to be sufficiently filled, so must be under-sized */
				if(isNetworkInputHalfFilled()) {
					doubleNetworkInputCapacity();
				}
				/*
				 * In any case, just need to pull more bytes from network 
				 * (/!\ without flashing current ones)
				 */
				// asynchronous, so stop unwrapping and resume on AIO completion

				// need more data, so pull
				return pull; // (immediate next action)


				/*
				 * SSLEngine was not able to process the operation because there 
				 * are not enough bytes available in the destination buffer 
				 * (ApplicationInput) to hold the result.
				 */	
			case BUFFER_UNDERFLOW:

				// so double destination buffer ...
				doubleApplicationInputBufferCapacity();

				// ... and retry
				return this; // (immediate next action)

			case CLOSED: 
				// this side has been closed, so initiate closing
				return closing; // (immediate next action)

			case OK:
				// everything is fine, so process normally
				break;
			}


			switch(result.getHandshakeStatus()) {

			/* From javadoc:
			 * The SSLEngine needs to receive data from the remote side before handshaking can continue.
			 */
			case NEED_UNWRAP: return pull;

			/*
			 * From java doc: The SSLEngine needs to unwrap before handshaking can continue.
			 */
			case NEED_UNWRAP_AGAIN: return this;

			/*
			 * (From java doc): The SSLEngine must send data to the remote side before
			 * handshaking can continue, so SSLEngine.wrap() should be called.
			 */
			case NEED_WRAP: return requestWrapping;
				

			/*
			 * (From java doc): The SSLEngine needs the results of one (or more) delegated
			 * tasks before handshaking can continue.
			 */
			case NEED_TASK: return delegatesRunning;

			/*
			 * From java doc: The SSLEngine has just finished handshaking.
			 */
			case FINISHED:

				/*
				 * End of handshaking, start independent working of inbound/outbound. Since
				 * Inbound MIGHT have been left in idle mode, wake it up to ensure it is active
				 */
				outbound.resume();

				// -> continue to next case
				
			case NOT_HANDSHAKING: 
				

				/* 
				 * ALWAYS drain to supply the upper layer with app data
				 * as EARLY as possible
				 */
				// <drain>
				if(result.bytesProduced()>0) {
					
					// flip buffer to prepare reading (see SSL_EndPoint.onReceived contract).
					/* application input buffer -> WRITE */
					applicationBuffer.flip();

					// apply
					// we ignore the fact that receiver can potentially read more bytes
					receiver.on(applicationBuffer);

					// since endPoint.onReceived read ALL data, nothing left, so clear
					/* application input buffer -> READ */
					applicationBuffer.clear();	
				}
				
				return this;
				
			}
		}
		catch (SSLException e) {
			e.printStackTrace();
			return closing;
		}
		
		return null;		
	}


	private void doubleApplicationInputBufferCapacity() throws SSLException {
		int increasedSize = 2 * applicationBuffer.capacity();
		if (isVerbose) {
			System.out
			.println("[SSL/" + name + "] " + "Application input buffer capacity increased to " + increasedSize);
		}

		if (increasedSize > 4 * engine.getSession().getApplicationBufferSize()) {
			throw new SSLException(
					"[SSL_Inbound] networkInput capacity is now 4x getApplicationBufferSize. " + "Seen as excessive");
		}

		ByteBuffer extendedBuffer = ByteBuffer.allocate(increasedSize);
		applicationBuffer.flip();
		extendedBuffer.put(applicationBuffer);
		applicationBuffer = extendedBuffer;
	}


	private boolean isNetworkInputHalfFilled() {
		return networkBuffer.position()>networkBuffer.capacity()/2;
	}


	private void doubleNetworkInputCapacity() throws SSLException {

		int increasedSize = 2 * networkBuffer.capacity();
		if (isVerbose) {
			System.out.println("[SSL_NetworkInput] " + name + 
					" -> Network input buffer capacity increased to " 
					+ increasedSize);
		}
		if (increasedSize > 4 * engine.getSession().getPacketBufferSize()) {
			throw new SSLException(
					"[SSL_Inbound] networkInput capacity is now 4x getPacketBufferSize. " +
					"Seen as excessive");
		}

		ByteBuffer extendedBuffer = ByteBuffer.allocate(increasedSize);
		networkBuffer.flip();
		extendedBuffer.put(networkBuffer);
		networkBuffer = extendedBuffer;
	}

}
