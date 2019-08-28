package com.qx.io.ssl.inbound;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

public class Unwrapping extends SSL_Inbound.Mode {


	public Unwrapping(SSL_Inbound inbound) {
		inbound.super();
	}
	
	@Override
	public String declare() {
		return "is unwrapping...";
	}




	@Override
	public void run(SSL_Inbound.Process process) {

		try {

			// if nothing to read in network buffer, go back to pulling
			/*
				if(!networkBuffer.hasRemaining()) {
					return pulling.new Task();
				}
			 */

			SSLEngineResult	result = getEngine().unwrap(getNetworkBuffer(), getApplicationBuffer());

			if(isVerbose()) {
				System.out.println(getName()+": "+result);
			}

			// drain as soon as bytes available
			if(result.bytesProduced()>0) {
				drain();
			}

			switch(result.getHandshakeStatus()) {

			/*
			 * From javadoc -> The SSLEngine needs to receive data from the remote side
			 * before handshaking can continue.
			 */
			case NEED_UNWRAP: 

				switch(result.getStatus()) {

				case BUFFER_UNDERFLOW: handleBufferUnderflow(process); break;

				case BUFFER_OVERFLOW: handleBufferOverflow(); break;

				// this side has been closed, so initiate closing
				case CLOSED: 
					process.mode = close();
					break;

					// everything is fine, so process normally
				case OK: 
					process.mode = this; 
					break;
				}

				break; // </NEED_WRAP>

				/*
				 * From java doc: The SSLEngine needs to unwrap before handshaking can continue.
				 */
			case NEED_UNWRAP_AGAIN: 

				switch(result.getStatus()) {

				case BUFFER_UNDERFLOW: handleBufferUnderflow(process); break;

				case BUFFER_OVERFLOW: handleBufferOverflow(); break;

				// this side has been closed, so initiate closing
				case CLOSED: 
					process.mode = close();
					break;

					// then(this); keep on unwrapping
				case OK: 
					process.mode = this;
					break;
				}
				break; // </NEED_UNWRAP_AGAIN>

				/*
				 * (From java doc): The SSLEngine must send data to the remote side before
				 * handshaking can continue, so SSLEngine.wrap() should be called.
				 */
			case NEED_WRAP: 

				switch(result.getStatus()) {

				// this side has been closed, so initiate closing
				case CLOSED: 
					process.mode = close();
					break;

				case BUFFER_UNDERFLOW: // ignored since WRAP is required

				case BUFFER_OVERFLOW: // ignored since WRAP is required

				case OK: // everything is fine, so process normally
					
					process.isRunning = false; // stop current process
					wrap(); // trigger wrap
					break;

				}
				break; // </NEED_WRAP>

				/*
				 * (From java doc): The SSLEngine needs the results of one (or more) delegated
				 * tasks before handshaking can continue.
				 */
			case NEED_TASK: 

				switch(result.getStatus()) {

				case BUFFER_UNDERFLOW: handleBufferUnderflow(process); break;

				case BUFFER_OVERFLOW: handleBufferOverflow(); break; 

				// this side has been closed, so initiate closing
				case CLOSED:
					process.mode = close();
					break;

				case OK: 
					process.mode = runDelegates(this); 
					break;
				}
				break; // </NEED_TASK>

				/*
				 * From java doc: The SSLEngine has just finished handshaking.
				 */
			case FINISHED:

				/*
				 * End of handshaking, start independent working of inbound/outbound. Since
				 * Inbound MIGHT have been left in idle mode, wake it up to ensure it is active
				 */
				wrap();


				// -> continue to next case

			case NOT_HANDSHAKING: 

				switch(result.getStatus()) {

				case BUFFER_UNDERFLOW: handleBufferUnderflow(process); break;

				case BUFFER_OVERFLOW: handleBufferOverflow(); break;

				// this side has been closed, so initiate closing
				case CLOSED: 
					process.mode = close();
					break;

				// everything is fine, so process normally
				case OK: 
					process.mode = this; // no effect, for clarity purposes
					break;
				}
				break; // </NOT_HANDSHAKING>
			}
		}
		catch (SSLException e) {
			e.printStackTrace();
			process.mode = close();
		}
	}










	/**
	 * <p>
	 * (From javadoc): The SSLEngine was not able to unwrap the incoming data
	 * because there were not enough source bytes available to make a complete
	 * packet.
	 * </p>
	 * <p>
	 * Two reasons are possible:
	 * </p>
	 * <ul>
	 * <li>Not enough bytes pulled from the network -> need to pull</li>
	 * <li>Not enough space in the network incoming buffer -> need to increase size
	 * and retry to pull to fill</li>
	 * </ul>
	 * 
	 * @throws SSLException
	 */
	private void handleBufferUnderflow(SSL_Inbound.Process process) throws SSLException {

		/* 
		 * networkInput seems to be sufficiently filled, so must be under-sized 
		 */
		if(isNetworkInputHalfFilled()) {
			doubleNetworkInputCapacity();
		}

		/*
		 * In any case, just need to pull more bytes from network 
		 * (/!\ without flashing current ones) and come back to unwrap
		 */
		// asynchronous, so stop unwrapping and resume on AIO completion

		// need more data, so pull and then come back to this mode
		pull(this);
		
		// stop process
		process.isRunning = false;
	}


	/**
	 * <p>(from javadoc) SSLEngine was not able to process the operation because there 
	 * are not enough bytes available in the destination buffer 
	 * (ApplicationInput) to hold the result.
	 * </p>
	 * <p>
	 * </p>
	 * @throws SSLException 
	 */
	public void handleBufferOverflow() throws SSLException {

		// so double destination buffer ...
		doubleApplicationInputBufferCapacity();

	}

	private boolean isNetworkInputHalfFilled() {
		ByteBuffer networkBuffer = getNetworkBuffer();
		return networkBuffer.position()>networkBuffer.capacity()/2;
	}



	private void doubleNetworkInputCapacity() throws SSLException {
		ByteBuffer networkBuffer = getNetworkBuffer();

		int increasedCapacity = 2 * networkBuffer.capacity();
		if (isVerbose()) {
			System.out.println("[SSL_NetworkInput] " + getName() + 
					" -> Network input buffer capacity increased to " 
					+ increasedCapacity);
		}
		if (increasedCapacity > 4 * getEngine().getSession().getPacketBufferSize()) {
			throw new SSLException(
					"[SSL_Inbound] networkInput capacity is now 4x getPacketBufferSize. " +
					"Seen as excessive");
		}

		ByteBuffer extendedBuffer = resizeNetworkBuffer(increasedCapacity);
		networkBuffer.flip();
		extendedBuffer.put(networkBuffer);
	}


	private void doubleApplicationInputBufferCapacity() throws SSLException {
		ByteBuffer applicationBuffer = getApplicationBuffer();
		int increasedSize = 2 * applicationBuffer.capacity();
		if (isVerbose()) {
			System.out
			.println("[SSL/" + getName() + "] " + "Application input buffer capacity increased to " + increasedSize);
		}

		if (increasedSize > 4 * getEngine().getSession().getApplicationBufferSize()) {
			throw new SSLException(
					"[SSL_Inbound] Application buffer capacity is now "
							+ "4x getApplicationBufferSize. " + "Seen as excessive");
		}



		ByteBuffer extendedBuffer = resizeApplicationBuffer(increasedSize);
		applicationBuffer.flip();
		extendedBuffer.put(applicationBuffer);
	}
}
