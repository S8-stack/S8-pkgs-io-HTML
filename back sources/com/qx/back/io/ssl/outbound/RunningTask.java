package com.qx.back.io.ssl.outbound;

import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLEngine;

public class RunningTask extends SSL_OutboundMode {

	private boolean isVerbose;
	
	private SSLEngine engine;

	public ExecutorService internalExecutor;
	
	private SSL_OutboundMode wrapping;
	
	
	public RunningTask(SSL_Outbound inbound) {
		super(inbound);
	}

	@Override
	public void bind() {
		isVerbose = outbound.isVerbose;
		engine = outbound.engine;
		internalExecutor = outbound.internalExecutor;
		wrapping =outbound.wrapping;
	}

	@Override
	public SSL_OutboundMode run() {
		
		Runnable taskRunnable = engine.getDelegatedTask();

		if(taskRunnable!=null) {
			if(isVerbose) {
				System.out.println("\trunning delegated task...");	
			}
			internalExecutor.execute(new Runnable() {
				
				@Override
				public void run() {
					
					// perform the task
					taskRunnable.run();
					
					// then try to run other task
					outbound.run(RunningTask.this);
				}
			});
			return null; // stop here and wait for the task to awake back inbound
		}
		else {
			/*
			 * Directly switch back to wrapping
			 */
			return wrapping;
		}
	}

}
