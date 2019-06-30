package com.qx.back.io.ssl.inbound;

import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLEngine;

public class RunningTask extends SSL_InboundMode {

	private boolean isVerbose;
	
	private SSLEngine engine;

	public ExecutorService internalExecutor;
	
	private SSL_InboundMode unwrapping;
	
	
	public RunningTask(SSL_Inbound inbound) {
		super(inbound);
	}

	@Override
	public void bind() {
		isVerbose = inbound.isVerbose;
		engine = inbound.engine;
		internalExecutor = inbound.internalExecutor;
		unwrapping = inbound.unwrapping;
	}

	@Override
	public SSL_InboundMode run() {
		
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
					inbound.run(RunningTask.this);
				}
			});
			return null; // stop here and wait for the task to awake back inbound
		}
		else {
			/*
			 * Directly switch back to unwrapping
			 */
			return unwrapping;
		}
	}

}
