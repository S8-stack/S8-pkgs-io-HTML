package com.qx.io.ssl.outbound;

public class RunningDelegates extends SSL_Outbound.Mode {


	private SSL_Outbound.Mode callback;

	public RunningDelegates(SSL_Outbound outbound, SSL_Outbound.Mode callback) {
		outbound.super();
		this.callback = callback;
	}
	
	@Override
	public String declare() {
		return "is running delegates...";
	}
	

	@Override
	public void run(SSL_Outbound.Process process) {

		Runnable taskRunnable = getEngine().getDelegatedTask();

		if(taskRunnable!=null) {
			if(isVerbose()) {
				System.out.println("\trunning delegated task...");	
			}
			// perform the task
			taskRunnable.run();
		}

		/*
		 * Switch back to callback
		 */
		process.mode = callback;

	}
}
