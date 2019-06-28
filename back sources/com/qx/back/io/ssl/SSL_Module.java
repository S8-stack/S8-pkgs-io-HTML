package com.qx.back.io.ssl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import com.qx.back.lang.xml.XML_Context;
import com.qx.back.lang.xml.annotation.XML_GetElement;
import com.qx.back.lang.xml.annotation.XML_SetElement;
import com.qx.back.lang.xml.annotation.XML_Type;

/**
 * Handle SSL stuff
 * 
 * <p>
 * how-to: GENERATE a new keystore with cmd (on terminal):
 * </p>
 * 
 * <ul>
 * <li><b>Generate the server certificate.</b>: Type the keytool command all on
 * one line:
 * <code>pc$ keytool -genkey -alias server-alias -keyalg RSA -keypass rDfe4_!xef 
 * -storepass rDfe4_!xef -keystore keystore.jks</code></li>
 * 
 * 
 * 
 * When you press Enter, keytool prompts you to enter the server name,
 * organizational unit, organization, locality, state, and country code.
 * 
 * You must type the server name in response to keytool’s first prompt, in which
 * it asks for first and last names. For testing purposes, this can be
 * localhost.
 * 
 * When you run the example applications, the host (server name) specified in
 * the keystore must match the host identified in the javaee.server.name
 * property specified in the file
 * tut-install/examples/bp-project/build.properties.
 * 
 * <p>
 * </p>
 * 
 * @author pc
 *
 *
 */
public class SSL_Module {


	@XML_Type(name="SSL_configuration")
	public static class Configuration {

		public String keystorePathname;

		public String keystorePassword;

		public String encryptionProtocol = "TLSv1.2";

		@XML_GetElement(name="keystore_pathname")
		public String getKeystorePathname() {
			return keystorePathname;
		}

		@XML_SetElement(name="keystore_pathname")
		public void setKeystorePathname(String keystorePathname) {
			this.keystorePathname = keystorePathname;
		}

		@XML_GetElement(name="keystore_password")
		public String getKeystorePassword() {
			return keystorePassword;
		}

		@XML_SetElement(name="keystore_password")
		public void setKeystorePassword(String keystorePassword) {
			this.keystorePassword = keystorePassword;
		}

		@XML_GetElement(name="encryption_protocol")
		public String getEncryptionProtocol() {
			return encryptionProtocol;
		}

		@XML_SetElement(name="encryption_protocol")
		public void setEncryptionProtocol(String encryptionProtocol) {
			this.encryptionProtocol = encryptionProtocol;
		}

	}


	public static SSLContext createContext(Configuration configuration) 
			throws 
			KeyManagementException, 
			NoSuchAlgorithmException, 
			CertificateException, 
			FileNotFoundException, 
			IOException, 
			KeyStoreException, 
			UnrecoverableKeyException 
	{
		char[] password = configuration.keystorePassword.toCharArray();

		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(new File(configuration.keystorePathname)), password);

		// Create key managers
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		keyManagerFactory.init(keyStore, password);
		KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

		// Create trust managers
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
		trustManagerFactory.init(keyStore);
		TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

		SSLContext sslContext = SSLContext.getInstance(configuration.encryptionProtocol);
		sslContext.init(keyManagers, trustManagers, new SecureRandom());

		return sslContext;
	}


	public static SSLContext createContext(String pathname) throws Exception {

		// retrieve configuration
		Reader reader = new BufferedReader(new InputStreamReader(new FileInputStream(new File(pathname))));
		XML_Context context = new XML_Context(Configuration.class);
		Configuration configuration = (Configuration) context.deserialize(reader);
		reader.close();

		return createContext(configuration);
	}


}
