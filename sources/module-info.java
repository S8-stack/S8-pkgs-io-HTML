/**
 * 
 */
/**
 * @author pc
 *
 */
module com.qx.io.ssl {
	
	exports com.qx.io.ssl.inbound;
	exports com.qx.io.ssl.outbound;
	exports com.qx.io.ssl;

	requires transitive com.qx.base;
	requires transitive com.qx.lang.xml;
}