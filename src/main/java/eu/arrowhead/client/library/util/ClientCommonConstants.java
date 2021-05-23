package eu.arrowhead.client.library.util;

public class ClientCommonConstants {
	
	//=================================================================================================
	// members

	public static final String CLIENT_SYSTEM_NAME = "client_system_name";
	public static final String $CLIENT_SYSTEM_NAME = "${" + CLIENT_SYSTEM_NAME + "}";
	public static final String CLIENT_SERVER_ADDRESS = "server.address";
	public static final String $CLIENT_SERVER_ADDRESS_WD = "${" + CLIENT_SERVER_ADDRESS + ": localhost" + "}";
	public static final String CLIENT_SERVER_PORT = "server.port";
	public static final String $CLIENT_SERVER_PORT_WD = "${" + CLIENT_SERVER_PORT + ": 8080" + "}";
	public static final String TOKEN_SECURITY_FILTER_ENABLED = "token.security.filter.enabled";
	public static final String $TOKEN_SECURITY_FILTER_ENABLED_WD = "${" + TOKEN_SECURITY_FILTER_ENABLED + ":true" + "}";
	public static final String CORE_SERVICE_DEFINITION_SUFFIX = "-ah.core";
	public static final String MONITOR_CONNECTION_URI = "/index.php?r=api/monitor-connection";
	public static final String TERMINATE_CONNECTION_URI = "/index.php?r=api/terminate-connection";
    public static final String ADD_COMMUNICATION_LOG = "/index.php?r=api/add-communication-log";
    public static final String ADD_ORCHESTRATION_LOG = "/index.php?r=api/add-orchestration-log";
	
	//=================================================================================================
	// assistant methods

	//-------------------------------------------------------------------------------------------------
	private ClientCommonConstants() {
		throw new UnsupportedOperationException();
	}
}
