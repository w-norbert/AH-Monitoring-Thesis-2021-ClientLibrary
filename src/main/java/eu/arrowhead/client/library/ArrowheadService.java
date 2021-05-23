package eu.arrowhead.client.library;


import java.math.BigInteger;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Date;

import javax.annotation.Resource;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.mysql.cj.xdevapi.JsonArray;
import eu.arrowhead.common.dto.shared.*;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import eu.arrowhead.client.library.util.ClientCommonConstants;
import eu.arrowhead.client.library.util.CoreServiceUri;
import eu.arrowhead.common.CommonConstants;
import eu.arrowhead.common.SSLProperties;
import eu.arrowhead.common.Utilities;
import eu.arrowhead.common.core.CoreSystem;
import eu.arrowhead.common.core.CoreSystemService;
import eu.arrowhead.common.dto.shared.OrchestrationFormRequestDTO.Builder;
import eu.arrowhead.common.exception.ArrowheadException;
import eu.arrowhead.common.exception.AuthException;
import eu.arrowhead.common.exception.BadPayloadException;
import eu.arrowhead.common.exception.InvalidParameterException;
import eu.arrowhead.common.exception.UnavailableServerException;
import eu.arrowhead.common.http.HttpService;

@Component("ArrowheadService")
public class ArrowheadService {
	
	//=================================================================================================
	// members
	
	@Value(ClientCommonConstants.$CLIENT_SYSTEM_NAME)
	private String clientSystemName;
	
	@Value(ClientCommonConstants.$CLIENT_SERVER_ADDRESS_WD)
	private String clientSystemAddress;
	
	@Value(ClientCommonConstants.$CLIENT_SERVER_PORT_WD)
	private int clientSystemPort;
	
	@Value(CommonConstants.$SERVICE_REGISTRY_ADDRESS_WD)
	private String serviceReqistryAddress;
	
	@Value(CommonConstants.$SERVICE_REGISTRY_PORT_WD)
	private int serviceRegistryPort;

	@Resource(name = CommonConstants.ARROWHEAD_CONTEXT)
	private Map<String,Object> arrowheadContext;
	
	@Autowired
	private SSLProperties sslProperties;
	
	@Autowired
	private HttpService httpService;

	@Autowired
	private Environment env;

    @Value("${monitoring.access_token}")
    private String monitoringAccessToken;

	private final static String INTERFACE_SECURE_FLAG = "SECURE";
	private final static String INTERFACE_INSECURE_FLAG = "INSECURE";
	
	private final Logger logger = LogManager.getLogger(ArrowheadService.class);
	
	//=================================================================================================
	// methods

	//------------------------------------------------------------------------------------------------
	/**
	 * @param coreSystemService CoreSystemService enum which represents an Arrowhead Core System Service
	 * @return the URI details of the Arrowhead Core System or null when the specified coreSystemService is not a public one or ArrowhedContext component not contains the the given core service.
	 */
	public CoreServiceUri getCoreServiceUri(final CoreSystemService coreSystemService) {
		if (!CommonConstants.PUBLIC_CORE_SYSTEM_SERVICES.contains(coreSystemService)) {
			logger.debug("'{}' core service is not a public service.", coreSystemService);
			return null;
		} else if (!arrowheadContext.containsKey(coreSystemService.getServiceDefinition() + ClientCommonConstants.CORE_SERVICE_DEFINITION_SUFFIX)) {
			logger.debug("'{}' core service is not contained by Arrowhead Context.", coreSystemService);
			return null;
		} else {
			return (CoreServiceUri) arrowheadContext.get(coreSystemService.getServiceDefinition() + ClientCommonConstants.CORE_SERVICE_DEFINITION_SUFFIX);
		}		
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Queries and stores the public service URIs of the given Arrowhead Core System in the ArrowheadContext component. 
	 * If the specified Core System has no public service or the server is not available, then ArrowheadContext won't contain the core service and a log info message will be triggered.
	 * 
	 * @param coreSystem CoreSystem enum which represents an Arrowhead Core System
	 */
	public void updateCoreServiceURIs(final CoreSystem coreSystem) {
		final List<CoreSystemService> publicServices = getPublicServicesOfCoreSystem(coreSystem);
		if (publicServices.isEmpty()) {
			logger.info("'{}' core system has no public service.", coreSystem.name());
			return;
		}
		
		for (final CoreSystemService coreService : publicServices) {			
			try {	
				final ResponseEntity<ServiceQueryResultDTO> response = queryServiceReqistryByCoreService(coreService);
				
				if (response.getBody().getServiceQueryData().isEmpty()) {
					logger.info("'{}' core service couldn't be retrieved due to the following reason: not registered by Serivce Registry", coreService.getServiceDefinition());
					arrowheadContext.remove(coreService.getServiceDefinition() + ClientCommonConstants.CORE_SERVICE_DEFINITION_SUFFIX);
					
				} else {
					final ServiceRegistryResponseDTO serviceRegistryResponseDTO = response.getBody().getServiceQueryData().get(0);
					arrowheadContext.put(coreService.getServiceDefinition() + ClientCommonConstants.CORE_SERVICE_DEFINITION_SUFFIX, new CoreServiceUri(serviceRegistryResponseDTO.getProvider().getAddress(),
							serviceRegistryResponseDTO.getProvider().getPort(), serviceRegistryResponseDTO.getServiceUri()));					
				}
				
			} catch (final  ArrowheadException ex) {
				logger.debug("'{}' core service couldn't be retrieved due to the following reason: {}", coreService.getServiceDefinition(), ex.getMessage());
			}			
		}
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) request to the 'echo' end point of the given Arrowhead Core System.
	 * 
	 * @param coreSystem CoreSystem enum which represents an Arrowhead Core System
	 * @return true if answer received from core system server and false if not or the specified core system has no public service or it is not known by Service Registry Core System
	 */
	public boolean echoCoreSystem(final CoreSystem coreSystem) {		
		String address = null;
		Integer port = null;
		String coreUri = null;
		
		try {
			
			if (coreSystem == CoreSystem.SERVICE_REGISTRY) {
				address = serviceReqistryAddress;
				port = serviceRegistryPort;
				coreUri = CommonConstants.SERVICE_REGISTRY_URI;
				
			} else {			
				final List<CoreSystemService> publicServices = getPublicServicesOfCoreSystem(coreSystem);			
				if (publicServices.isEmpty()) {
					logger.debug("'{}' core system has no public service.", coreSystem.name());
					return false;
					
				} else {				
					final ResponseEntity<ServiceQueryResultDTO> srResponse = queryServiceReqistryByCoreService(publicServices.get(0));
					
					if (srResponse.getBody().getServiceQueryData().isEmpty()) {
						logger.debug("'{}' core system not known by Service Registry", coreSystem.name());
						return false;
					} else {
						address = srResponse.getBody().getServiceQueryData().get(0).getProvider().getAddress();
						port = srResponse.getBody().getServiceQueryData().get(0).getProvider().getPort();
						coreUri = publicServices.get(0).getServiceUri().split("/")[1];
					}				
				}			
			}
		
			httpService.sendRequest(Utilities.createURI(getUriScheme(), address, port, coreUri + CommonConstants.ECHO_URI), HttpMethod.GET, String.class);		
		} catch (final Exception ex) {
			logger.debug("Exception occured during the {} core system 'echo' request. Message : {}", coreSystem.name(), ex.getMessage());
			return false;
		}
		return true;
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) 'register' request to Service Registry Core System.
	 * 
	 * @param request ServiceRegistryRequestDTO which represents the required payload of the http(s) request
	 * @return the ServiceRegistryResponseDTO received from Service Registry Core System
	 * @throws AuthException when you are not authorized by Service Registry Core System
	 * @throws BadPayloadException when the payload couldn't be validated by Service Registry Core System 
	 * @throws InvalidParameterException when the payload content couldn't be validated by Service Registry Core System
	 * @throws ArrowheadException when internal server error happened at Service Registry Core System
	 * @throws UnavailableServerException when Service Registry Core System is not available
	 */
	public ServiceRegistryResponseDTO registerServiceToServiceRegistry(final ServiceRegistryRequestDTO request) {
		final String registerUriStr = CommonConstants.SERVICE_REGISTRY_URI + CommonConstants.OP_SERVICE_REGISTRY_REGISTER_URI;
		final UriComponents registerUri = Utilities.createURI(getUriScheme(), serviceReqistryAddress, serviceRegistryPort, registerUriStr);
		
		return httpService.sendRequest(registerUri, HttpMethod.POST, ServiceRegistryResponseDTO.class, request).getBody();
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) 'register' request to Service Registry Core System. In the case of service already registered, then the old service registry entry will be overwritten.  
	 * 
	 * @param request ServiceRegistryRequestDTO which represents the required payload of the http(s) request
	 * @return the ServiceRegistryResponseDTO received from Service Registry Core System
	 * @throws AuthException when you are not authorized by Service Registry Core System
	 * @throws BadPayloadException when the payload couldn't be validated by Service Registry Core System 
	 * @throws InvalidParameterException when the payload content couldn't be validated by Service Registry Core System
	 * @throws ArrowheadException when internal server error happened at Service Registry Core System
	 * @throws UnavailableServerException when Service Registry Core System is not available
	 */
	public ServiceRegistryResponseDTO forceRegisterServiceToServiceRegistry(final ServiceRegistryRequestDTO request) {
		final String registerUriStr = CommonConstants.SERVICE_REGISTRY_URI + CommonConstants.OP_SERVICE_REGISTRY_REGISTER_URI;
		final UriComponents registerUri = Utilities.createURI(getUriScheme(), serviceReqistryAddress, serviceRegistryPort, registerUriStr);
		
		try {			
			return httpService.sendRequest(registerUri, HttpMethod.POST, ServiceRegistryResponseDTO.class, request).getBody();
		} catch (final InvalidParameterException ex) {
			unregisterServiceFromServiceRegistry(request.getServiceDefinition());
			return httpService.sendRequest(registerUri, HttpMethod.POST, ServiceRegistryResponseDTO.class, request).getBody();
		}	
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) 'unregister' request to Service Registry Core System.
	 * 
	 * @param serviceDefinition String value which represents the service being deleted from service registry
	 * @throws AuthException when you are not authorized by Service Registry Core System
	 * @throws BadPayloadException when the payload couldn't be validated by Service Registry Core System 
	 * @throws InvalidParameterException when the payload content couldn't be validated by Service Registry Core System
	 * @throws ArrowheadException when internal server error happened at Service Registry Core System
	 * @throws UnavailableServerException when Service Registry Core System is not available
	 */
	public void unregisterServiceFromServiceRegistry(final String serviceDefinition) {
		final String unregisterUriStr = CommonConstants.SERVICE_REGISTRY_URI + CommonConstants.OP_SERVICE_REGISTRY_UNREGISTER_URI;
		final MultiValueMap<String,String> queryMap = new LinkedMultiValueMap<>(4);
		queryMap.put(CommonConstants.OP_SERVICE_REGISTRY_UNREGISTER_REQUEST_PARAM_PROVIDER_SYSTEM_NAME, List.of(clientSystemName));
		queryMap.put(CommonConstants.OP_SERVICE_REGISTRY_UNREGISTER_REQUEST_PARAM_PROVIDER_ADDRESS, List.of(clientSystemAddress));
		queryMap.put(CommonConstants.OP_SERVICE_REGISTRY_UNREGISTER_REQUEST_PARAM_PROVIDER_PORT, List.of(String.valueOf(clientSystemPort)));
		queryMap.put(CommonConstants.OP_SERVICE_REGISTRY_UNREGISTER_REQUEST_PARAM_SERVICE_DEFINITION, List.of(serviceDefinition));
		final UriComponents unregisterUri = Utilities.createURI(getUriScheme(), serviceReqistryAddress, serviceRegistryPort, queryMap, unregisterUriStr);
		
		httpService.sendRequest(unregisterUri, HttpMethod.DELETE, Void.class);
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Queries its public key from Authorization Core System. 
	 * 
	 * @return the public key of Authorization Core System or null when the public key core service URI is not known by ArrowheadContext component.
	 * @throws AuthException when you are not authorized by Authorization Core System
	 * @throws ArrowheadException when internal server error happened at Authorization Core System
	 * @throws UnavailableServerException when Authorization Core System is not available
	 */
	public PublicKey queryAuthorizationPublicKey() {
		final CoreServiceUri uri = getCoreServiceUri(CoreSystemService.AUTH_PUBLIC_KEY_SERVICE);
		if (uri == null) {
			logger.debug("Authorization Public Key couldn't be retrieved due to the following reason: " +  CoreSystemService.AUTH_PUBLIC_KEY_SERVICE.name() + " not known by Arrowhead Context");
			return null;
		}
		
		final ResponseEntity<String> response = httpService.sendRequest(Utilities.createURI(getUriScheme(), uri.getAddress(), uri.getPort(), uri.getPath()), HttpMethod.GET, String.class);
				
		return Utilities.getPublicKeyFromBase64EncodedString(response.getBody());
	}
	
	//-------------------------------------------------------------------------------------------------
	/** 
	 * @return your public key or null when https mode is not enabled
	 */
	public PublicKey getMyPublicKey() {
		if (sslProperties.isSslEnabled()) {
			return (PublicKey) arrowheadContext.get(CommonConstants.SERVER_PUBLIC_KEY);
		} else {
			return null;
		}
	}
	
	//-------------------------------------------------------------------------------------------------
	/** 
	 * @return your private key or null when https mode is not enabled
	 */
	public PrivateKey getMyPrivateKey() {
		if (sslProperties.isSslEnabled()) {
			return (PrivateKey) arrowheadContext.get(CommonConstants.SERVER_PRIVATE_KEY);
		} else {
			return null;
		}
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * @return an Orchestration form builder prefilled with your system properties
	 */
	public Builder getOrchestrationFormBuilder() {
		final SystemRequestDTO thisSystem = new SystemRequestDTO();
		thisSystem.setSystemName(clientSystemName);
		thisSystem.setAddress(clientSystemAddress);
		thisSystem.setPort(clientSystemPort);
		if (sslProperties.isSslEnabled()) {
			final PublicKey publicKey = (PublicKey) arrowheadContext.get(CommonConstants.SERVER_PUBLIC_KEY);
			thisSystem.setAuthenticationInfo(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
		}
		
		return new OrchestrationFormRequestDTO.Builder(thisSystem);
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) 'orchestration' request to Orchestrator Core System.
	 * 
	 * @param request OrchestrationFormRequestDTO which represents the required payload of the http(s) request
	 * @return the OrchestrationResponseDTO received from Orchestrator Core System or null when the orchestration service URI is not known by Arrowhead Context
	 * @throws AuthException when you are not authorized by Orchestrator Core System
	 * @throws BadPayloadException when the payload couldn't be validated by Orchestrator Core System 
	 * @throws InvalidParameterException when the payload content couldn't be validated by Orchestrator Core System
	 * @throws ArrowheadException when internal server error happened at one of the core system involved in orchestration process 
	 * @throws UnavailableServerException when one of the core system involved in orchestration process is not available 
	 */
	public OrchestrationResponseDTO proceedOrchestration(final OrchestrationFormRequestDTO request) {
		final CoreServiceUri uri = getCoreServiceUri(CoreSystemService.ORCHESTRATION_SERVICE);
		if (uri == null) {
			logger.debug("Orchestration couldn't be proceeded due to the following reason: " +  CoreSystemService.ORCHESTRATION_SERVICE.name() + " not known by Arrowhead Context");
			return null;
		}

		OrchestrationResponseDTO response = httpService.sendRequest(Utilities.createURI(getUriScheme(), uri.getAddress(), uri.getPort(), uri.getPath()), HttpMethod.POST, OrchestrationResponseDTO.class, request).getBody();
		addOrchestrationLog(request, response);
		return response;
	}

    /**
     * After the consumer application decided which producer to use this method must be called by it
     * in order to report a new connection to the Monitoring Component
     * @param orchestrationResult OrchestrationResultDTO which contains the information for the chosen producer
     * @param interfaceName String containing the name of the communication'S  interface
     */
    public void monitorConnection(OrchestrationResultDTO orchestrationResult, String interfaceName) {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        try {
            final String uri = getBaseAddress() + ClientCommonConstants.MONITOR_CONNECTION_URI;
            JSONObject requestJson = new JSONObject();
            requestJson.put("requester_name", this.clientSystemName);
            requestJson.put("requester_address", this.clientSystemAddress);
            requestJson.put("requester_port",  this.clientSystemPort);
            requestJson.put("provider_id", orchestrationResult.getProvider().getId());
            requestJson.put("service_id", orchestrationResult.getService().getId());
            requestJson.put("interface_name", interfaceName);
            JSONArray requestArray = new JSONArray();
            requestArray.add(requestJson);
            HttpPost request = new HttpPost(uri);
            StringEntity params = new StringEntity(requestArray.toString());
            request.addHeader("content-type", "application/json");
            request.addHeader("Authorization", monitoringAccessToken);
            request.setEntity(params);
            httpClient.execute(request);
        } catch (Exception ex) {
            System.err.println("Got an exception! ");
            System.err.println(ex.getMessage());
        }
    }

    /**
     * After the consumer application decided which producer to use this method must be called by it
     * in order to report a terminated connection to the Monitoring Component
     * @param orchestrationResult OrchestrationResultDTO which contains the information for the chosen producer
     * @param interfaceName String containing the name of the communication'S  interface
     */
    public void terminateConnection(OrchestrationResultDTO orchestrationResult, String interfaceName) {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        try {
            final String uri = getBaseAddress() + ClientCommonConstants.TERMINATE_CONNECTION_URI;
            JSONObject requestJson = new JSONObject();
            requestJson.put("requester_name", this.clientSystemName);
            requestJson.put("requester_address", this.clientSystemAddress);
            requestJson.put("requester_port",  this.clientSystemPort);
            requestJson.put("provider_id", orchestrationResult.getProvider().getId());
            requestJson.put("service_id", orchestrationResult.getService().getId());
            requestJson.put("interface_name", interfaceName);
            JSONArray requestArray = new JSONArray();
            requestArray.add(requestJson);
            HttpPost request = new HttpPost(uri);
            StringEntity params = new StringEntity(requestArray.toString());
            request.addHeader("content-type", "application/json");
            request.addHeader("Authorization", monitoringAccessToken);
            request.setEntity(params);
            CloseableHttpResponse response = httpClient.execute(request);
            System.out.println(response.toString());

        } catch (Exception ex) {
            System.err.println("Got an exception! ");
            System.err.println(ex.getMessage());
        }
    }

    /**
     * Logs an orchestration request and response to the Monitoring Components
     * @param request OrchestrationFormRequestDTO which represents the required payload of the http(s) request
     * @param response OrchestrationResponseDTP which contains the response from the Orchestrator component
     */
	private void addOrchestrationLog(OrchestrationFormRequestDTO request, OrchestrationResponseDTO response) {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
		try {
            final String uri = getBaseAddress() + ClientCommonConstants.ADD_ORCHESTRATION_LOG;

			SystemRequestDTO requesterSystem = request.getRequesterSystem();
			List<OrchestrationResultDTO> responseDTOList = response.getResponse();

			JSONArray requestArray = new JSONArray();
			for(int i = 0; i < responseDTOList.size(); i++) {
				for(int j = 0; j < responseDTOList.size(); j++) {
                    JSONObject requestJson = new JSONObject();
                    requestJson.put("requester_name", requesterSystem.getSystemName());
                    requestJson.put("requester_address", requesterSystem.getAddress());
                    requestJson.put("requester_port", requesterSystem.getPort());
                    requestJson.put("provider_id", responseDTOList.get(i).getProvider().getId());
                    requestJson.put("service_id",  responseDTOList.get(i).getService().getId());
                    requestJson.put("interface_id", responseDTOList.get(i).getInterfaces().get(j).getId());
                    requestArray.add(requestJson);
				}
			}
            HttpPost httpRequest = new HttpPost(uri);
            StringEntity params = new StringEntity(requestArray.toString());
            httpRequest.addHeader("content-type", "application/json");
            httpRequest.addHeader("Authorization", monitoringAccessToken);
            httpRequest.setEntity(params);
            httpClient.execute(httpRequest);
		} catch (Exception e) {
			System.err.println("Got an exception! ");
			System.err.println(e.getMessage());
		}
	}

    /**
     * This method logs HTTP communication to the Monitoring Component
     * @param httpMethod HttpMethod which is the HTTP verb of the query
     * @param address String the address where the query was sent
     * @param port int the port number where the query was sent
     * @param serviceUri String the uri of the service
     * @param interfaceName String the name of the interface of the query
     */
	private void monitorCommunication(final HttpMethod httpMethod, final String address, final int port, final String serviceUri, final String interfaceName) {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
		try {
            final String uri = getBaseAddress() + ClientCommonConstants.ADD_COMMUNICATION_LOG;
            JSONObject requestJson = new JSONObject();
            requestJson.put("requester_name", this.clientSystemName);
            requestJson.put("requester_address", this.clientSystemAddress);
            requestJson.put("requester_port",  this.clientSystemPort);
            requestJson.put("http_method", httpMethod.toString());
            requestJson.put("provider_address", address);
            requestJson.put("provider_port", port);
            requestJson.put("service_uri", serviceUri);
            requestJson.put("interface_name", interfaceName);
            JSONArray requestArray = new JSONArray();
            requestArray.add(requestJson);
            HttpPost request = new HttpPost(uri);
            StringEntity params = new StringEntity(requestArray.toString());
            request.addHeader("content-type", "application/json");
            request.addHeader("Authorization", monitoringAccessToken);
            request.setEntity(params);
            httpClient.execute(request);
		} catch (Exception e) {
			System.err.println("Got an exception! ");
			System.err.println(e.getMessage());
		}
	}

    /**
     * This method logs HTTP communication to the Monitoring Component
     * @param httpMethod HttpMethod which is the HTTP verb of the query
     * @param uriComponents UriComponents containing the URI of the query
     */
	private void monitorCommunication(final HttpMethod httpMethod, final UriComponents uriComponents) {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        try {
            final String uri = getBaseAddress() + ClientCommonConstants.ADD_COMMUNICATION_LOG;
            JSONObject requestJson = new JSONObject();
            requestJson.put("requester_name", this.clientSystemName);
            requestJson.put("requester_address", this.clientSystemAddress);
            requestJson.put("requester_port",  this.clientSystemPort);
            requestJson.put("http_method", httpMethod.toString());
            requestJson.put("uri_components", uriComponents.toString());
            JSONArray requestArray = new JSONArray();
            requestArray.add(requestJson);
            HttpPost request = new HttpPost(uri);
            StringEntity params = new StringEntity(requestArray.toString());
            request.addHeader("content-type", "application/json");
            request.addHeader("Authorization", monitoringAccessToken);
            request.setEntity(params);
            httpClient.execute(request);
        } catch (Exception e) {
            System.err.println("Got an exception! ");
            System.err.println(e.getMessage());
        }
	}

    /**
     * A private helper method to create the base address for the Monitoring API
     * @return String the base url of the Monitoring API
     */
	private String getBaseAddress() {
		return "http://"+env.getProperty("monitoring_address") + ":" +env.getProperty("monitoring_port");
	}


	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) 'orchestration/{systemId}' request to Orchestrator Core System.
	 * 
	 * @param systemId long value which represents the required system id path variable
	 * @return the OrchestrationResponseDTO with all top priority provider from Orchestration Store or null when the orchestration service URI is not known by Arrowhead Context
	 * @throws AuthException when you are not authorized by Orchestrator Core System
	 * @throws BadPayloadException when the systemId couldn't be validated by Orchestrator Core System 
	 * @throws InvalidParameterException when the system is not found by Service Registry Core System
	 * @throws ArrowheadException when internal server error happened at one of the core system involved in orchestration process 
	 * @throws UnavailableServerException when one of the core system involved in orchestration process is not available 
	 */
	public OrchestrationResponseDTO queryOrchestrationStore(final long systemId) {
		final CoreServiceUri uri = getCoreServiceUri(CoreSystemService.ORCHESTRATION_SERVICE);
		if (uri == null) {
			logger.debug("Orchestration from store couldn't be proceeded due to the following reason: " +  CoreSystemService.ORCHESTRATION_SERVICE.name() + " not known by Arrowhead Context");
			return null;
		}
		
		return httpService.sendRequest(Utilities.createURI(getUriScheme(), uri.getAddress(), uri.getPort(), uri.getPath() + "/" + systemId), HttpMethod.GET, OrchestrationResponseDTO.class).getBody();
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) request with the specified service reachability details.
	 * 
	 * @param responseType which represents the expected response body.
	 * @param httpMethod HttpMethod enum which represents the method how the service is available.
	 * @param address String value which represents the host where the service is available.
	 * @param port int value which represents the port where the service is available
	 * @param serviceUri String value which represents the URI where the service is available.
	 * @param interfaceName String value which represents the name of the interface used for the communication. Usable interfaces could be received in orchestration response.
	 * @param token (nullable) String value which represents the token for being authorized at the provider side if necessary. Token could be received in orchestration response per interface type.  
	 * @param payload (nullable) Object type which represents the required payload of the http(s) request if any necessary.
	 * @param queryParams (nullable) String... variable arguments which represent the additional key-value http(s) query parameters if any necessary. E.g.: "k1", "v1", "k2", "v2".  
	 * @return the response received from the provider 
	 * 
	 * @throws InvalidParameterException when service URL can't be assembled.
	 * @throws AuthException when ssl context or access control related issue happened.
	 * @throws ArrowheadException when the communication is managed via Gateway Core System and internal server error happened.
	 * @throws UnavailableServerException when the specified server is not available.
	 */
	public <T> T consumeServiceHTTP(final Class<T> responseType, final HttpMethod httpMethod, final String address, final int port, final String serviceUri, final String interfaceName, final String token,
								  final Object payload, final String... queryParams) {
		if (responseType == null) {
			throw new InvalidParameterException("responseType cannot be null.");
		}
		if (httpMethod == null) {
			throw new InvalidParameterException("httpMethod cannot be null.");
		}
		if (Utilities.isEmpty(address)) {
			throw new InvalidParameterException("address cannot be null or blank.");
		}
		if (Utilities.isEmpty(serviceUri)) {
			throw new InvalidParameterException("serviceUri cannot be null or blank.");
		}
		if (Utilities.isEmpty(interfaceName)) {
			throw new InvalidParameterException("interfaceName cannot be null or blank.");
		}
		
		String[] validatedQueryParams;
		if (queryParams == null) {
			validatedQueryParams = new String[0];
		} else {
			validatedQueryParams = queryParams;
		}
		
		UriComponents uri;
		if(!Utilities.isEmpty(token)) {
			final List<String> query = new ArrayList<>();
			query.addAll(Arrays.asList(validatedQueryParams));
			query.add(CommonConstants.REQUEST_PARAM_TOKEN);
			query.add(token);
			uri = Utilities.createURI(getUriSchemeFromInterfaceName(interfaceName), address, port, serviceUri, query.toArray(new String[query.size()]));
		} else {
			uri = Utilities.createURI(getUriSchemeFromInterfaceName(interfaceName), address, port, serviceUri, validatedQueryParams);
		}
		
		final ResponseEntity<T> response = httpService.sendRequest(uri, httpMethod, responseType, payload);
		monitorCommunication(httpMethod, address, port, serviceUri, interfaceName);
		return response.getBody();
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) request with the specified service reachability details.
	 * 
	 * @param responseType which represents the expected response body.
	 * @param httpMethod HttpMethod enum which represents the method how the service is available.
	 * @param uriComponents UriComponents object which represents the URI where the service is available.
	 * @param token (nullable) String value which represents the token for being authorized at the provider side if necessary. Token could be received in orchestration response per interface type.  
	 * @param payload (nullable) Object type which represents the required payload of the http(s) request if any necessary.
	 * @return the response received from the provider 
	 * 
	 * @throws InvalidParameterException when service URL can't be assembled.
	 * @throws AuthException when ssl context or access control related issue happened.
	 * @throws ArrowheadException when the communication is managed via Gateway Core System and internal server error happened.
	 * @throws UnavailableServerException when the specified server is not available.
	 */
	public <T> T consumeServiceHTTP(final Class<T> responseType, final HttpMethod httpMethod, final UriComponents uriComponents, final String token, final Object payload) {
		UriComponents uri = uriComponents;
		if (responseType == null) {
			throw new InvalidParameterException("responseType cannot be null.");
		}
		if (httpMethod == null) {
			throw new InvalidParameterException("httpMethod cannot be null.");
		}
		if (uri == null) {
			throw new InvalidParameterException("uriComponents cannot be null.");
		}
		
		if (!Utilities.isEmpty(token)) {
			final String uriToExpand = uri.toUriString();
			final UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uriToExpand);
			uri = builder.queryParam(CommonConstants.REQUEST_PARAM_TOKEN, token).build();
		} 
		
		final ResponseEntity<T> response = httpService.sendRequest(uri, httpMethod, responseType, payload);
		monitorCommunication(httpMethod, uriComponents);
		return response.getBody();
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) 'subscription' request to Event Handler Core System.
	 * 
	 * @param request SubscriptionRequestDTO which represents the required payload of the http(s) request
	 * @throws AuthException when you are not authorized by Event Handler Core System
	 * @throws BadPayloadException when the payload couldn't be validated by Event Handler Core System 
	 * @throws InvalidParameterException when the payload content couldn't be validated by Event Handler Core System
	 * @throws ArrowheadException when internal server error happened at Event Handler Core System
	 * @throws UnavailableServerException when Event Handler Core System is not available
	 */
	public void subscribeToEventHandler(final SubscriptionRequestDTO request) {
		final CoreServiceUri uri = getCoreServiceUri(CoreSystemService.EVENT_SUBSCRIBE_SERVICE);
		if (uri == null) {
			logger.debug("Subscription couldn't be proceeded due to the following reason: " +  CoreSystemService.EVENT_SUBSCRIBE_SERVICE.name() + " not known by Arrowhead Context");
			return;
		}
		
		httpService.sendRequest(Utilities.createURI(getUriScheme(), uri.getAddress(), uri.getPort(), uri.getPath()), HttpMethod.POST, Void.class, request);
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) 'unsubscription' request to Event Handler Core System.
	 * 
	 * @param eventType String which represents the required eventType parameter of the http(s) request
	 * @param subscriberName String which represents the required subscriberName parameter of the http(s) request
	 * @param subscriberAddress String which represents the required subscriberAddress parameter of the http(s) request
	 * @param subscriberPort int which represents the required subscriberPort parameter of the http(s) request
	 * @throws AuthException when you are not authorized by Event Handler Core System
	 * @throws BadPayloadException when the payload couldn't be validated by Event Handler Core System 
	 * @throws InvalidParameterException when the payload content couldn't be validated by Event Handler Core System
	 * @throws ArrowheadException when internal server error happened at Event Handler Core System
	 * @throws UnavailableServerException when Event Handler Core System is not available
	 */
	public void unsubscribeFromEventHandler(final String eventType, final String subscriberName, final String subscriberAddress, final int subscriberPort ) {
		final CoreServiceUri uri = getCoreServiceUri(CoreSystemService.EVENT_UNSUBSCRIBE_SERVICE);
		if (uri == null) {
			logger.debug("Unsubscription couldn't be proceeded due to the following reason: " +  CoreSystemService.EVENT_UNSUBSCRIBE_SERVICE.name() + " not known by Arrowhead Context");
			return;
		}
		
		final MultiValueMap<String, String> requestParams = new LinkedMultiValueMap<>();
		requestParams.add(CommonConstants.OP_EVENT_HANDLER_UNSUBSCRIBE_REQUEST_PARAM_EVENT_TYPE, eventType);
		requestParams.add(CommonConstants.OP_EVENT_HANDLER_UNSUBSCRIBE_REQUEST_PARAM_SUBSCRIBER_SYSTEM_NAME, subscriberName);
		requestParams.add(CommonConstants.OP_EVENT_HANDLER_UNSUBSCRIBE_REQUEST_PARAM_SUBSCRIBER_ADDRESS, subscriberAddress);
		requestParams.add(CommonConstants.OP_EVENT_HANDLER_UNSUBSCRIBE_REQUEST_PARAM_SUBSCRIBER_PORT, String.valueOf(subscriberPort));
		
		final UriComponents unsubscribeUri = Utilities.createURI(getUriScheme(), uri.getAddress(), uri.getPort(), requestParams, uri.getPath());		
		httpService.sendRequest(unsubscribeUri, HttpMethod.DELETE, Void.class);
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Sends a http(s) 'publish' request to Event Handler Core System.
	 * 
	 * @param request EventPublishRequestDTO which represents the required payload of the http(s) request
	 * @throws AuthException when you are not authorized by Event Handler Core System
	 * @throws BadPayloadException when the payload couldn't be validated by Event Handler Core System 
	 * @throws InvalidParameterException when the payload content couldn't be validated by Event Handler Core System
	 * @throws ArrowheadException when internal server error happened at Event Handler Core System
	 * @throws UnavailableServerException when Event Handler Core System is not available
	 */
	public void publishToEventHandler(final EventPublishRequestDTO request) {
		final CoreServiceUri uri = getCoreServiceUri(CoreSystemService.EVENT_PUBLISH_SERVICE);
		if (uri == null) {
			logger.debug("Publishing couldn't be proceeded due to the following reason: " +  CoreSystemService.EVENT_PUBLISH_SERVICE.name() + " not known by Arrowhead Context");
			return;
		}
		
		httpService.sendRequest(Utilities.createURI(getUriScheme(), uri.getAddress(), uri.getPort(), uri.getPath()), HttpMethod.POST, Void.class, request);
	}
	
	//-------------------------------------------------------------------------------------------------
	/**
	 * Get the serverCN from arrowheadContext
	 * 
	 * @returns Arrowhead Client-System ServerCN
	*/
	public String getServerCN(){
		return (String) arrowheadContext.get(CommonConstants.SERVER_COMMON_NAME);
	}
	
	//=================================================================================================
	// assistant methods

	//-------------------------------------------------------------------------------------------------
	private ResponseEntity<ServiceQueryResultDTO> queryServiceReqistryByCoreService(final CoreSystemService coreService) {
		final ServiceQueryFormDTO request = new ServiceQueryFormDTO();
		request.setServiceDefinitionRequirement(coreService.getServiceDefinition());
		
		return httpService.sendRequest(Utilities.createURI(getUriScheme(), serviceReqistryAddress, serviceRegistryPort, CommonConstants.SERVICE_REGISTRY_URI + CommonConstants.OP_SERVICE_REGISTRY_QUERY_URI),
									   HttpMethod.POST, ServiceQueryResultDTO.class, request);
	}
	
	//-------------------------------------------------------------------------------------------------
	private String getUriScheme() {
		return sslProperties.isSslEnabled() ? CommonConstants.HTTPS : CommonConstants.HTTP;
	}
	
	//-------------------------------------------------------------------------------------------------
	private String getUriSchemeFromInterfaceName(final String interfaceName) {
		final String[] splitInterf = interfaceName.split("-");
		final String protocolStr = splitInterf[0];
		if (!protocolStr.equalsIgnoreCase(CommonConstants.HTTP) && !protocolStr.equalsIgnoreCase(CommonConstants.HTTPS)) {
			// Currently only HTTP(S) is supported
			throw new InvalidParameterException("Invalid interfaceName: protocol should be 'http' or 'https'.");
		}
		
		final boolean isSecure = INTERFACE_SECURE_FLAG.equalsIgnoreCase(splitInterf[1]);
		final boolean isInsecure = INTERFACE_INSECURE_FLAG.equalsIgnoreCase(splitInterf[1]);
		if (!isSecure && !isInsecure) {
			return getUriScheme();
		}
		
		return isSecure ? CommonConstants.HTTPS : CommonConstants.HTTP;
	}
	
	//-------------------------------------------------------------------------------------------------
	private List<CoreSystemService> getPublicServicesOfCoreSystem(final CoreSystem coreSystem) {
		final List<CoreSystemService> publicServices = new ArrayList<>();
		publicServices.addAll(coreSystem.getServices());
		publicServices.retainAll(CommonConstants.PUBLIC_CORE_SYSTEM_SERVICES);
		return publicServices;
	}
}
