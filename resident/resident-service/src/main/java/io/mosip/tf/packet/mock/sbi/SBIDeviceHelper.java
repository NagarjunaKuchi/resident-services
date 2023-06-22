package io.mosip.tf.packet.mock.sbi;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.tf.packet.config.LoggerConfiguration;
import io.mosip.tf.packet.dto.DeviceInfo;
import io.mosip.tf.packet.dto.DeviceInfoDto;
import io.mosip.tf.packet.dto.DigitalId;
import io.mosip.tf.packet.dto.DiscoverDto;
import io.mosip.tf.packet.util.FileHelper;
import io.mosip.tf.packet.util.JwtUtility;
import io.mosip.tf.packet.util.SBIConstant;
import io.mosip.tf.packet.util.StringHelper;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Random;

import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;


public class SBIDeviceHelper {
	
	private final Logger LOGGER = LoggerConfiguration.logConfig(SBIDeviceHelper.class);
	
	private static final String UTC_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss'Z'";
	private String purpose;
	private String profileId;
	private String deviceId;
	private int deviceSubId;

	private String deviceType;
	private String deviceSubType;

	private DigitalId digitalId;
	private DeviceInfo deviceInfo;
	private DiscoverDto discoverDto;
	private DeviceInfoDto deviceInfoDto;
    private HashMap<String, String> statusMap = new HashMap<> ();
    private HashMap<String, Long> delayMap = new HashMap<> ();
    protected int qualityScore;
    protected boolean isQualityScoreSet;
    private boolean scoreFromIso = false;
    
	@Autowired
	Environment env;
			
	public SBIDeviceHelper(String purpose, String deviceType, String deviceSubType, String keystoreFilePath) {
		super();
		//setKeystoreFilePath(keystoreFilePath);
		setPurpose (purpose);
		setDeviceType (deviceType);
		setDeviceSubType (deviceSubType);
		setDeviceStatus (SBIConstant.DEVICE_STATUS_ISREADY);
		initDeviceDetails();
	}

	public void initDeviceDetails() {
		setDigitalId (getDigitalId (getDeviceType (), getDeviceSubType ()));
		setDiscoverDto (getDiscoverInfo (getDeviceType (), getDeviceSubType (), getDigitalId ()));
		setDeviceInfo (getDeviceInfo (getDeviceType (), getDeviceSubType (), getDigitalId ()));
		setDeviceInfoDto (getDeviceInfoDto (getDeviceType (), getDeviceSubType (), getDeviceInfo ()));
	}

	protected DigitalId getDigitalId(String deviceType, String deviceSubType) {
		DigitalId digitalId = null;
		String fileName = null;
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			switch (deviceType)
			{
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER:
					switch (deviceSubType)
					{
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP:
							fileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Finger/Slap/DigitalId.json"; 
							//env.getProperty(SBIConstant.MOSIP_FINGER_SLAP_DIGITALID_JSON);
							break;
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE:
							fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_FINGER_SINGLE_DIGITALID_JSON);
							break;
					}
				break;
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE:
					if (deviceSubType.equalsIgnoreCase(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE))
						fileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Face/DigitalId.json"; 
						//env.getProperty(SBIConstant.MOSIP_FACE_DIGITALID_JSON);
				break;
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS:
					switch (deviceSubType)
					{
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE:
							fileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Iris/Double/DigitalId.json"; 
							//env.getProperty(SBIConstant.MOSIP_IRIS_DOUBLE_DIGITALID_JSON);
							break;
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE:
							fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_IRIS_SINGLE_DIGITALID_JSON);
							break;
					}
				break;
			}
			
			if (FileHelper.exists(fileName)) 
			{
				File file = new File(fileName);
				digitalId = objectMapper.readValue(file, DigitalId.class);
				if (digitalId != null)
				{
					digitalId.setDateTime(formatToISOString(DateUtils.getUTCCurrentDateTime()));
				}
				
				return digitalId;
			}	
		} catch (Exception ex) {
        	LOGGER.error("getDigitalId :: deviceType::" + deviceType + " :: deviceSubType::" + deviceSubType , ex);
		}
		return null;
	}
	
	private static String formatToISOString(LocalDateTime localDateTime) {
		return localDateTime.format(DateTimeFormatter.ofPattern(UTC_DATETIME_PATTERN));
	}
	
	protected DiscoverDto getDiscoverInfo(String deviceType, String deviceSubType, DigitalId digitalId) {		
		DiscoverDto discoverDto = null;
		String fileName = null;
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			switch (deviceType)
			{
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER:
					switch (deviceSubType)
					{
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP:
							fileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Finger/Slap/DeviceDiscovery.json"; 
							//env.getProperty(SBIConstant.MOSIP_FINGER_SLAP_DEVICEDEISCOVERYINFO_JSON);
							break;
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE:
							fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_FINGER_SINGLE_DEVICEDEISCOVERYINFO_JSON);
							break;
					}
				break;
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE:
					if (deviceSubType.equalsIgnoreCase(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE))
						fileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Face/DeviceDiscovery.json"; 
						//env.getProperty(SBIConstant.MOSIP_FACE_DEVICEDEISCOVERYINFO_JSON);
				break;
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS:
					switch (deviceSubType)
					{
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE:
							fileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Iris/Double/DeviceDiscovery.json"; 
							//env.getProperty(SBIConstant.MOSIP_IRIS_DOUBLE_DEVICEDEISCOVERYINFO_JSON);
							break;
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE:
							fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_IRIS_SINGLE_DEVICEDEISCOVERYINFO_JSON);
							break;
					}
				break;
			}

			if (FileHelper.exists(fileName)) 
			{
				File jsonFile = new File(fileName);
				discoverDto = objectMapper.readValue(jsonFile, DiscoverDto.class);
				if (discoverDto != null)
				{
					discoverDto.setDigitalId(getUnsignedDigitalId (digitalId, true));
					discoverDto.setDeviceStatus(getDeviceStatus());
					discoverDto.setPurpose(getPurpose ());
					//discoverDto.setCallbackId("http://" + env.getProperty(SBIConstant.SERVER_ADDRESS) + ":" + getPort() + "/");

					switch (getDeviceStatus())
					{						
						case SBIConstant.DEVICE_STATUS_NOTREADY:
//							discoverDto.setError(new ErrorInfo ("110", SBIJsonInfo.getErrorDescription("en", "110"))); 
							break;
						case SBIConstant.DEVICE_STATUS_ISBUSY:
//							discoverDto.setError(new ErrorInfo ("111", SBIJsonInfo.getErrorDescription("en", "111"))); 
							break;
						case SBIConstant.DEVICE_STATUS_NOTREGISTERED:
							discoverDto.setDeviceId("");
							discoverDto.setDeviceCode("");
							discoverDto.setPurpose("");
//							discoverDto.setError(new ErrorInfo ("100", SBIJsonInfo.getErrorDescription("en", "100"))); 
							break;
						default:
//							discoverDto.setError(new ErrorInfo ("0", SBIJsonInfo.getErrorDescription("en", "0"))); 
							break;
					}
				}
				
				return discoverDto;
			}	
		} catch (Exception ex) {
        	LOGGER.error("getDiscoverInfo :: deviceType::" + deviceType + " :: deviceSubType::" + deviceSubType , ex);
		}
		return null;
	}
	
	protected DeviceInfo getDeviceInfo(String deviceType, String deviceSubType, DigitalId digitalId) {
		DeviceInfo deviceInfo = null;
		String fileName = null;
		String keyStoreFileName = null;
		String keyAlias = null;
		String keyPwd = null;
		FileInputStream inputStream = null;
		try {			
			ObjectMapper objectMapper = new ObjectMapper();
			switch (deviceType)
			{
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER:
					switch (deviceSubType)
					{
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP:
							fileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Finger/Slap/DeviceInfo.json"; 
							//env.getProperty(SBIConstant.MOSIP_FINGER_SLAP_DEVICEINFO_JSON);
//							keyStoreFileName = getKeystoreFilePath() + (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEYSTORE_FILE_NAME_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEYSTORE_FILE_NAME));
//							keyAlias = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEY_ALIAS_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEY_ALIAS));
//							keyPwd = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEYSTORE_PWD_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEYSTORE_PWD));
							break;
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE:
							fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_FINGER_SINGLE_DEVICEINFO_JSON);
//							keyStoreFileName = getKeystoreFilePath() + (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEYSTORE_FILE_NAME_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEYSTORE_FILE_NAME));
//							keyAlias = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEY_ALIAS_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEY_ALIAS));
//							keyPwd = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEYSTORE_PWD_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEYSTORE_PWD));
							break;
					}
				break;
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE:
					if (deviceSubType.equalsIgnoreCase(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE))
					{
						fileName = FileHelper.getCanonicalPath () + "/Biometric Devices/Face/DeviceInfo.json";//"env.getProperty(SBIConstant.MOSIP_FACE_DEVICEINFO_JSON);
//						keyStoreFileName = FileHelper.getCanonicalPath () + (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_FILE_NAME_FTM) : "/Biometric Devices/Face/Keys/Device.p12");//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_FILE_NAME)
//						keyAlias = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEY_ALIAS_FTM) : "Device");
//						keyPwd = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_PWD_FTM) : "mosipface");
					}
				break;
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS:
					switch (deviceSubType)
					{
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE:
							fileName = FileHelper.getCanonicalPath () + "/Biometric Devices/Iris/Double/DeviceInfo.json";//env.getProperty(SBIConstant.MOSIP_IRIS_DOUBLE_DEVICEINFO_JSON);
//							keyStoreFileName = getKeystoreFilePath() + (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEYSTORE_FILE_NAME_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEYSTORE_FILE_NAME));
//							keyAlias = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEY_ALIAS_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEY_ALIAS));
//							keyPwd = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEYSTORE_PWD_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEYSTORE_PWD));
							break;
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE:
							fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_IRIS_SINGLE_DEVICEINFO_JSON);
//							keyStoreFileName = getKeystoreFilePath() + (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEYSTORE_FILE_NAME_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEYSTORE_FILE_NAME));
//							keyAlias = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEY_ALIAS_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEY_ALIAS));
//							keyPwd = (purpose.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH) ? env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEYSTORE_PWD_FTM) : env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEYSTORE_PWD));
							break;
					}
				break;
			}

		    keyStoreFileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Face/Keys/Device_Govstack.p12"; 
					//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_FILE_NAME);
			keyAlias = "Device";//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEY_ALIAS);
			keyPwd = "mosipface";//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_PWD);

			if (FileHelper.exists(fileName) && FileHelper.exists(keyStoreFileName)) 
			{
				File jsonFile = new File(fileName);
			    File keyStoreFile = new File(keyStoreFileName);
			    KeyStore keystore = null;
			    if (keyStoreFile.exists())
			    {
			    	inputStream = new FileInputStream (keyStoreFile);
					keystore = loadKeyStore (inputStream, keyPwd);			    	
			    }
				
				PrivateKey key = (PrivateKey)keystore.getKey(keyAlias, keyPwd.toCharArray());

	            /* Get certificate of public key */
	            java.security.cert.Certificate cert = keystore.getCertificate(keyAlias); 

	            /* Here it prints the public key*/
	            //LOGGER.Info("Public Key:");
	            //LOGGER.Info(cert.getPublicKey());

	            /* Here it prints the private key*/
	            //LOGGER.Info("\nPrivate Key:");
	            //LOGGER.Info(key);
	            
				deviceInfo = objectMapper.readValue(jsonFile, DeviceInfo.class);
				deviceInfo.setBioValue("<bioValue>");
				deviceInfo.setTimestamp(formatToISOString(DateUtils.getUTCCurrentDateTime()));
				if (deviceInfo != null)
				{
					deviceInfo.setDigitalId(getUnsignedDigitalId (digitalId, false));
					deviceInfo.setDeviceStatus(getDeviceStatus());
					deviceInfo.setPurpose(getPurpose ());
				//	deviceInfo.setCallbackId("http://" + env.getProperty(SBIConstant.SERVER_ADDRESS) + ":" + getPort() + "/");
					if (!getDeviceStatus().equalsIgnoreCase(SBIConstant.DEVICE_STATUS_NOTREGISTERED))
					{
						deviceInfo.setDigitalId(getSignedDigitalId (deviceInfo.getDigitalId(), key, cert));
					}
					else
					{
						deviceInfo.setDeviceId("");
						deviceInfo.setDeviceCode("");
						deviceInfo.setPurpose("");
					}
				}
        		return deviceInfo;
			}	
		} catch (Exception ex) {
        	LOGGER.error("getDeviceInfo :: deviceType::" + deviceType + " :: deviceSubType::" + deviceSubType , ex);
		}
		finally
		{
			try { // because close can throw an exception
		        if (inputStream != null) inputStream.close();
		    } catch (IOException ignored) {}
		}
		return null;
	}
	
	protected DeviceInfoDto getDeviceInfoDto(String deviceType, String deviceSubType, DeviceInfo deviceInfo) {
		DeviceInfoDto deviceInfoDto = new DeviceInfoDto ();
		String keyStoreFileName = null;
		String keyAlias = null;
		String keyPwd = null;
		FileInputStream inputStream = null;

		try {
			ObjectMapper objectMapper = new ObjectMapper();
//			switch (deviceType)
//			{
//				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER:
//					switch (deviceSubType)
//					{
//						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP:
//							keyStoreFileName = getKeystoreFilePath() + env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEYSTORE_FILE_NAME);
//							keyAlias = env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEY_ALIAS);
//							keyPwd = env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEYSTORE_PWD);
//							break;
//						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE:
//							keyStoreFileName = getKeystoreFilePath() + env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEYSTORE_FILE_NAME);
//							keyAlias = env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEY_ALIAS);
//							keyPwd = env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEYSTORE_PWD);
//							break;
//					}
//				break;
//				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE:
//					if (deviceSubType.equalsIgnoreCase(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE))
//					{
//						keyStoreFileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Face/Keys/Device.p12"; 
//								//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_FILE_NAME);
//						keyAlias = "Device";//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEY_ALIAS);
//						keyPwd = "mosipface";//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_PWD);
//					}
//				break;
//				case SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS:
//					switch (deviceSubType)
//					{
//						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE:
//							keyStoreFileName = getKeystoreFilePath() + env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEYSTORE_FILE_NAME);
//							keyAlias = env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEY_ALIAS);
//							keyPwd = env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEYSTORE_PWD);
//							break;
//						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE:
//							keyStoreFileName = getKeystoreFilePath() + env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEYSTORE_FILE_NAME);
//							keyAlias = env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEY_ALIAS);
//							keyPwd = env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEYSTORE_PWD);
//							break;
//					}
//				break;
//			}

		    keyStoreFileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Face/Keys/Device_Govstack.p12"; 
					//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_FILE_NAME);
			keyAlias = "Device";//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEY_ALIAS);
			keyPwd = "mosipface";//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_PWD);
			if (FileHelper.exists(keyStoreFileName)) 
			{
				String strDeviceInfo = objectMapper.writeValueAsString(deviceInfo);
			    File keyStoreFile = new File(keyStoreFileName);
			    KeyStore keystore = null;
			    if (keyStoreFile.exists())
			    {
			    	inputStream = new FileInputStream (keyStoreFile);
					keystore = loadKeyStore (inputStream, keyPwd);			    	
			    }
								
				PrivateKey key = (PrivateKey)keystore.getKey(keyAlias, keyPwd.toCharArray());

	            /* Get certificate of public key */
	            java.security.cert.Certificate cert = keystore.getCertificate(keyAlias); 

	            /* Here it prints the public key*/
	            //LOGGER.Info("Public Key:");
	            //LOGGER.Info(cert.getPublicKey());

	            /* Here it prints the private key*/
	            //LOGGER.Info("\nPrivate Key:");
	            //LOGGER.Info(key);
				switch (getDeviceStatus())
				{						
					case SBIConstant.DEVICE_STATUS_NOTREADY:
			            deviceInfoDto.setDeviceInfo(JwtUtility.getJwt(strDeviceInfo.getBytes("UTF-8"), key, (X509Certificate) cert));
			            //deviceInfoDto.setError(new ErrorInfo ("110", SBIJsonInfo.getErrorDescription("en", "110"))); 
						break;
					case SBIConstant.DEVICE_STATUS_ISBUSY:
			            deviceInfoDto.setDeviceInfo(JwtUtility.getJwt(strDeviceInfo.getBytes("UTF-8"), key, (X509Certificate) cert));
			            //deviceInfoDto.setError(new ErrorInfo ("111", SBIJsonInfo.getErrorDescription("en", "111"))); 
						break;
					case SBIConstant.DEVICE_STATUS_NOTREGISTERED:
			            deviceInfoDto.setDeviceInfo(getUnsignedDeviceInfo (deviceInfo, true));
			            //deviceInfoDto.setError(new ErrorInfo ("100", SBIJsonInfo.getErrorDescription("en", "100"))); 
						break;
					default:
			            deviceInfoDto.setDeviceInfo(JwtUtility.getJwt(strDeviceInfo.getBytes("UTF-8"), key, (X509Certificate) cert));
			            //deviceInfoDto.setError(new ErrorInfo ("0", SBIJsonInfo.getErrorDescription("en", "0"))); 
						break;
				}

        		return deviceInfoDto ;
			}	
		} catch (Exception ex) {
        	LOGGER.error("getDeviceInfoDto :: deviceType::" + deviceType + " :: deviceSubType::" + deviceSubType , ex);
		}
		finally
		{
			try { // because close can throw an exception
		        if (inputStream != null) inputStream.close();
		    } catch (IOException ignored) {}
		}
		return null;
	}

	public String getSignBioMetricsDataDto(String deviceType, String deviceSubType, String currentBioData) {
		String signedBioMetricsDataDto = null;
		String keyStoreFileName = null;
		String keyAlias = null;
		String keyPwd = null;
		FileInputStream inputStream = null;
		
		try {
//			switch (deviceType)
//			{
//				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER:
//					switch (deviceSubType)
//					{
//						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP:
//							keyStoreFileName = getKeystoreFilePath() + env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEYSTORE_FILE_NAME);
//							keyAlias = env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEY_ALIAS);
//							keyPwd = env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_KEYSTORE_PWD);
//							break;
//						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE:
//							keyStoreFileName = getKeystoreFilePath() + env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEYSTORE_FILE_NAME);
//							keyAlias = env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEY_ALIAS);
//							keyPwd = env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SINGLE_KEYSTORE_PWD);
//							break;
//					}
//				break;
//				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE:
//					if (deviceSubType.equalsIgnoreCase(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE))
//					{
//						keyStoreFileName = getKeystoreFilePath() + env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_FILE_NAME);
//						keyAlias = env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEY_ALIAS);
//						keyPwd = env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_PWD);
//					}
//				break;
//				case SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS:
//					switch (deviceSubType)
//					{
//						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE:
//							keyStoreFileName = getKeystoreFilePath() + env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEYSTORE_FILE_NAME);
//							keyAlias = env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEY_ALIAS);
//							keyPwd = env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_KEYSTORE_PWD);
//							break;
//						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE:
//							keyStoreFileName = getKeystoreFilePath() + env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEYSTORE_FILE_NAME);
//							keyAlias = env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEY_ALIAS);
//							keyPwd = env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_SINGLE_KEYSTORE_PWD);
//							break;
//					}
//				break;
//			}

		    keyStoreFileName = FileHelper.getCanonicalPath () +"/Biometric Devices/Face/Keys/Device_Govstack.p12"; 
					//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_FILE_NAME);
			keyAlias = "Device";//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEY_ALIAS);
			keyPwd = "mosipface";//env.getProperty(SBIConstant.MOSIP_STREAM_FACE_KEYSTORE_PWD);

			if (FileHelper.exists(keyStoreFileName)) 
			{
				File keyStoreFile = new File(keyStoreFileName);
			    KeyStore keystore = null;
			    if (keyStoreFile.exists())
			    {
			    	inputStream = new FileInputStream (keyStoreFile);
					keystore = loadKeyStore (inputStream, keyPwd);			    	
			    }
				
				PrivateKey key = (PrivateKey)keystore.getKey(keyAlias, keyPwd.toCharArray());

	            /* Get certificate of public key */
	            java.security.cert.Certificate cert = keystore.getCertificate(keyAlias); 

	            /* Here it prints the public key*/
	            //LOGGER.Info("Public Key:");
	            //LOGGER.Info(cert.getPublicKey());

	            /* Here it prints the private key*/
	            //LOGGER.Info("\nPrivate Key:");
	            //LOGGER.Info(key);
	            signedBioMetricsDataDto = JwtUtility.getJwt(currentBioData.getBytes("UTF-8"), key, (X509Certificate) cert);
      		//System.out.println("signedBioMetrics :: " + signedBioMetricsDataDto);
        		return signedBioMetricsDataDto ;
			}	
		} catch (Exception ex) {
        	LOGGER.error("getSignBioMetricsDataDto :: deviceType::" + deviceType + " :: deviceSubType::" + deviceSubType , ex);
		}
		finally
		{
			try { // because close can throw an exception
		        if (inputStream != null) inputStream.close();
		    } catch (IOException ignored) {}
		}		
		return null;
	}

	private String getUnsignedDeviceInfo (DeviceInfo deviceInfo, boolean isBase64URLEncoded)
    {
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			if (isBase64URLEncoded)
			{
				return StringHelper.base64UrlEncode (objectMapper.writeValueAsString(deviceInfo));
			}
			else
			{
				return objectMapper.writeValueAsString(deviceInfo);
			}
		} catch (Exception ex) {
        	LOGGER.error("getUnsignedDeviceInfo :: " , ex);
		}
		return null;
    }

	private String getUnsignedDigitalId (DigitalId digitalId, boolean isBase64URLEncoded)
    {
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			if (isBase64URLEncoded)
			{
				return StringHelper.base64UrlEncode (objectMapper.writeValueAsString(digitalId));
			}
			else
			{
				return objectMapper.writeValueAsString(digitalId);
			}
		} catch (Exception ex) {
        	LOGGER.error("getUnsignedDigitalId :: " , ex);
		}
		return null;
    }

	private String getSignedDigitalId (String digitalId, PrivateKey privateKey, Certificate cert)
    {
		try {
			return JwtUtility.getJwt (digitalId.getBytes("UTF-8"), privateKey, (X509Certificate) cert);
		} catch (Exception ex) {
        	LOGGER.error("getSignedDigitalId :: " , ex);
		}
		return null;
    }
	
	private KeyStore loadKeyStore(FileInputStream inputStream, String keystorePwd) throws Exception {
	    KeyStore keyStore = KeyStore.getInstance("JKS");
        // if exists, load
        keyStore.load(inputStream, keystorePwd.toCharArray());

        /*
	    else {
	        // if not exists, create
	        keyStore.load(null, null);
	        keyStore.store(new FileOutputStream(file), keystorePwd.toCharArray());
	    }
	    */
	    return keyStore;
	}
		
	protected byte[] getLiveStreamBufferedImage() {
		byte[] image = null;
		String fileName = null;
		try {
			switch (getDeviceType())
			{
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER:
					switch (getDeviceSubType())
					{
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP:
							switch (getDeviceSubId ())
							{
								case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT:
									fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_SUBID_LEFT_HAND);
									break;
								case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT:
									fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_SUBID_RIGHT_HAND);
									break;
								case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_THUMB:
									fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_STREAM_FINGER_SLAP_SUBID_THUMBS);
									break;
							}
							break;
					}
				break;
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE:
					if (deviceSubType.equalsIgnoreCase(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE))
					{
						if (getDeviceSubId () == SBIConstant.DEVICE_FACE_SUB_TYPE_ID_FULLFACE)
							fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_STREAM_FACE_SUBID_FULLFACE);
					}
				break;
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS:
					switch (getDeviceSubType())
					{
						case SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE:
							switch (getDeviceSubId ())
							{
								case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_LEFT:
									fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_SUBID_LEFT);
									break;
								case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_RIGHT:
									fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_SUBID_RIGHT);
									break;
								case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_BOTH:
									fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_STREAM_IRIS_DOUBLE_SUBID_BOTH);
									break;
							}
							break;
					}
				break;
			}

			if (FileHelper.exists(fileName)) 
			{
				//image = FileHelper.readAllBytes ImageIO.read(new File(fileName));
				image = FileHelper.readAllBytes (fileName);
            	//LOGGER.info ("getLiveStreamBufferedImage :: fileName ::" + fileName);
				//LOGGER.info ("getLiveStreamBufferedImage :: image ::" + image.length);

				return image;
			}	
		} catch (Exception ex) {
        	LOGGER.error("getLiveStreamBufferedImage :: deviceType::" + deviceType + " :: deviceSubType::" + deviceSubType , ex);
		}
		return null;
	}

	protected byte[] getBiometricISOImage(String seedName, String bioSubTypeFileName) {
		byte[] image = null;
		String fileName = null;
		boolean isFolderExist = true;
		try {
			fileName = FileHelper.getCanonicalPath () + env.getProperty(SBIConstant.MOSIP_PROFILE_FOLDER_PATH) + File.separator + getProfileId () + File.separator + getPurpose();
        	//LOGGER.error("getBiometricISOImage :: profileId::" + getProfileId() + " :: Not Set :: fileName :: " + fileName);
			if (!FileHelper.directoryExists(fileName))	
			{
				isFolderExist = false;
				if (FileHelper.directoryExists(fileName))	
				{
					isFolderExist = true;
				}				
			}
			if (isFolderExist)
			{
				fileName = fileName + File.separator + seedName + bioSubTypeFileName;
	            LOGGER.info("getBiometricISOImage :: bioSubTypeFileName :: " + bioSubTypeFileName + " :: fileName ::" + fileName);
				if (FileHelper.exists(fileName))	
				{
					image = FileHelper.readAllBytes (fileName);
					return image;
				}				
			}
		} catch (Exception ex) {
        	LOGGER.error("getBiometricISOImage :: profileId::" + getProfileId() + " :: bioSubTypeFileName::" + bioSubTypeFileName, ex);
		}
		return null;
	}
	
	public String getPurpose() {
		return purpose;
	}
	public void setPurpose(String purpose) {
		this.purpose = purpose;
	}
	public String getProfileId() {
		return profileId;
	}
	public void setProfileId(String profileId) {
		this.profileId = profileId;
	}

	public String getKeystoreFilePath() {
		try {
			return FileHelper.getCanonicalPath();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
//	public void setKeystoreFilePath(String keystoreFilePath) {
//		try {
//			this.keystoreFilePath = keystoreFilePath != null ? keystoreFilePath : FileHelper.getCanonicalPath();
//		} catch (IOException ex) {
//			LOGGER.error("setKeystoreFilePath :: " + keystoreFilePath , ex);
//		}
//	}
	
	public String getDeviceType() {
		return deviceType;
	}
	public void setDeviceType(String deviceType) {
		this.deviceType = deviceType;
	}
	public String getDeviceSubType() {
		return deviceSubType;
	}
	public void setDeviceSubType(String deviceSubType) {
		this.deviceSubType = deviceSubType;
	}
	public DigitalId getDigitalId() {
		return digitalId;
	}

	public void setDigitalId(DigitalId digitalId) {
		this.digitalId = digitalId;
	}

	public DeviceInfo getDeviceInfo() {
		return deviceInfo;
	}

	public void setDeviceInfo(DeviceInfo deviceInfo) {
		this.deviceInfo = deviceInfo;
	}

	public DiscoverDto getDiscoverDto() {
		return discoverDto;
	}
	public void setDiscoverDto(DiscoverDto discoverDto) {
		this.discoverDto = discoverDto;
	}
	public DeviceInfoDto getDeviceInfoDto() {
		return deviceInfoDto;
	}
	public void setDeviceInfoDto(DeviceInfoDto deviceInfoDto) {
		this.deviceInfoDto = deviceInfoDto;
	}

	public String getDeviceStatus() {
		String status = null;
		if (this.statusMap == null)
			this.statusMap = new HashMap<> ();

		if ((this.statusMap.containsKey(SBIConstant.DEVICE_STATUS) == false || SBIConstant.DEVICE_STATUS_ISREADY.equalsIgnoreCase (this.statusMap.get(SBIConstant.DEVICE_STATUS))))
        {
			status = SBIConstant.DEVICE_STATUS_ISREADY;;
            return status; 
        }
		switch (getDeviceStatus(SBIConstant.DEVICE_STATUS))
		{
			case SBIConstant.DEVICE_STATUS_ISBUSY:
				status = SBIConstant.DEVICE_STATUS_ISBUSY;
				break;
			case SBIConstant.DEVICE_STATUS_ISREADY:
				status = SBIConstant.DEVICE_STATUS_ISREADY;
				break;
			case SBIConstant.DEVICE_STATUS_NOTREGISTERED:
				status = SBIConstant.DEVICE_STATUS_NOTREGISTERED;
				break;
			default:
				status = SBIConstant.DEVICE_STATUS_NOTREADY;
				break;
			
		}
        return status;
	}

	public void setDeviceStatus(String deviceStatus) {
        if (this.statusMap.containsKey(SBIConstant.DEVICE_STATUS) == false)
        	this.statusMap.put(SBIConstant.DEVICE_STATUS, deviceStatus);
        else
        	this.statusMap.put(SBIConstant.DEVICE_STATUS, deviceStatus);
	}
	
	public String getDeviceStatus(String key) {
        if (this.statusMap.containsKey(key))
        	return this.statusMap.get(key);
        return null;
	}

	public boolean isScoreFromIso() {
		return scoreFromIso;
	}
	public void setScoreFromIso(boolean scoreFromIso) {
		this.scoreFromIso = scoreFromIso;
	}
	
	public long getDelayForMethod(String methodFor) {
		if (this.delayMap != null)
		{
	        if (this.delayMap.containsKey(methodFor))
	        	return this.delayMap.get(methodFor);
		}
		return 0;
	}

	public void setDelayForMethod(String[] methodFor, long delay) {
		if (this.delayMap == null)
			this.delayMap = new HashMap<> ();
		
		if (methodFor != null)
		{
			for (int index = 0; index < methodFor.length; index++) 
			{
				this.delayMap.putIfAbsent(methodFor[index], delay);
			}
		}
	}
	
	public void resetDelayForMethod()
	{
		if (this.delayMap != null)
		{
			this.delayMap.clear();
			this.delayMap = null;
		}
	}

//	public SBICaptureInfo getCaptureInfo() {
//		return captureInfo;
//	}
//	public void setCaptureInfo(SBICaptureInfo captureInfo) {
//		this.captureInfo = captureInfo;
//	}
	
	public String getDeviceId() {
		return deviceId;
	}
	public void setDeviceId(String deviceId) {
		this.deviceId = deviceId;
	}
	
	public int getDeviceSubId() {
		return deviceSubId;
	}
	public void setDeviceSubId(int deviceSubId) {
		this.deviceSubId = deviceSubId;
	}
	
	public int getQualityScore() {
		if (this.qualityScore <= 0 || this.qualityScore > 100)
			this.qualityScore = Integer.parseInt(env.getProperty(SBIConstant.MOSIP_MOCK_SBI_QUALITY_SCORE));
		
        return this.qualityScore;
	}

	public void setQualityScore(int qualityScore) {
        this.qualityScore = qualityScore;
	}

	public boolean isQualityScoreSet() {
		return isQualityScoreSet;
	}
	public void setQualityScoreSet(boolean isQualityScoreSet) {
		this.isQualityScoreSet = isQualityScoreSet;
	}		

	public int getRandomNumberForSeed(int seed) {
		int value = new Random().nextInt(seed);
		if (value == 0)
			value = 1;
		
		return value;
	}
}
