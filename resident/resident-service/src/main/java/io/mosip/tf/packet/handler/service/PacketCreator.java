package io.mosip.tf.packet.handler.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import org.apache.commons.io.IOUtils;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.tf.packet.dto.DeviceInfo;
import io.mosip.tf.packet.dto.DeviceMetaInfo;
import io.mosip.commons.packet.dto.Document;
import io.mosip.commons.packet.dto.PacketInfo;
import io.mosip.commons.packet.dto.packet.PacketDto;
import io.mosip.commons.packet.exception.PacketCreatorException;
import io.mosip.commons.packet.facade.PacketWriter;
import io.mosip.kernel.biometrics.commons.BiometricsSignatureHelper;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.spi.CbeffUtil;
import io.mosip.kernel.core.exception.BaseCheckedException;
import io.mosip.kernel.core.exception.BaseUncheckedException;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.kernel.core.util.exception.JsonProcessingException;
import io.mosip.kernel.signature.dto.JWTSignatureVerifyResponseDto;
import io.mosip.tf.packet.config.LoggerConfiguration;
import io.mosip.tf.packet.constant.ApiName;
import io.mosip.tf.packet.constant.LoggerFileConstant;
import io.mosip.tf.packet.constant.PacketMetaInfoConstants;
import io.mosip.tf.packet.constant.ResidentErrorCode;
import io.mosip.tf.packet.dto.FieldValue;
import io.mosip.tf.packet.dto.PackerGeneratorFailureDto;
import io.mosip.tf.packet.dto.PacketGeneratorResDto;
import io.mosip.tf.packet.dto.RegistrationType;
import io.mosip.tf.packet.dto.ResidentUpdateDto;
import io.mosip.tf.packet.dto.ResponseWrapper;
import io.mosip.tf.packet.dto.JWTSignatureVerifyRequestDto;
import io.mosip.tf.packet.exception.ApisResourceAccessException;
import io.mosip.tf.packet.mock.sbi.SBIDeviceHelper;
import io.mosip.tf.packet.util.AuditUtil;
import io.mosip.tf.packet.util.EventEnum;
import io.mosip.tf.packet.util.IdSchemaUtil;
import io.mosip.tf.packet.util.JsonUtil;
import io.mosip.tf.packet.util.ResidentServiceRestClient;
import io.mosip.tf.packet.util.SBIConstant;
import io.mosip.tf.packet.util.Utilities;
import io.mosip.tf.packet.validator.RequestHandlerRequestValidator;
import io.mosip.tf.packet.dto.RequestWrapper;

@Component
public class PacketCreator {

	private final Logger logger = LoggerConfiguration.logConfig(PacketCreator.class);
	@Autowired
	private ResidentServiceRestClient restClientService;

	@Autowired
	RequestHandlerRequestValidator validator;

	@Value("${IDSchema.Version}")
	private String idschemaVersion;

	@Autowired
	private IdSchemaUtil idSchemaUtil;

	@Autowired
	SyncAndUploadService syncUploadEncryptionService;

	@Autowired
	private PacketWriter packetWriter;

	@Autowired
	private Environment env;

	@Autowired
	private ObjectMapper mapper;

	@Autowired
	private Utilities utilities;

	@Autowired
	AuditUtil audit;

	@Autowired
	protected CbeffUtil cbeffUtil;

	private static final String PROOF_OF_ADDRESS = "proofOfAddress";
	private static final String PROOF_OF_DOB = "proofOfDOB";
	private static final String PROOF_OF_RELATIONSHIP = "proofOfRelationship";
	private static final String PROOF_OF_IDENTITY = "proofOfIdentity";
	private static final String IDENTITY = "identity";
	private static final String FORMAT = "format";
	private static final String TYPE = "type";
	private static final String VALUE = "value";
	Map<String, DeviceMetaInfo> capturedRegisteredDevices = new LinkedHashMap<>();

	public PacketGeneratorResDto createPacket(ResidentUpdateDto request) throws BaseCheckedException, IOException {
		logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(), request.getIdValue(),
				"ResidentUpdateServiceImpl::createPacket()");
		byte[] packetZipBytes = null;
		audit.setAuditRequestDto(EventEnum.CREATE_PACKET);
		PackerGeneratorFailureDto dto = new PackerGeneratorFailureDto();
		if (validator.isValidCenter(request.getCenterId())) {

			logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(),
					request.getIdValue(),
					"ResidentUpdateServiceImpl::createPacket()::validations for UIN,TYPE,CENTER,MACHINE are successful");

			File file = null;

			try {
				Map<String, String> idMap = new HashMap<>();
				String demoJsonString = new String(CryptoUtil.decodeURLSafeBase64(request.getIdentityJson()));
				JSONObject demoJsonObject = JsonUtil.objectMapperReadValue(demoJsonString, JSONObject.class);
				LinkedHashMap<String, String> fields = (LinkedHashMap<String, String>) demoJsonObject.get(IDENTITY);

				fields.keySet().forEach(key -> {
					try {
						idMap.put(key,
								fields.get(key) != null ? JsonUtils.javaObjectToJsonString(fields.get(key)) : null);
					} catch (JsonProcessingException e) {
						throw new BaseUncheckedException(ResidentErrorCode.JSON_PROCESSING_EXCEPTION.getErrorCode(),
								ResidentErrorCode.JSON_PROCESSING_EXCEPTION.getErrorMessage(), e);
					}
				});

				// set demographic documents
				Map<String, Document> map = new HashMap<>();
				if (request.getProofOfAddress() != null && !request.getProofOfAddress().isEmpty())
					setDemographicDocuments(request.getProofOfAddress(), demoJsonObject, PROOF_OF_ADDRESS, map);
				if (request.getProofOfDateOfBirth() != null && !request.getProofOfDateOfBirth().isEmpty())
					setDemographicDocuments(request.getProofOfAddress(), demoJsonObject, PROOF_OF_DOB, map);
				if (request.getProofOfRelationship() != null && !request.getProofOfRelationship().isEmpty())
					setDemographicDocuments(request.getProofOfAddress(), demoJsonObject, PROOF_OF_RELATIONSHIP, map);
				if (request.getProofOfIdentity() != null && !request.getProofOfIdentity().isEmpty())
					setDemographicDocuments(request.getProofOfAddress(), demoJsonObject, PROOF_OF_IDENTITY, map);

				PacketDto packetDto = new PacketDto();
				packetDto.setId(generateRegistrationId(request.getCenterId(), request.getMachineId()));
				packetDto.setSource(utilities.getDefaultSource());
				packetDto.setProcess(RegistrationType.NEW.toString());
				packetDto.setSchemaVersion(idschemaVersion);
				packetDto.setSchemaJson(idSchemaUtil.getIdSchema(Double.valueOf(idschemaVersion)));
				packetDto.setFields(idMap);
				packetDto.setDocuments(map);
				packetDto.setAudits(utilities.generateAudit(packetDto.getId()));
				packetDto.setOfflineMode(false);
				packetDto.setRefId(request.getCenterId() + "_" + request.getMachineId());
				packetDto.setBiometrics(
						addBiometricDocuments("individualBiometrics", request.getIndividualBiometrics()));
				;
				packetDto.setMetaInfo(getRegistrationMetaData(request.getIdValue(), request.getRequestType().toString(),
						request.getCenterId(), request.getMachineId()));
				List<PacketInfo> packetInfos = packetWriter.createPacket(packetDto);

				if (CollectionUtils.isEmpty(packetInfos) || packetInfos.iterator().next().getId() == null)
					throw new PacketCreatorException(ResidentErrorCode.PACKET_CREATION_EXCEPTION.getErrorCode(),
							ResidentErrorCode.PACKET_CREATION_EXCEPTION.getErrorMessage());

				file = new File(env.getProperty("object.store.base.location") + File.separator
						+ env.getProperty("packet.manager.account.name") + File.separator
						+ packetInfos.iterator().next().getId() + ".zip");

				FileInputStream fis = new FileInputStream(file);

				packetZipBytes = IOUtils.toByteArray(fis);

				String creationTime = DateUtils.formatToISOString(LocalDateTime.now());

				logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
						packetDto.getId(),
						"ResidentUpdateServiceImpl::createPacket()::packet created and sent for sync service");

				PacketGeneratorResDto packerGeneratorResDto = syncUploadEncryptionService.uploadUinPacket(
						packetDto.getId(), creationTime, RegistrationType.NEW.toString(), packetZipBytes);

				logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
						packetDto.getId(), "ResidentUpdateServiceImpl::createPacket()::packet synched and uploaded");
				return packerGeneratorResDto;
			} catch (Exception e) {
				logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
						ResidentErrorCode.BASE_EXCEPTION.getErrorMessage(), ExceptionUtils.getStackTrace(e));
				if (e instanceof BaseCheckedException) {
					throw (BaseCheckedException) e;
				}
				audit.setAuditRequestDto(EventEnum.UNKNOWN_EXCEPTION);
				throw new BaseCheckedException(ResidentErrorCode.UNKNOWN_EXCEPTION.getErrorCode(),
						ResidentErrorCode.UNKNOWN_EXCEPTION.getErrorMessage(), e);

			} finally {
				// if (file != null && file.exists())
				// FileUtils.forceDelete(file);
			}

		} else
			return dto;
	}

	public String getPayLoad(String data) {
		if (data == null || data.isEmpty()) {
		}
		String payload = null;
		Pattern pattern = Pattern.compile(SBIConstant.BIOMETRIC_SEPERATOR);
		Matcher matcher = pattern.matcher(data);
		if (matcher.find()) {
			payload = matcher.group(1);
			System.out.println("PAYLOAD :: " + payload);
		}
		return payload;
	}

	private Map<String, BiometricRecord> addBiometricDocuments(String individualBiometrics, String cbeffData)
			throws Exception {
		Map<String, BiometricRecord> bioValues = new HashMap<String, BiometricRecord>();
		BiometricRecord biometricRecord = new BiometricRecord();
		byte[] data = CryptoUtil.decodeURLSafeBase64(cbeffData);
		List<BIR> segments = new ArrayList<>();
		try {
			cbeffUtil.validateXML(data);
			byte[] newCbeffData = cbeffUtil.createXML(cbeffUtil.getBIRDataFromXML(data));
			System.out.println("newCbeffData:" + CryptoUtil.encodeToURLSafeBase64(newCbeffData));
			List<BIR> birs = cbeffUtil.getBIRDataFromXML(newCbeffData);
			for (BIR bir : birs) {
				BIR newBir = new BIR();
				newBir.setBdb(bir.getBdb());
				newBir.setBdbInfo(bir.getBdbInfo());
				newBir.setBirInfo(bir.getBirInfo());
				newBir.setBirs(bir.getBirs());
				newBir.setCbeffversion(bir.getCbeffversion());
				newBir.setVersion(bir.getVersion());
				newBir.setOthers(getBIROthers(bir.getBdbInfo().getType().toString()));
				newBir.setSb(getSignature(getSignBioData(bir.getBdbInfo().getType().toString(),
						CryptoUtil.encodeToURLSafeBase64(bir.getBdb()),
						getBIROthers(bir.getBdbInfo().getType().toString()).get("PAYLOAD"))).getBytes());
				segments.add(newBir);

				try {
					String token = BiometricsSignatureHelper.extractJWTToken(newBir);
					if (validateJWTToken("", token)) {
						System.out.println("Validating Token success for :: " + bir.getBdbInfo().getType().toString()
								+ " " + bir.getBdbInfo().getSubtype().toString());

					} else {
						System.out.println("Validating Token fail for :: " + bir.getBdbInfo().getType().toString() + " "
								+ bir.getBdbInfo().getSubtype().toString());

					}

				} catch (Exception wx) {
					wx.printStackTrace();
					System.out.println("Error from Packet Creator:: " + wx.getMessage());
					;
				}
//				}
			}
			biometricRecord.setSegments(segments);
			bioValues.put(individualBiometrics, biometricRecord);
		} catch (Exception e) {
			throw e;
		}
		return bioValues;
	}

	public String signBiometrics(String cbeffData) {
		List<BIR> segments = new ArrayList<>();
		try {
			byte[] data = CryptoUtil.decodeURLSafeBase64(cbeffData);
			cbeffUtil.validateXML(data);
			List<BIR> birs = cbeffUtil.getBIRDataFromXML(data);

			for (BIR bir : birs) {
				BIR newBir = new BIR();
				newBir.setBdb(bir.getBdb());
				newBir.setBdbInfo(bir.getBdbInfo());
				newBir.setBirInfo(bir.getBirInfo());
				newBir.setBirs(bir.getBirs());
				newBir.setCbeffversion(bir.getCbeffversion());
				newBir.setVersion(bir.getVersion());
				newBir.setOthers(getBIROthers(bir.getBdbInfo().getType().toString()));
				newBir.setSb(getSignature(getSignBioData(bir.getBdbInfo().getType().toString(),
						CryptoUtil.encodeToURLSafeBase64(bir.getBdb()),
						getBIROthers(bir.getBdbInfo().getType().toString()).get("PAYLOAD"))).getBytes());
				segments.add(newBir);
				String token = BiometricsSignatureHelper.extractJWTToken(newBir);
				if (validateJWTToken("", token)) {
//					System.out.println("Validating Token success for :: " + bir.getBdbInfo().getType().toString() + " "
//							+ bir.getBdbInfo().getSubtype().toString());
				} else {
					System.out.println("Validating Token fail for :: " + bir.getBdbInfo().getType().toString() + " "
							+ bir.getBdbInfo().getSubtype().toString());
					signBiometrics(cbeffData);

				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		byte[] newCbeffData = null;
		try {
			newCbeffData = cbeffUtil.createXML(segments);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return CryptoUtil.encodeToURLSafeBase64(newCbeffData);
	}

	public String getSignature(String data) {
		if (data == null || data.isEmpty()) {

		}
		Pattern pattern = Pattern.compile(SBIConstant.BIOMETRIC_SEPERATOR);
		Matcher matcher = pattern.matcher(data);
		if (matcher.find()) {
			// returns header..signature
			return data.replace(matcher.group(1), "");
		}

		return null;
	}

	private HashMap<String, String> getBIROthers(String type) {
		HashMap<String, String> others = new HashMap<>();
		if (type.contains("FACE")) {
			SBIDeviceHelper deviceHelper = new SBIDeviceHelper("Registration", SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE,
					SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE,
					env.getProperty("mosip.mock.sbi.file.face.keys.keystorefilename"));
			others.put("SPEC_VERSION", "0.9.5");
			others.put("RETRIES", "1");
			others.put("FORCE_CAPTURED", "false");
			others.put("EXCEPTION", "false");

			try {
				others.put("PAYLOAD", mapper.writeValueAsString(deviceHelper.getDeviceInfo()));
			} catch (com.fasterxml.jackson.core.JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			others.put("SDK_SCORE", "0.0");
			if (!capturedRegisteredDevices.containsKey(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)) {
				DeviceMetaInfo deviceMetaInfo = new DeviceMetaInfo();
				DeviceInfo deviceInfo = new DeviceInfo();
				deviceInfo = deviceHelper.getDeviceInfo();
				deviceMetaInfo.setDigitalId(deviceHelper.getDigitalId());
				deviceMetaInfo.setDeviceCode(deviceInfo.getDeviceCode());
				deviceMetaInfo.setDeviceServiceVersion(deviceInfo.getServiceVersion());
				capturedRegisteredDevices.put(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE, deviceMetaInfo);
			}
			return others;
		}
		if (type.contains("FINGER")) {
			SBIDeviceHelper deviceHelper = new SBIDeviceHelper("Registration", SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER,
					SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP,
					env.getProperty("mosip.mock.sbi.file.face.keys.keystorefilename"));
			others.put("SPEC_VERSION", "0.9.5");
			others.put("RETRIES", "1");
			others.put("FORCE_CAPTURED", "false");
			others.put("EXCEPTION", "false");
//			others.put("PAYLOAD", deviceHelper.getDeviceInfoDto().getDeviceInfo());
			try {
				others.put("PAYLOAD", mapper.writeValueAsString(deviceHelper.getDeviceInfo()));
			} catch (com.fasterxml.jackson.core.JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			others.put("SDK_SCORE", "0.0");
			if (!capturedRegisteredDevices.containsKey(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)) {
				DeviceMetaInfo deviceMetaInfo = new DeviceMetaInfo();
				DeviceInfo deviceInfo = new DeviceInfo();
				deviceInfo = deviceHelper.getDeviceInfo();
				deviceMetaInfo.setDigitalId(deviceHelper.getDigitalId());
				deviceMetaInfo.setDeviceCode(deviceInfo.getDeviceCode());
				deviceMetaInfo.setDeviceServiceVersion(deviceInfo.getServiceVersion());
				capturedRegisteredDevices.put(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER, deviceMetaInfo);
			}

			return others;

		}
		if (type.contains("IRIS")) {
			SBIDeviceHelper deviceHelper = new SBIDeviceHelper("Registration", SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS,
					SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE,
					env.getProperty("mosip.mock.sbi.file.face.keys.keystorefilename"));
			others.put("SPEC_VERSION", "0.9.5");
			others.put("RETRIES", "1");
			others.put("FORCE_CAPTURED", "false");
			others.put("EXCEPTION", "false");
			try {
				others.put("PAYLOAD", mapper.writeValueAsString(deviceHelper.getDeviceInfo()));
			} catch (com.fasterxml.jackson.core.JsonProcessingException e) {
				e.printStackTrace();
			}

			others.put("SDK_SCORE", "0.0");
			if (!capturedRegisteredDevices.containsKey(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) {
				DeviceMetaInfo deviceMetaInfo = new DeviceMetaInfo();
				DeviceInfo deviceInfo = new DeviceInfo();
				deviceInfo = deviceHelper.getDeviceInfo();
				deviceMetaInfo.setDigitalId(deviceHelper.getDigitalId());
				deviceMetaInfo.setDeviceCode(deviceInfo.getDeviceCode());
				deviceMetaInfo.setDeviceServiceVersion(deviceInfo.getServiceVersion());
				capturedRegisteredDevices.put(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS, deviceMetaInfo);
			}
			return others;
		}
		return others;
	}

	private String getSignBioData(String type, String bioData, String payload) {
		String bioDataToSign = payload.replace("<bioValue>", bioData);
		if (type.contains("FACE")) {
			SBIDeviceHelper deviceHelper = new SBIDeviceHelper("Registration", SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE,
					SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE,
					env.getProperty("mosip.mock.sbi.file.face.keys.keystorefilename"));
			return deviceHelper.getSignBioMetricsDataDto(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE,
					SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE, bioDataToSign);
		}
		if (type.contains("FINGER")) {
			SBIDeviceHelper deviceHelper = new SBIDeviceHelper("Registration", SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER,
					SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP,
					env.getProperty("mosip.mock.sbi.file.face.keys.keystorefilename"));
			return deviceHelper.getSignBioMetricsDataDto(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER,
					SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP, bioDataToSign);
		}
		if (type.contains("IRIS")) {
			SBIDeviceHelper deviceHelper = new SBIDeviceHelper("Registration", SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS,
					SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE,
					env.getProperty("mosip.mock.sbi.file.face.keys.keystorefilename"));
			return deviceHelper.getSignBioMetricsDataDto(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS,
					SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE, bioDataToSign);
		}
		return null;
	}

	private void setDemographicDocuments(String documentBytes, JSONObject demoJsonObject, String documentName,
			Map<String, Document> map) {
		JSONObject identityJson = JsonUtil.getJSONObject(demoJsonObject, IDENTITY);
		JSONObject documentJson = JsonUtil.getJSONObject(identityJson, documentName);
		if (documentJson == null)
			return;
		Document docDetailsDto = new Document();
		docDetailsDto.setDocument(CryptoUtil.decodeURLSafeBase64(documentBytes));
		docDetailsDto.setFormat((String) JsonUtil.getJSONValue(documentJson, FORMAT));
		docDetailsDto.setValue((String) JsonUtil.getJSONValue(documentJson, VALUE));
		docDetailsDto.setType((String) JsonUtil.getJSONValue(documentJson, TYPE));
		map.put(documentName, docDetailsDto);
	}

	private Map<String, String> getRegistrationMetaData(String registrationType, String uin, String centerId,
			String machineId) throws JsonProcessingException {

		Map<String, String> metadata = new HashMap<>();

		FieldValue[] fieldValues = new FieldValue[3];
		FieldValue fieldValue0 = new FieldValue();
		fieldValue0.setLabel(PacketMetaInfoConstants.CENTERID);
		fieldValue0.setValue(centerId);
		fieldValues[0] = fieldValue0;

		FieldValue fieldValue1 = new FieldValue();
		fieldValue1.setLabel(PacketMetaInfoConstants.MACHINEID);
		fieldValue1.setValue(machineId);
		fieldValues[1] = fieldValue1;

		FieldValue fieldValue2 = new FieldValue();
		fieldValue2.setLabel(PacketMetaInfoConstants.REGISTRATION_TYPE);
		fieldValue2.setValue(registrationType);
		fieldValues[2] = fieldValue2;

		metadata.put("metaData", JsonUtils.javaObjectToJsonString(fieldValues));
		setOperationsData(metadata);
		try {
			metadata.put("capturedRegisteredDevices", mapper.writeValueAsString(capturedRegisteredDevices.values()));
		} catch (com.fasterxml.jackson.core.JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return metadata;
	}

	private void setOperationsData(Map<String, String> metaInfoMap) {
		Map<String, String> operationsDataMap = new LinkedHashMap<>();
		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_ID, "globaladmin");
		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_BIOMETRIC_FILE, null);
		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_ID, null);
		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_BIOMETRIC_FILE, null);
		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_PWD, "false");
		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_PWD, "true");
		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_PIN, null);
		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_PIN, null);
		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_OTP, "false");
		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_OTP, "false");
		metaInfoMap.put(PacketMetaInfoConstants.META_INFO_OPERATIONS_DATA,
				getJsonString(getLabelValueDTOListString(operationsDataMap)));
	}

	private String getJsonString(Object object) {
		try {
			return mapper.writeValueAsString(object);
		} catch (IOException ioException) {
			//
		}
		return null;
	}

	private List<Map<String, String>> getLabelValueDTOListString(Map<String, String> operationsDataMap) {
		List<Map<String, String>> labelValueMap = new LinkedList<>();
		for (Entry<String, String> fieldName : operationsDataMap.entrySet()) {
			Map<String, String> map = new LinkedHashMap<>();
			map.put("label", fieldName.getKey());
			map.put("value", fieldName.getValue());
			labelValueMap.add(map);
		}
		return labelValueMap;
	}

	private String generateRegistrationId(String centerId, String machineId) throws BaseCheckedException {
		List<String> pathsegments = new ArrayList<>();
		pathsegments.add(centerId);
		pathsegments.add(machineId);
		String rid = null;
		ResponseWrapper<?> responseWrapper;
		JSONObject ridJson;
		try {

			logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
					"PacketGeneratorServiceImpl::generateRegistrationId():: RIDgeneration Api call started");
			responseWrapper = (ResponseWrapper<?>) restClientService.getApi(ApiName.RIDGENERATION, pathsegments, "", "",
					ResponseWrapper.class);
			if (CollectionUtils.isEmpty(responseWrapper.getErrors())) {
				ridJson = mapper.readValue(mapper.writeValueAsString(responseWrapper.getResponse()), JSONObject.class);
				logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
						"\"PacketGeneratorServiceImpl::generateRegistrationId():: RIDgeneration Api call  ended with response data : "
								+ JsonUtil.objectMapperObjectToJson(ridJson));
				rid = (String) ridJson.get("rid");

			} else {
				List<ServiceError> error = responseWrapper.getErrors();
				logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
						"\"PacketGeneratorServiceImpl::generateRegistrationId():: RIDgeneration Api call  ended with response data : "
								+ error.get(0).getMessage());
				throw new BaseCheckedException(ResidentErrorCode.BASE_EXCEPTION.getErrorCode(),
						error.get(0).getMessage(), new Throwable());
			}

		} catch (ApisResourceAccessException e) {
			if (e.getCause() instanceof HttpClientErrorException) {
				throw new BaseCheckedException(ResidentErrorCode.BASE_EXCEPTION.getErrorCode(), e.getMessage(), e);
			}
		} catch (IOException e) {
			throw new BaseCheckedException(ResidentErrorCode.BASE_EXCEPTION.getErrorCode(), e.getMessage(), e);
		}
		return rid;
	}

	private boolean validateJWTToken(String id, String token) {
		JWTSignatureVerifyRequestDto jwtSignatureVerifyRequestDto = new JWTSignatureVerifyRequestDto();

		jwtSignatureVerifyRequestDto.setApplicationId("REGISTRATION");
		jwtSignatureVerifyRequestDto.setReferenceId("SIGN");
		jwtSignatureVerifyRequestDto.setJwtSignatureData(token);
		jwtSignatureVerifyRequestDto.setActualData(token.split("\\.")[1]);
//		System.out.println("jwtSignatureVerifyRequestDto actual Data :: " + jwtSignatureVerifyRequestDto.getActualData());

		// in packet validator stage we are checking only the structural part of the
		// packet so setting validTrust to false
		jwtSignatureVerifyRequestDto.setValidateTrust(false);
		jwtSignatureVerifyRequestDto.setDomain("Device");
		RequestWrapper<JWTSignatureVerifyRequestDto> request = new RequestWrapper<>();

		request.setRequest(jwtSignatureVerifyRequestDto);
		request.setVersion("1.0");
		DateTimeFormatter format = DateTimeFormatter
				.ofPattern(env.getProperty("mosip.registration.processor.datetime.pattern"));
		LocalDateTime localdatetime = LocalDateTime.parse(
				DateUtils.getUTCCurrentDateTimeString(env.getProperty("mosip.registration.processor.datetime.pattern")),
				format);
		request.setRequesttime(localdatetime.toString());

		ResponseWrapper<?> responseWrapper = null;
		try {
			responseWrapper = (ResponseWrapper<?>) restClientService.postApi(env.getProperty("JWTVERIFY"),
					MediaType.APPLICATION_JSON, request, ResponseWrapper.class);
		} catch (ApisResourceAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (responseWrapper.getResponse() != null) {
			JWTSignatureVerifyResponseDto jwtResponse = null;
			try {
				jwtResponse = mapper.readValue(mapper.writeValueAsString(responseWrapper.getResponse()),
						JWTSignatureVerifyResponseDto.class);
			} catch (com.fasterxml.jackson.core.JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			if (!jwtResponse.isSignatureValid()) {
//				try {
////					logger.error(LoggerFileConstant.REGISTRATIONID.toString(), id,
////							"Request -> " + JsonUtils.javaObjectToJsonString(request)
////							," Response -> " + JsonUtils.javaObjectToJsonString(responseWrapper));
//				} catch (JsonProcessingException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
				return false;
			} else {
				System.out.println("Signature Validation is success");
				return true;
			}
		} else {
			try {
				logger.error(LoggerFileConstant.REGISTRATIONID.toString(), id,
						"Request -> " + JsonUtils.javaObjectToJsonString(request),
						" Response -> " + JsonUtils.javaObjectToJsonString(responseWrapper));
			} catch (JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return false;
		}

	}

}
