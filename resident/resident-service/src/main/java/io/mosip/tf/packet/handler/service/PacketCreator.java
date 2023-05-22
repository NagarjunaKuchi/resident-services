package io.mosip.tf.packet.handler.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.io.IOUtils;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

import io.mosip.commons.packet.dto.Document;
import io.mosip.commons.packet.dto.PacketInfo;
import io.mosip.commons.packet.dto.packet.PacketDto;
import io.mosip.commons.packet.exception.PacketCreatorException;
import io.mosip.commons.packet.facade.PacketWriter;
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
import io.mosip.kernel.core.util.FileUtils;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.kernel.core.util.exception.JsonProcessingException;
import io.mosip.tf.packet.config.LoggerConfiguration;
import io.mosip.tf.packet.constant.ApiName;
import io.mosip.tf.packet.constant.LoggerFileConstant;
import io.mosip.tf.packet.constant.PacketMetaInfoConstants;
import io.mosip.tf.packet.constant.ResidentErrorCode;
import io.mosip.tf.packet.dto.FieldValue;
import io.mosip.tf.packet.dto.PackerGeneratorFailureDto;
import io.mosip.tf.packet.dto.PacketGeneratorResDto;
import io.mosip.tf.packet.dto.RegistrationType;
import io.mosip.tf.packet.dto.ResidentIndividialIDType;
import io.mosip.tf.packet.dto.ResidentUpdateDto;
import io.mosip.tf.packet.dto.ResponseWrapper;
import io.mosip.tf.packet.exception.ApisResourceAccessException;
import io.mosip.tf.packet.util.AuditUtil;
import io.mosip.tf.packet.util.EventEnum;
import io.mosip.tf.packet.util.IdSchemaUtil;
import io.mosip.tf.packet.util.JsonUtil;
import io.mosip.tf.packet.util.ResidentServiceRestClient;
import io.mosip.tf.packet.util.TokenGenerator;
import io.mosip.tf.packet.util.Utilities;
import io.mosip.tf.packet.validator.RequestHandlerRequestValidator;

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
	
	private ObjectMapper objectMapper = new ObjectMapper();

	private static final String PROOF_OF_ADDRESS = "proofOfAddress";
	private static final String PROOF_OF_DOB = "proofOfDOB";
	private static final String PROOF_OF_RELATIONSHIP = "proofOfRelationship";
	private static final String PROOF_OF_IDENTITY = "proofOfIdentity";
	private static final String IDENTITY = "identity";
	private static final String FORMAT = "format";
	private static final String TYPE = "type";
	private static final String VALUE = "value";

	public PacketGeneratorResDto createPacket(ResidentUpdateDto request) throws BaseCheckedException, IOException {
		logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(),
				request.getIdValue(), "ResidentUpdateServiceImpl::createPacket()");
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
						idMap.put(key, fields.get(key) != null ? JsonUtils.javaObjectToJsonString(fields.get(key)) : null);
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
					setDemographicDocuments(request.getProofOfAddress(), demoJsonObject, PROOF_OF_RELATIONSHIP,
							map);
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
				packetDto.setMetaInfo(getRegistrationMetaData(request.getIdValue(),
						request.getRequestType().toString(), request.getCenterId(), request.getMachineId()));
				packetDto.setAudits(utilities.generateAudit(packetDto.getId()));
				packetDto.setOfflineMode(false);
				packetDto.setRefId(request.getCenterId() + "_" + request.getMachineId());
				packetDto.setBiometrics(addBiometricDocuments("individualBiometrics", request.getIndividualBiometrics()));;
				List<PacketInfo> packetInfos = packetWriter.createPacket(packetDto);

				if (CollectionUtils.isEmpty(packetInfos) || packetInfos.iterator().next().getId() == null)
					throw new PacketCreatorException(ResidentErrorCode.PACKET_CREATION_EXCEPTION.getErrorCode(), ResidentErrorCode.PACKET_CREATION_EXCEPTION.getErrorMessage());

				file = new File(env.getProperty("object.store.base.location")
						+ File.separator + env.getProperty("packet.manager.account.name")
						+ File.separator + packetInfos.iterator().next().getId() + ".zip");

				FileInputStream fis = new FileInputStream(file);

				packetZipBytes = IOUtils.toByteArray(fis);

				String creationTime = DateUtils.formatToISOString(LocalDateTime.now());

				logger.debug(LoggerFileConstant.SESSIONID.toString(),
						LoggerFileConstant.REGISTRATIONID.toString(), packetDto.getId(),
						"ResidentUpdateServiceImpl::createPacket()::packet created and sent for sync service");

				PacketGeneratorResDto packerGeneratorResDto = syncUploadEncryptionService.uploadUinPacket(
						packetDto.getId(), creationTime, RegistrationType.NEW.toString(),
						packetZipBytes);

				logger.debug(LoggerFileConstant.SESSIONID.toString(),
						LoggerFileConstant.REGISTRATIONID.toString(), packetDto.getId(),
						"ResidentUpdateServiceImpl::createPacket()::packet synched and uploaded");
				return packerGeneratorResDto;
			} catch (Exception e) {
				logger.error(LoggerFileConstant.SESSIONID.toString(),
						LoggerFileConstant.REGISTRATIONID.toString(),
						ResidentErrorCode.BASE_EXCEPTION.getErrorMessage(),
						ExceptionUtils.getStackTrace(e));
				if (e instanceof BaseCheckedException) {
					throw (BaseCheckedException) e;
				}
				audit.setAuditRequestDto(EventEnum.UNKNOWN_EXCEPTION);
				throw new BaseCheckedException(ResidentErrorCode.UNKNOWN_EXCEPTION.getErrorCode(),
						ResidentErrorCode.UNKNOWN_EXCEPTION.getErrorMessage(), e);

			} finally {
				//if (file != null && file.exists())
				//	FileUtils.forceDelete(file);
			}

		} else
			return dto;
	}

	private Map<String, BiometricRecord> addBiometricDocuments(String individualBiometrics, String cbeffData) throws Exception {
		Map<String, BiometricRecord> bioValues = new HashMap<String, BiometricRecord>();
		BiometricRecord biometricRecord = new BiometricRecord();
		byte[] data = CryptoUtil.decodeURLSafeBase64(cbeffData);
		try {
			cbeffUtil.validateXML(data);
			byte[] newCbeffData = cbeffUtil.createXML(cbeffUtil.getBIRDataFromXML(data));
			System.out.println("newCbeffData:" + CryptoUtil.encodeToURLSafeBase64(newCbeffData));
			List<BIR> birs = cbeffUtil.getBIRDataFromXML(newCbeffData);			
			biometricRecord.setSegments(birs);
			biometricRecord.setOthers(null);
			bioValues.put(individualBiometrics, biometricRecord);
//			System.out.println(new Gson().toJson(biometricRecord.getSegments()));
			for (BIR bir : birs) {
				System.out.println(bir.getBdbInfo().getType());
				System.out.println(bir.getBdbInfo().getSubtype());
			}
		} catch (Exception e) {
			throw e;
		}
		return bioValues;
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

		FieldValue[] fieldValues = new FieldValue[4];
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
		
		FieldValue fieldValue3 = new FieldValue();
		fieldValue2.setLabel(PacketMetaInfoConstants.REGISTRATION_TYPE);
		fieldValue2.setValue(registrationType);		
		
		
		metadata.put("metaData", JsonUtils.javaObjectToJsonString(fieldValues));
		setOperationsData(metadata);
		return metadata;
	}
	
	private void setOperationsData(Map<String, String> metaInfoMap){

		Map<String, String> operationsDataMap = new LinkedHashMap<>();
		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_ID, "globaladmin");
//		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_BIOMETRIC_FILE,
//				registrationDTO.getOfficerBiometrics().isEmpty() ? null : officerBiometricsFileName);
//		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_BIOMETRIC_FILE,
//				registrationDTO.getSupervisorBiometrics().isEmpty() ? null : supervisorBiometricsFileName);
		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_ID,
		"globaladmin");
		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_PWD,
				String.valueOf("Techno@123"));
		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_PWD,
				String.valueOf("Techno@123"));
		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_PIN, null);
		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_PIN, null);
		operationsDataMap.put(PacketMetaInfoConstants.META_SUPERVISOR_OTP,
				String.valueOf("false"));
		operationsDataMap.put(PacketMetaInfoConstants.META_OFFICER_OTP,
				String.valueOf("false"));

		metaInfoMap.put(PacketMetaInfoConstants.META_INFO_OPERATIONS_DATA,
				getJsonString(getLabelValueDTOListString(operationsDataMap)));

	}
	
	private String getJsonString(Object object){
		try {
			return objectMapper.writeValueAsString(object);
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

			logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					"", "PacketGeneratorServiceImpl::generateRegistrationId():: RIDgeneration Api call started");
			responseWrapper = (ResponseWrapper<?>) restClientService.getApi(ApiName.RIDGENERATION, pathsegments, "", "",
					ResponseWrapper.class);
			if (CollectionUtils.isEmpty(responseWrapper.getErrors())) {
				ridJson = mapper.readValue(mapper.writeValueAsString(responseWrapper.getResponse()), JSONObject.class);
				logger.debug(LoggerFileConstant.SESSIONID.toString(),
						LoggerFileConstant.REGISTRATIONID.toString(), "",
						"\"PacketGeneratorServiceImpl::generateRegistrationId():: RIDgeneration Api call  ended with response data : "
								+ JsonUtil.objectMapperObjectToJson(ridJson));
				rid = (String) ridJson.get("rid");

			} else {
				List<ServiceError> error = responseWrapper.getErrors();
				logger.debug(LoggerFileConstant.SESSIONID.toString(),
						LoggerFileConstant.REGISTRATIONID.toString(), "",
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

}
