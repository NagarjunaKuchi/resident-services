package io.mosip.tf.packet.service.impl;

import io.mosip.kernel.core.exception.BaseCheckedException;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.tf.packet.config.LoggerConfiguration;
import io.mosip.tf.packet.constant.*;
import io.mosip.tf.packet.dto.*;
import io.mosip.tf.packet.exception.*;
import io.mosip.tf.packet.handler.service.PacketCreator;
import io.mosip.tf.packet.service.NotificationService;
import io.mosip.tf.packet.service.PacketCreatorService;
import io.mosip.tf.packet.util.*;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import static io.mosip.tf.packet.constant.ResidentErrorCode.MACHINE_MASTER_CREATE_EXCEPTION;
import static io.mosip.tf.packet.constant.ResidentErrorCode.PACKET_SIGNKEY_EXCEPTION;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class PacketCreatorServiceImpl implements PacketCreatorService {

	private static final String DATETIME_PATTERN = "mosip.utc-datetime-pattern";
	private static final String STATUS_CHECK_ID = "mosip.resident.service.status.check.id";
	private static final String STATUS_CHECEK_VERSION = "mosip.resident.service.status.check.version";
	private static final String PROCESSING_MESSAGE = "UNDER PROCESSING";
	private static final String WAITING_MESSAGE = "WAITING FOR ADDITIONAL INFORMATION FROM APPLICANT";
	private static final String PROOF_OF_ADDRESS = "poa";
	private static final String PROOF_OF_DOB = "pob";
	private static final String PROOF_OF_RELATIONSHIP = "por";
	private static final String PROOF_OF_IDENTITY = "poi";
	private static final String IDENTITY = "identity";
	private static final String VALUE = "value";
	private static final String DOCUMENT = "documents";
	private static final String SERVER_PROFILE_SIGN_KEY = "PROD";
	private static final String UIN = "uin";

	private static final Logger logger = LoggerConfiguration.logConfig(PacketCreatorServiceImpl.class);

	@Autowired
	private PacketCreator packetCreator;


	@Autowired
	NotificationService notificationService;

	@Autowired
	private ResidentServiceRestClient residentServiceRestClient;

	@Autowired
	Environment env;

	@Autowired
	private Utilitiy utility;

    @Autowired
    private Utilities utilities;

    @Value("${resident.center.id}")
    private String centerId;

	@Value("${resident.machine.id}")
	private String machineId;

	@Value("${resident.update-uin.machine-name-prefix}")
	private String residentMachinePrefix;

	@Value("${resident.update-uin.machine-spec-id}")
	private String machineSpecId;

	@Value("${resident.update-uin.machine-zone-code}")
	private String zoneCode;

	@Autowired
	private AuditUtil audit;


	@Override
	public RegStatusCheckResponseDTO getRidStatus(RequestDTO request) {
		logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.APPLICATIONID.toString(),
				LoggerFileConstant.APPLICATIONID.toString(), "ResidentServiceImpl::getRidStatus():: entry");

		RegStatusCheckResponseDTO response = null;
		RegistrationStatusResponseDTO responseWrapper = null;
		RegistrationStatusRequestDTO dto = new RegistrationStatusRequestDTO();
		List<RegistrationStatusSubRequestDto> rids = new ArrayList<>();
		RegistrationStatusSubRequestDto rid = new RegistrationStatusSubRequestDto(request.getIndividualId());

		rids.add(rid);
		dto.setRequest(rids);
		dto.setId(env.getProperty(STATUS_CHECK_ID));
		dto.setVersion(env.getProperty(STATUS_CHECEK_VERSION));
		dto.setRequesttime(DateUtils.getUTCCurrentDateTimeString(env.getProperty(DATETIME_PATTERN)));
		audit.setAuditRequestDto(EventEnum.GETTING_RID_STATUS);
		try {
			responseWrapper = (RegistrationStatusResponseDTO) residentServiceRestClient.postApi(
					env.getProperty(ApiName.REGISTRATIONSTATUSSEARCH.name()), MediaType.APPLICATION_JSON, dto,
					RegistrationStatusResponseDTO.class);
			if (responseWrapper == null) {
				logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.APPLICATIONID.toString(),
						LoggerFileConstant.APPLICATIONID.toString(), "In valid response from Registration status API");
				audit.setAuditRequestDto(EventEnum.INVALID_API_RESPONSE);
				throw new RIDInvalidException(ResidentErrorCode.INVALID_API_RESPONSE.getErrorCode(),
						ResidentErrorCode.INVALID_API_RESPONSE.getErrorMessage()
								+ ApiName.REGISTRATIONSTATUSSEARCH.name());
			}

			if (responseWrapper.getErrors() != null && !responseWrapper.getErrors().isEmpty()) {
				logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.APPLICATIONID.toString(),
						LoggerFileConstant.APPLICATIONID.toString(), responseWrapper.getErrors().get(0).toString());
				audit.setAuditRequestDto(EventEnum.RID_NOT_FOUND);
				throw new RIDInvalidException(ResidentErrorCode.NO_RID_FOUND_EXCEPTION.getErrorCode(),
						ResidentErrorCode.NO_RID_FOUND_EXCEPTION.getErrorMessage()
								+ responseWrapper.getErrors().get(0).toString());
			}
			if ((responseWrapper.getResponse() == null || responseWrapper.getResponse().isEmpty())) {
				logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.APPLICATIONID.toString(),
						LoggerFileConstant.APPLICATIONID.toString(), "In valid response from Registration status API");
				audit.setAuditRequestDto(EventEnum.INVALID_API_RESPONSE);
				throw new RIDInvalidException(ResidentErrorCode.INVALID_API_RESPONSE.getErrorCode(),
						ResidentErrorCode.INVALID_API_RESPONSE.getErrorMessage() + ApiName.REGISTRATIONSTATUSSEARCH);
			}

			String status = validateResponse(responseWrapper.getResponse().get(0).getStatusCode());
			response = new RegStatusCheckResponseDTO();
			response.setRidStatus(status);
			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.RID_STATUS_RESPONSE, status));

		} catch (ApisResourceAccessException e) {
			audit.setAuditRequestDto(
					EventEnum.getEventEnumWithDynamicName(EventEnum.API_RESOURCE_UNACCESS, "checking RID status"));
			if (e.getCause() instanceof HttpClientErrorException) {
				HttpClientErrorException httpClientException = (HttpClientErrorException) e.getCause();
				throw new ResidentServiceException(ResidentErrorCode.API_RESOURCE_ACCESS_EXCEPTION.getErrorCode(),
						httpClientException.getResponseBodyAsString());
			} else if (e.getCause() instanceof HttpServerErrorException) {
				HttpServerErrorException httpServerException = (HttpServerErrorException) e.getCause();
				throw new ResidentServiceException(ResidentErrorCode.API_RESOURCE_ACCESS_EXCEPTION.getErrorCode(),
						httpServerException.getResponseBodyAsString());
			} else {
				throw new ResidentServiceException(ResidentErrorCode.API_RESOURCE_ACCESS_EXCEPTION.getErrorCode(),
						ResidentErrorCode.API_RESOURCE_ACCESS_EXCEPTION.getErrorMessage() + e.getMessage(), e);
			}

		}

		logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.APPLICATIONID.toString(),
				LoggerFileConstant.APPLICATIONID.toString(), "ResidentServiceImpl::getRidStatus():: exit");
		return response;
	}

	private String validateResponse(String statusCode) {
		if (statusCode.equalsIgnoreCase(RegistrationExternalStatusCode.PROCESSED.name()))
			return statusCode.toUpperCase();
		if (statusCode.equalsIgnoreCase(RegistrationExternalStatusCode.REJECTED.name()))
			return statusCode.toUpperCase();
		if (statusCode.equalsIgnoreCase(RegistrationExternalStatusCode.REREGISTER.name()))
			return statusCode.toUpperCase();
		if (statusCode.equalsIgnoreCase(RegistrationExternalStatusCode.RESEND.name()))
			return statusCode.toUpperCase();
		if (statusCode.equalsIgnoreCase(RegistrationExternalStatusCode.PROCESSING.name()))
			return PROCESSING_MESSAGE;
		if (statusCode.equalsIgnoreCase(RegistrationExternalStatusCode.UIN_GENERATED.name()))
			return RegistrationExternalStatusCode.PROCESSED.name();
		if (statusCode.equalsIgnoreCase(RegistrationExternalStatusCode.AWAITING_INFORMATION.name()))
			return WAITING_MESSAGE;
		return PROCESSING_MESSAGE;

	}

	@Override
	public ResidentUpdateResponseDTO createPacket(PacketCreateRequestDto dto) throws ResidentServiceCheckedException {
		ResidentUpdateResponseDTO responseDto = new ResidentUpdateResponseDTO();
		try {
			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.VALIDATE_OTP, "",
					"Request for Create packet"));
            final String publicKey = getPublicKeyFromKeyManager();
            MachineSearchResponseDTO machineSearchResponseDTO = searchMachineInMasterService(residentMachinePrefix, publicKey);
            String machineId = getMachineId(machineSearchResponseDTO, publicKey);
            if (machineId == null) {
               machineId = createNewMachineInMasterService(residentMachinePrefix, machineSpecId, zoneCode, centerId, publicKey);
            }

			ResidentUpdateDto regProcReqUpdateDto = new ResidentUpdateDto();
			regProcReqUpdateDto.setCenterId(centerId);
			regProcReqUpdateDto.setMachineId(machineId);
			regProcReqUpdateDto.setIdentityJson(dto.getIdentityJson());
			regProcReqUpdateDto.setIndividualBiometrics(dto.getIndividualBiometrics());
			List<ResidentDocuments> documents = dto.getDocuments();
			byte[] decodedDemoJson = CryptoUtil.decodeURLSafeBase64(dto.getIdentityJson());
			JSONObject demographicJsonObject = JsonUtil.readValue(new String(decodedDemoJson), JSONObject.class);
			JSONObject demographicIdentity = JsonUtil.getJSONObject(demographicJsonObject, IDENTITY);
			String mappingJson = utility.getMappingJson();
			if (demographicIdentity == null || demographicIdentity.isEmpty() || mappingJson == null
					|| mappingJson.trim().isEmpty()) {
				audit.setAuditRequestDto(
						EventEnum.getEventEnumWithValue(EventEnum.JSON_PARSING_EXCEPTION, ""));
				throw new ResidentServiceException(ResidentErrorCode.JSON_PROCESSING_EXCEPTION.getErrorCode(),
						ResidentErrorCode.JSON_PROCESSING_EXCEPTION.getErrorMessage());
			}
			JSONObject mappingJsonObject = JsonUtil.readValue(mappingJson, JSONObject.class);
			
			JSONObject mappingDocument = JsonUtil.getJSONObject(mappingJsonObject, DOCUMENT);
			String poaMapping = getDocumentName(mappingDocument, PROOF_OF_ADDRESS);
			String poiMapping = getDocumentName(mappingDocument, PROOF_OF_IDENTITY);
			String porMapping = getDocumentName(mappingDocument, PROOF_OF_RELATIONSHIP);
			String pobMapping = getDocumentName(mappingDocument, PROOF_OF_DOB);
			JSONObject proofOfAddressJson = JsonUtil.getJSONObject(demographicIdentity, poaMapping);
			regProcReqUpdateDto.setProofOfAddress(getDocumentValue(proofOfAddressJson, documents));
			JSONObject proofOfIdentityJson = JsonUtil.getJSONObject(demographicIdentity, poiMapping);
			regProcReqUpdateDto.setProofOfIdentity(getDocumentValue(proofOfIdentityJson, documents));
			JSONObject proofOfrelationJson = JsonUtil.getJSONObject(demographicIdentity, porMapping);
			regProcReqUpdateDto.setProofOfRelationship(getDocumentValue(proofOfrelationJson, documents));
			JSONObject proofOfBirthJson = JsonUtil.getJSONObject(demographicIdentity, pobMapping);
			regProcReqUpdateDto.setProofOfDateOfBirth(getDocumentValue(proofOfBirthJson, documents));

			regProcReqUpdateDto.setIdSchemaVersion(demographicIdentity.get("IDSchemaVersion").toString());;
			PacketGeneratorResDto response = packetCreator.createPacket(regProcReqUpdateDto);
			Map<String, Object> additionalAttributes = new HashMap<>();
			additionalAttributes.put("RID", response.getRegistrationId());
			audit.setAuditRequestDto(
					EventEnum.getEventEnumWithValue(EventEnum.OBTAINED_RID_UIN_UPDATE, ""));
			responseDto.setRegistrationId(response.getRegistrationId());
			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.SEND_NOTIFICATION_SUCCESS,
					"", "Request for UIN update"));

		} catch (OtpValidationFailedException e) {
			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.OTP_VALIDATION_FAILED,
					"", "Request for UIN update"));

			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.SEND_NOTIFICATION_FAILURE,
					"", "Request for UIN update"));
			throw new ResidentServiceException(ResidentErrorCode.OTP_VALIDATION_FAILED.getErrorCode(), e.getErrorText(),
					e);

		} catch (ValidationFailedException e) {
			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.VALIDATION_FAILED_EXCEPTION,
					e.getMessage() + " Transaction id: " + "", "Request for UIN update"));

			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.SEND_NOTIFICATION_FAILURE,
					"", "Request for UIN update"));
			throw new ResidentServiceException(e.getErrorCode(), e.getMessage(), e);

		} catch (ApisResourceAccessException e) {
			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.API_RESOURCE_UNACCESS,
					"", "Request for UIN update"));

			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.SEND_NOTIFICATION_FAILURE,
					"", "Request for UIN update"));
			if (e.getCause() instanceof HttpClientErrorException) {
				HttpClientErrorException httpClientException = (HttpClientErrorException) e.getCause();
				throw new ResidentServiceException(ResidentErrorCode.API_RESOURCE_ACCESS_EXCEPTION.getErrorCode(),
						httpClientException.getResponseBodyAsString());

			} else if (e.getCause() instanceof HttpServerErrorException) {
				HttpServerErrorException httpServerException = (HttpServerErrorException) e.getCause();
				throw new ResidentServiceException(ResidentErrorCode.API_RESOURCE_ACCESS_EXCEPTION.getErrorCode(),
						httpServerException.getResponseBodyAsString());
			} else {
				throw new ResidentServiceException(ResidentErrorCode.API_RESOURCE_ACCESS_EXCEPTION.getErrorCode(),
						ResidentErrorCode.API_RESOURCE_ACCESS_EXCEPTION.getErrorMessage() + e.getMessage(), e);
			}
		} catch (IOException e) {
			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.IO_EXCEPTION, "",
					"Request for UIN update"));

			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.SEND_NOTIFICATION_FAILURE,
					"", "Request for UIN update"));
			throw new ResidentServiceException(ResidentErrorCode.IO_EXCEPTION.getErrorCode(),
					ResidentErrorCode.IO_EXCEPTION.getErrorMessage(), e);
		} catch (BaseCheckedException e) {
			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.BASE_EXCEPTION, "",
					"Request for UIN update"));

			audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.SEND_NOTIFICATION_FAILURE,
					"", "Request for UIN update"));
			throw new ResidentServiceException(ResidentErrorCode.BASE_EXCEPTION.getErrorCode(),
					ResidentErrorCode.BASE_EXCEPTION.getErrorMessage(), e);
		}
		return responseDto;
	}

	// get name of document
	private String getDocumentName(JSONObject identityJson, String name) {
		JSONObject docJson = JsonUtil.getJSONObject(identityJson, name);
		return JsonUtil.getJSONValue(docJson, VALUE);
	}

	// get document content
	private String getDocumentValue(JSONObject documentJsonObject, List<ResidentDocuments> documents) {
		if (documentJsonObject == null || documents == null || documents.isEmpty())
			return null;
		String documentName = JsonUtil.getJSONValue(documentJsonObject, VALUE);
		Optional<ResidentDocuments> residentDocument = documents.parallelStream()
				.filter(document -> document.getName().equals(documentName)).findAny();
		if (residentDocument.isPresent())
			return residentDocument.get().getValue();
		else
			throw new ResidentServiceException(ResidentErrorCode.DOCUMENT_NOT_FOUND.getErrorCode(),
					ResidentErrorCode.DOCUMENT_NOT_FOUND.getErrorMessage());

	}
	
	private String getPublicKeyFromKeyManager() throws ApisResourceAccessException {
		PacketSignPublicKeyRequestDTO signKeyRequestDto = PacketSignPublicKeyRequestDTO.builder().request(PacketSignPublicKeyRequestDTO.PacketSignPublicKeyRequest.builder().serverProfile(SERVER_PROFILE_SIGN_KEY).build()).build();
		PacketSignPublicKeyResponseDTO signKeyResponseDTO;
		try {
			HttpEntity<PacketSignPublicKeyRequestDTO> httpEntity = new HttpEntity<>(signKeyRequestDto);
			signKeyResponseDTO = residentServiceRestClient.postApi(env.getProperty(ApiName.PACKETSIGNPUBLICKEY.name()), MediaType.APPLICATION_JSON, httpEntity, PacketSignPublicKeyResponseDTO.class);
			logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), SERVER_PROFILE_SIGN_KEY,
					"ResidentServiceImpl::reqUinUpdate():: PACKETSIGNPUBLICKEY POST service call ended with response data "
							+ signKeyResponseDTO.toString());
			if (signKeyResponseDTO.getErrors() != null && !signKeyResponseDTO.getErrors().isEmpty()) {
				throw new ResidentServiceTPMSignKeyException(signKeyResponseDTO.getErrors().get(0).getErrorCode(), signKeyResponseDTO.getErrors().get(0).getMessage());
			}
			if (signKeyResponseDTO.getResponse() == null) {
				throw new ResidentServiceTPMSignKeyException(PACKET_SIGNKEY_EXCEPTION.getErrorCode(), PACKET_SIGNKEY_EXCEPTION.getErrorMessage());
			}
		} catch (Exception e) {
			logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), SERVER_PROFILE_SIGN_KEY,
					"ResidentServiceImpl::reqUinUpdate():: PACKETSIGNPUBLICKEY POST service call"
							+ ExceptionUtils.getStackTrace(e));
			throw new ApisResourceAccessException("Could not fetch public key from kernel keymanager", e);
		}
		return signKeyResponseDTO.getResponse().getPublicKey();
	}

	private MachineSearchResponseDTO searchMachineInMasterService(String residentMachinePrefix, String publicKey) throws ApisResourceAccessException {
		MachineSearchRequestDTO.MachineSearchFilter searchFilterName = MachineSearchRequestDTO.MachineSearchFilter.builder().columnName("name").type("contains").value(residentMachinePrefix).build();
		MachineSearchRequestDTO.MachineSearchFilter searchFilterPublicKey = MachineSearchRequestDTO.MachineSearchFilter.builder().columnName("signPublicKey").type("equals").value(publicKey).build();
		MachineSearchRequestDTO.MachineSearchSort searchSort = MachineSearchRequestDTO.MachineSearchSort.builder().sortType("desc").sortField("createdDateTime").build();
		MachineSearchRequestDTO machineSearchRequestDTO = MachineSearchRequestDTO.builder()
				.version("1.0")
				//.requesttime(DateUtils.getUTCCurrentDateTimeString()) //TODO fix this
				.request(MachineSearchRequestDTO.MachineSearchRequest.builder()
						.filters(List.of(searchFilterName, searchFilterPublicKey))
						.sort(List.of(searchSort))
						.pagination(MachineSearchRequestDTO.MachineSearchPagination.builder().pageStart(0).pageFetch(10).build())
						.languageCode(utilities.getLanguageCode())
						.build())
				.build();
		MachineSearchResponseDTO machineSearchResponseDTO;
		try {
			HttpEntity<MachineSearchRequestDTO> httpEntity = new HttpEntity<>(machineSearchRequestDTO);
			machineSearchResponseDTO = residentServiceRestClient.postApi(env.getProperty(ApiName.MACHINESEARCH.name()), MediaType.APPLICATION_JSON, httpEntity, MachineSearchResponseDTO.class);
			logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), residentMachinePrefix,
					"ResidentServiceImpl::reqUinUpdate():: MACHINESEARCH POST service call ended with response data "
							+ machineSearchResponseDTO.toString());
			if (machineSearchResponseDTO.getErrors() != null && !machineSearchResponseDTO.getErrors().isEmpty()) {
				throw new ResidentMachineServiceException(machineSearchResponseDTO.getErrors().get(0).getErrorCode(), machineSearchResponseDTO.getErrors().get(0).getMessage());
			}
		} catch (Exception e) {
			logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), residentMachinePrefix,
					"ResidentServiceImpl::reqUinUpdate():: MACHINESEARCH POST service call"
							+ ExceptionUtils.getStackTrace(e));
			throw new ApisResourceAccessException("Could not fetch machines from master data", e);
		}
		return machineSearchResponseDTO;
	}

	private String getMachineId(MachineSearchResponseDTO machineSearchResponseDTO, final String publicKey) {
		if (machineSearchResponseDTO.getResponse() != null) {
			List<MachineDto> fetchedMachines = machineSearchResponseDTO.getResponse().getData();
			if (fetchedMachines != null && !fetchedMachines.isEmpty()) {
				List<MachineDto> machines = fetchedMachines.stream().filter(mac -> mac.getSignPublicKey().equals(publicKey)).collect(Collectors.toList());
				if (!machines.isEmpty()) {
					return machines.get(0).getId();
				}
			}
		}
		return null;
	}

	private String createNewMachineInMasterService(String residentMachinePrefix, String machineSpecId, String zoneCode, String regCenterId, String publicKey) throws ApisResourceAccessException {
		MachineCreateRequestDTO machineCreateRequestDTO = MachineCreateRequestDTO.builder()
				//.requesttime(DateUtils.getUTCCurrentDateTimeString()) //TODO fix this
				.request(MachineDto.builder().serialNum(null).macAddress(null).ipAddress("0.0.0.0").isActive(true)
						.validityDateTime(DateUtils.formatToISOString(DateUtils.getUTCCurrentDateTime().plusYears(3)))
						.name(residentMachinePrefix + System.currentTimeMillis()).machineSpecId(machineSpecId).zoneCode(zoneCode).regCenterId(regCenterId).publicKey(publicKey).signPublicKey(publicKey).build())
				.build();
		MachineCreateResponseDTO machineCreateResponseDTO;
		try {
			HttpEntity<MachineCreateRequestDTO> httpEntity = new HttpEntity<>(machineCreateRequestDTO);
			machineCreateResponseDTO = residentServiceRestClient.postApi(env.getProperty(ApiName.MACHINECREATE.name()), MediaType.APPLICATION_JSON, httpEntity, MachineCreateResponseDTO.class);
			logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), residentMachinePrefix,
					"ResidentServiceImpl::reqUinUpdate():: MACHINECREATE POST service call ended with response data "
							+ machineCreateResponseDTO.toString());
			if (machineCreateResponseDTO.getErrors() != null && !machineCreateResponseDTO.getErrors().isEmpty()) {
				throw new ResidentMachineServiceException(machineCreateResponseDTO.getErrors().get(0).getErrorCode(), machineCreateResponseDTO.getErrors().get(0).getMessage());
			}
			if (machineCreateResponseDTO.getResponse() == null) {
				throw new ResidentMachineServiceException(MACHINE_MASTER_CREATE_EXCEPTION.getErrorCode(), MACHINE_MASTER_CREATE_EXCEPTION.getErrorMessage());
			}
		} catch (Exception e) {
			logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), residentMachinePrefix,
					"ResidentServiceImpl::reqUinUpdate():: MACHINECREATE POST service call"
							+ ExceptionUtils.getStackTrace(e));
			throw new ApisResourceAccessException("Could not create machine in master data", e);
		}
		return machineCreateResponseDTO.getResponse().getId();
	}

	private void validateAuthIndividualIdWithUIN(String individualId, String individualIdType, 
			JSONObject mappingJsonObject, JSONObject demographicIdentity) 
				throws ApisResourceAccessException, ValidationFailedException, IOException {
		String uin = "";
		if(ResidentIndividialIDType.UIN.toString().equals(individualIdType))
			uin = individualId;
		else if(ResidentIndividialIDType.VID.toString().equals(individualIdType)) {
			uin = utilities.getUinByVid(individualId);
		} else {
			logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.APPLICATIONID.toString(),
				LoggerFileConstant.APPLICATIONID.toString(), 
				"ResidentServiceImpl::validateAuthIndividualIdWithUIN():: Individual id type is invalid");
			throw new ValidationFailedException(ResidentErrorCode.INDIVIDUAL_ID_TYPE_INVALID.getErrorCode(),
				ResidentErrorCode.INDIVIDUAL_ID_TYPE_INVALID.getErrorMessage());
		}
		JSONObject identityMappingJsonObject = JsonUtil.getJSONObject(mappingJsonObject, IDENTITY);
		String uinMapping = getDocumentName(identityMappingJsonObject, UIN);
		String identityJsonUIN = JsonUtil.getJSONValue(demographicIdentity, uinMapping);
		if(!identityJsonUIN.equals(uin)) {
			logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.APPLICATIONID.toString(),
				LoggerFileConstant.APPLICATIONID.toString(), 
				"ResidentServiceImpl::validateAuthIndividualIdWithUIN():: Validation failed");
			throw new ValidationFailedException(ResidentErrorCode.INDIVIDUAL_ID_UIN_MISMATCH.getErrorCode(),
				ResidentErrorCode.INDIVIDUAL_ID_UIN_MISMATCH.getErrorMessage());
		}
	}

	@Override
	public String signBiometrics(String cbeff) {
		return packetCreator.signBiometrics(cbeff);
	}
}