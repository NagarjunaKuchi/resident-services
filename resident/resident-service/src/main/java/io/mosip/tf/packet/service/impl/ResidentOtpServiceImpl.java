package io.mosip.tf.packet.service.impl;

import io.mosip.tf.packet.constant.ApiName;
import io.mosip.tf.packet.constant.ResidentErrorCode;
import io.mosip.tf.packet.dto.OtpRequestDTO;
import io.mosip.tf.packet.dto.OtpResponseDTO;
import io.mosip.tf.packet.exception.ApisResourceAccessException;
import io.mosip.tf.packet.exception.ResidentServiceException;
import io.mosip.tf.packet.service.ResidentOtpService;
import io.mosip.tf.packet.util.AuditUtil;
import io.mosip.tf.packet.util.EventEnum;
import io.mosip.tf.packet.util.ResidentServiceRestClient;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

@Service
public class ResidentOtpServiceImpl implements ResidentOtpService {

	@Autowired
	private ResidentServiceRestClient residentServiceRestClient;

	@Autowired
	Environment env;

	@Autowired
	private AuditUtil audit;

	@Override
	public OtpResponseDTO generateOtp(OtpRequestDTO otpRequestDTO) {
		OtpResponseDTO responseDto = null;
		try {
			responseDto = residentServiceRestClient.postApi(
					env.getProperty(ApiName.OTP_GEN_URL.name()), MediaType.APPLICATION_JSON, otpRequestDTO,
					OtpResponseDTO.class);
		} catch (ApisResourceAccessException e) {
			audit.setAuditRequestDto(EventEnum.OTP_GEN_EXCEPTION);
			throw new ResidentServiceException(ResidentErrorCode.OTP_GENERATION_EXCEPTION.getErrorCode(),
					ResidentErrorCode.OTP_GENERATION_EXCEPTION.getErrorMessage(), e);
		}
		return responseDto;
	}


}
