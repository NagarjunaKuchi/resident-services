package io.mosip.tf.packet.service;

import java.util.List;

import org.springframework.stereotype.Service;

import io.mosip.tf.packet.constant.AuthTypeStatus;
import io.mosip.tf.packet.dto.AuthTxnDetailsDTO;
import io.mosip.tf.packet.exception.ApisResourceAccessException;
import io.mosip.tf.packet.exception.OtpValidationFailedException;

@Service
public interface IdAuthService {

	public boolean validateOtp(String transactionID, String individualId, String otp)
			throws OtpValidationFailedException;

	public boolean authTypeStatusUpdate(String individualId, List<String> authType,
			AuthTypeStatus authTypeStatus, Long unlockForSeconds) throws ApisResourceAccessException;
	
	public List<AuthTxnDetailsDTO> getAuthHistoryDetails(String individualId,
			String pageStart, String pageFetch) throws ApisResourceAccessException;
}
