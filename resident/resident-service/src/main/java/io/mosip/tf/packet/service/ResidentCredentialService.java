package io.mosip.tf.packet.service;

import io.mosip.tf.packet.dto.CredentialCancelRequestResponseDto;
import io.mosip.tf.packet.dto.CredentialRequestStatusResponseDto;
import io.mosip.tf.packet.dto.CredentialTypeResponse;
import io.mosip.tf.packet.dto.PartnerCredentialTypePolicyDto;
import io.mosip.tf.packet.dto.ResidentCredentialRequestDto;
import io.mosip.tf.packet.dto.ResidentCredentialResponseDto;
import io.mosip.tf.packet.dto.ResponseWrapper;
import io.mosip.tf.packet.exception.ResidentServiceCheckedException;

public interface ResidentCredentialService {

	public ResidentCredentialResponseDto reqCredential(ResidentCredentialRequestDto request) throws ResidentServiceCheckedException;

	public CredentialRequestStatusResponseDto getStatus(String requestId) throws ResidentServiceCheckedException;

	public CredentialTypeResponse getCredentialTypes();

	public CredentialCancelRequestResponseDto cancelCredentialRequest(String requestId);

	public byte[] getCard(String requestId) throws Exception;

	public ResponseWrapper<PartnerCredentialTypePolicyDto> getPolicyByCredentialType(String partnerId,
			String credentialType);
}
