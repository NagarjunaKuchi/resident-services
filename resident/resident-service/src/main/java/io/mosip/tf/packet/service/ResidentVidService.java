package io.mosip.tf.packet.service;

import io.mosip.tf.packet.dto.ResponseWrapper;
import io.mosip.tf.packet.dto.VidRequestDto;
import io.mosip.tf.packet.dto.VidResponseDto;
import io.mosip.tf.packet.dto.VidRevokeRequestDTO;
import io.mosip.tf.packet.dto.VidRevokeResponseDTO;
import io.mosip.tf.packet.exception.OtpValidationFailedException;
import io.mosip.tf.packet.exception.ResidentServiceCheckedException;

import org.springframework.stereotype.Service;

@Service
public interface ResidentVidService {

    public ResponseWrapper<VidResponseDto> generateVid(VidRequestDto requestDto) throws OtpValidationFailedException, ResidentServiceCheckedException;

    public ResponseWrapper<VidRevokeResponseDTO> revokeVid(VidRevokeRequestDTO requestDto,String vid) throws OtpValidationFailedException, ResidentServiceCheckedException;

}
