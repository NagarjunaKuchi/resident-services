package io.mosip.tf.packet.service;

import io.mosip.tf.packet.dto.RegStatusCheckResponseDTO;
import io.mosip.tf.packet.dto.RequestDTO;
import io.mosip.tf.packet.dto.PacketCreateRequestDto;
import io.mosip.tf.packet.dto.ResidentUpdateResponseDTO;
import io.mosip.tf.packet.exception.ApisResourceAccessException;
import io.mosip.tf.packet.exception.ResidentServiceCheckedException;

public interface PacketCreatorService {

	public RegStatusCheckResponseDTO getRidStatus(RequestDTO dto) throws ApisResourceAccessException;
	
	public ResidentUpdateResponseDTO createPacket(PacketCreateRequestDto dto) throws ResidentServiceCheckedException;

}
