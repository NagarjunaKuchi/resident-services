package io.mosip.tf.packet.dto;

import java.util.List;

import lombok.Data;

@Data
public class RegistrationStatusRequestDTO extends BaseRequestDTO{
		
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	/** The response. */
	private List<RegistrationStatusSubRequestDto> request;
	
}
