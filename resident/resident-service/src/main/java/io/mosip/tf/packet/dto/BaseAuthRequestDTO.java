package io.mosip.tf.packet.dto;

import lombok.Data;

@Data
public class BaseAuthRequestDTO {

	private boolean consentObtained = true;
	
	private String id;
	
}
