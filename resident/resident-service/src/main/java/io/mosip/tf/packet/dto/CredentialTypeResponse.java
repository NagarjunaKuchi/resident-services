package io.mosip.tf.packet.dto;

import java.util.List;

import lombok.Data;

@Data
public class CredentialTypeResponse {
	
	List<Type> credentialTypes;

}
