package io.mosip.tf.packet.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PacketCreateRequestDto {
	
	private String identityJson;
	
	private List<ResidentDocuments> documents;	
	
	private String individualBiometrics;

}
