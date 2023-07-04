package io.mosip.tf.packet.dto;

import org.json.simple.JSONObject;

import lombok.Data;

@Data
public class ResidentUpdateResponseDTO {
	private String registrationId;
	private String message;
	private JSONObject data;

}
