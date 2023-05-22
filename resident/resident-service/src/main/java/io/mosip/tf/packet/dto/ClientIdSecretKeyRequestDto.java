package io.mosip.tf.packet.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Setter
@Getter
public class ClientIdSecretKeyRequestDto {
	public String clientId;
	public String secretKey;
	public String appId;
}
