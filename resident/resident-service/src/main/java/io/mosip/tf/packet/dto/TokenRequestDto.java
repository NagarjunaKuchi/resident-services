package io.mosip.tf.packet.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Setter
@Getter
public class TokenRequestDto extends BaseRequestDTO {

	private ClientIdSecretKeyRequestDto request;
}
