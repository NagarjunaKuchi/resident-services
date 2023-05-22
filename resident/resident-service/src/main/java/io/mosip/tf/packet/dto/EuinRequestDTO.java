package io.mosip.tf.packet.dto;


import java.io.Serializable;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import io.mosip.tf.packet.constant.IdType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EuinRequestDTO implements Serializable {
	private static final long serialVersionUID = -4492209826585681216L;

	private String transactionID;

	private String individualId;

	private String individualIdType;

	private String cardType;

	private String otp;
}
