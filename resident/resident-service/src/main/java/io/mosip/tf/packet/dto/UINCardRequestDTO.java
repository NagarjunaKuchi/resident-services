package io.mosip.tf.packet.dto;

import java.io.Serializable;

import io.mosip.tf.packet.constant.IdType;
import lombok.Data;

@Data
public class UINCardRequestDTO  implements Serializable{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The idtype. */
	private IdType idtype;

	/** The id value. */
	private String idValue;

	/** The card type. */
	private String cardType;
}
