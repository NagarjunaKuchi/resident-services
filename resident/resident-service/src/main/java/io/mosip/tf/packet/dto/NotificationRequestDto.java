package io.mosip.tf.packet.dto;

import java.io.Serializable;
import java.util.Map;

import io.mosip.tf.packet.constant.NotificationTemplateCode;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class NotificationRequestDto implements Serializable {
	static final long serialVersionUID = 3726544930055329455L;
	private String id;
	private NotificationTemplateCode templateTypeCode;
	private Map<String, Object> additionalAttributes;
}
