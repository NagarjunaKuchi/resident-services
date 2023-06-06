package io.mosip.tf.packet.dto;

import lombok.Data;

@Data
public class DeviceMetaInfo {
	private String deviceCode;
	private String deviceServiceVersion;
	private DigitalId digitalId;
}
