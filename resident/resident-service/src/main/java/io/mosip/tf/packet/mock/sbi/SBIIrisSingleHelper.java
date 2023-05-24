package io.mosip.tf.packet.mock.sbi;

import io.mosip.tf.packet.util.SBIConstant;

public class SBIIrisSingleHelper extends SBIDeviceHelper {

	private SBIIrisSingleHelper(int port, String purpose, String keystoreFilePath, String biometricImageType) {
		super(purpose, SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS, SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE,
				keystoreFilePath);
	}

	// synchronized method to control simultaneous access
	synchronized public static SBIIrisSingleHelper getInstance(int port, String purpose, String keystoreFilePath,
			String biometricImageType) {
		return new SBIIrisSingleHelper(port, purpose, keystoreFilePath, biometricImageType);
	}

}
