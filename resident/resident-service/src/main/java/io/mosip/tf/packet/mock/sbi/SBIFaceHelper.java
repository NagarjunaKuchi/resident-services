package io.mosip.tf.packet.mock.sbi;

import io.mosip.tf.packet.util.SBIConstant;

public class SBIFaceHelper extends SBIDeviceHelper {

	private SBIFaceHelper(int port, String purpose, String keystoreFilePath, String biometricImageType) {
		super(purpose, SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE, SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE,
				keystoreFilePath);
	}

	// synchronized method to control simultaneous access
	synchronized public static SBIFaceHelper getInstance(int port, String purpose, String keystoreFilePath,
			String biometricImageType) {
		return new SBIFaceHelper(port, purpose, keystoreFilePath, biometricImageType);
	}


}