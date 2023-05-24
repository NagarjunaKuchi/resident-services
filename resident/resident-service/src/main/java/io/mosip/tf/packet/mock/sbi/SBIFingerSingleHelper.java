package io.mosip.tf.packet.mock.sbi;


import io.mosip.tf.packet.util.SBIConstant;

public class SBIFingerSingleHelper extends SBIDeviceHelper {

	private SBIFingerSingleHelper(int port, String purpose, String keystoreFilePath, String biometricImageType)
	{ 
		super (purpose, SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER, SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE, keystoreFilePath);
	} 
  
	//synchronized method to control simultaneous access 
	synchronized public static SBIFingerSingleHelper getInstance(int port, String purpose, String keystoreFilePath, String biometricImageType)
	{ 
		return new SBIFingerSingleHelper(port, purpose, keystoreFilePath, biometricImageType);
	}

}
