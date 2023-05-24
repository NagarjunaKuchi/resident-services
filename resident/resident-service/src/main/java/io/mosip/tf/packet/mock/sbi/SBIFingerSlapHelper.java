package io.mosip.tf.packet.mock.sbi;

import io.mosip.tf.packet.util.SBIConstant;

public class SBIFingerSlapHelper extends SBIDeviceHelper {	

	private SBIFingerSlapHelper(int port, String purpose, String keystorePath, String biometricImageType)
	{ 
		super (purpose, SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER, SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP, keystorePath);
	} 
  
	//synchronized method to control simultaneous access 
	synchronized public static SBIFingerSlapHelper getInstance(int port, String purpose, String keystorePath, String biometricImageType)
	{ 
		return new SBIFingerSlapHelper(port, purpose, keystorePath, biometricImageType);
	}
}
