package io.mosip.tf.packet.mock.sbi;


import io.mosip.tf.packet.util.SBIConstant;

public class SBIIrisDoubleHelper extends SBIDeviceHelper {
	  
	private SBIIrisDoubleHelper(int port, String purpose, String keystoreFilePath, String biometricImageType)
	{ 
		super (purpose, SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS, SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE, keystoreFilePath);
	} 
  
	//synchronized method to control simultaneous access 
	synchronized public static SBIIrisDoubleHelper getInstance(int port, String purpose, String keystoreFilePath, String biometricImageType)
	{ 
		return new SBIIrisDoubleHelper(port, purpose, keystoreFilePath, biometricImageType);
	}

}
