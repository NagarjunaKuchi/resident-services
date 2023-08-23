package io.mosip.tf.packet.dto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BIRInfo;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.entities.VersionType;
import lombok.Data;

@Data
public class ExtendedBiometricRecord {

	protected VersionType version;
	protected VersionType cbeffversion;
	protected BIRInfo birInfo;
	/**
	 * This can be of any modality, each subtype is an element in this list.
	 * it has type and subtype info in it
	 */
	protected List<ExtendedBIR> segments;
	protected HashMap<String, String> others;
	
	public ExtendedBiometricRecord() {
		this.segments = new ArrayList<>();
		this.others = new HashMap<>();
	}
	
	public ExtendedBiometricRecord(VersionType version, VersionType cbeffversion, BIRInfo birInfo) {
		this.version = version;
		this.cbeffversion = cbeffversion;
		this.birInfo = birInfo;
		this.segments = new ArrayList<ExtendedBIR>();
		this.others = new HashMap<>();
	}
	
}
