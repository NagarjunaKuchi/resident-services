package io.mosip.tf.packet.dto;

import java.util.HashMap;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.MapEntryDeserializer;

import io.mosip.kernel.biometrics.entities.AdapterOthersListToHashMap;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIRInfo;
import io.mosip.kernel.biometrics.entities.SBInfo;
import io.mosip.kernel.biometrics.entities.VersionType;
import io.mosip.kernel.core.cbeffutil.common.Base64Adapter;
import lombok.Data;
import lombok.NoArgsConstructor;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BIRType", propOrder = { "version", "cbeffversion", "birInfo", "bdbInfo",  "bdb",
		"sb" , "sbInfo","others"})
@XmlRootElement(name = "BIR")
@Data
@NoArgsConstructor
public class ExtendedBIR {

	@XmlElement(name = "Version")
	private VersionType version;
	@XmlElement(name = "CBEFFVersion")
	private VersionType cbeffversion;
	@XmlElement(name = "BIRInfo", required = true)
	private BIRInfo birInfo;
	@XmlElement(name = "BDBInfo")
	private BDBInfo bdbInfo;
	@XmlElement(name = "BDB")
	@XmlJavaTypeAdapter(Base64Adapter.class)
	private byte[] bdb;
	@XmlElement(name = "SB")
	@XmlJavaTypeAdapter(Base64Adapter.class)
	private byte[] sb;
	@XmlElement(name = "SBInfo")
	private SBInfo sbInfo;
	@XmlJavaTypeAdapter(AdapterOthersListToHashMap.class)
	@JsonDeserialize(using = MapEntryDeserializer.class)
	private HashMap<String, String> others;
	
}
