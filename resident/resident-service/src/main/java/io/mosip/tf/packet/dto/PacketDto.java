package io.mosip.tf.packet.dto;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import io.mosip.commons.packet.dto.Document;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class PacketDto implements Serializable {

    private String id;
    private String additionalInfoReqId;
    private String refId;
    private boolean offlineMode;
    private String process;
    private String source;
    private String schemaVersion;
    private String schemaJson;
    private Map<String, String> fields;
    private Map<String, String> metaInfo;
    private Map<String, Document> documents;
    private List<Map<String, String>> audits;
    private Map<String, ExtendedBiometricRecord> biometrics;

}
