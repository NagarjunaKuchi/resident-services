package io.mosip.resident.constant;

public enum NotificationTemplateCode {
	RS_AUTH_HIST_SUCCESS("RS_AUTH_HIST_SUCCESS"),
	RS_AUTH_HIST_FAILURE("RS_AUTH_HIST_FAILURE"),
	RS_DOW_UIN_SUCCESS("RS_DOW_UIN_SUCCESS"),
	RS_DOW_UIN_FAILURE("RS_DOW_UIN_FAILURE"),
	RS_LOCK_AUTH_SUCCESS("RS_LOCK_AUTH_SUCCESS"),
	RS_LOCK_AUTH_FAILURE("RS_LOCK_AUTH_FAILURE"),
	RS_UIN_RPR_SUCCESS("RS_UIN_RPR_SUCCESS"),
	RS_UIN_RPR_FAILURE("RS_UIN_RPR_FAILURE"),
	RS_UIN_UPDATE_SUCCESS("RS_UIN_UPDATE_SUCCESS"),
	RS_UIN_UPDATE_FAILURE("RS_UIN_UPDATE_FAILURE"),
	RS_UNLOCK_AUTH_SUCCESS("RS_UNLOCK_AUTH_SUCCESS"),
	RS_UNLOCK_AUTH_FAILURE("RS_UNLOCK_AUTH_FAILURE"),
	RS_VIN_GEN_SUCCESS("RS_VIN_GEN_SUCCESS"),
	RS_VIN_GEN_FAILURE("RS_VIN_GEN_FAILURE"),
	RS_VIN_REV_SUCCESS("RS_VIN_REV_SUCCESS"),
	RS_VIN_REV_FAILURE("RS_VIN_REV_FAILURE"), RS_CRE_REQ_SUCCESS("RS_CRE_REQ_SUCCESS"),
	RS_CRE_REQ_FAILURE("RS_CRE_REQ_FAILURE"), RS_CRE_STATUS("RS_CRE_STATUS"),
	RS_CRE_CANCEL_SUCCESS("RS_CRE_CANCEL_SUCCESS");
	
	private final String templateCode;

	NotificationTemplateCode(String templateCode) {
		this.templateCode = templateCode;
	}

	@Override
	public String toString() {
		return templateCode;
	}
	
	
	
}
