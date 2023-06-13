package io.mosip.tf.packet.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.tf.packet.dto.RequestWrapper;
import io.mosip.tf.packet.dto.PacketCreateRequestDto;
import io.mosip.tf.packet.dto.ResidentUpdateResponseDTO;
import io.mosip.tf.packet.exception.ResidentServiceCheckedException;
import io.mosip.tf.packet.service.PacketCreatorService;
import io.mosip.tf.packet.util.AuditUtil;
import io.mosip.tf.packet.util.EventEnum;
import io.mosip.tf.packet.validator.RequestValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@Tag(name = "packet-create-controller", description = "Packet-create-controller")
public class PacketController {

	@Autowired
	private PacketCreatorService packetCreatorService;

	@Autowired
	private RequestValidator validator;
	
	@Autowired
	private AuditUtil audit;

	@ResponseFilter
	@PostMapping(value = "/req/update-uin")
	@Operation(summary = "updateUin", description = "updateUin", tags = { "packet-create-controller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "201", description = "Created" ,content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "401", description = "Unauthorized" ,content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden" ,content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found" ,content = @Content(schema = @Schema(hidden = true)))})
	public ResponseWrapper<ResidentUpdateResponseDTO> updateUin(
			@Valid @RequestBody RequestWrapper<PacketCreateRequestDto> requestDTO)
			throws ResidentServiceCheckedException {
		audit.setAuditRequestDto(EventEnum.getEventEnumWithValue(EventEnum.VALIDATE_REQUEST,"Create Packet API"));
		validator.validateUpdateRequest(requestDTO);
		ResponseWrapper<ResidentUpdateResponseDTO> response = new ResponseWrapper<>();
		response.setResponse(packetCreatorService.createPacket(requestDTO.getRequest()));
		return response;
	}
	
	@ResponseFilter
	@PostMapping(value = "/req/sign/bio")
	public ResponseWrapper<String> signBiometrics(
			@Valid @RequestBody RequestWrapper<String> requestDTO){
		ResponseWrapper<String> response = new ResponseWrapper<>();
		response.setResponse(packetCreatorService.signBiometrics(requestDTO.getRequest()));
		return response;
	}
}