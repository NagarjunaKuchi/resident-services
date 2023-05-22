package io.mosip.tf.packet.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ResidentVidResponseDto extends BaseResponseDTO {

    private String vid;
    private String status;
    private String message;
}
