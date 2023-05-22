package io.mosip.tf.packet.dto;

import lombok.Data;
import java.io.Serializable;

@Data
public class VidResponseDto implements Serializable {

    private String vid;
    private String message;
}
