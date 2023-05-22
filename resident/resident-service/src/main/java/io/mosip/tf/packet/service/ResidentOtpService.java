package io.mosip.tf.packet.service;

import io.mosip.tf.packet.dto.OtpRequestDTO;
import io.mosip.tf.packet.dto.OtpResponseDTO;


public interface ResidentOtpService {

	/**
	 * Generate otp.
	 *
	 * @param otpRequestDTO OtpRequestDTO request.
	 * @return OtpResponseDTO object return.
	 * @throws IdAuthenticationBusinessException exception
	 */

	public OtpResponseDTO generateOtp(OtpRequestDTO otpRequestDTO);
}
