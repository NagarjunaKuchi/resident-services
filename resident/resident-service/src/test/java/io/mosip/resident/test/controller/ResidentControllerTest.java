/**
 * 
 */
package io.mosip.resident.test.controller;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import io.mosip.kernel.cbeffutil.impl.CbeffImpl;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;
import io.mosip.resident.test.ResidentTestBootApplication;
import io.mosip.tf.packet.constant.IdType;
import io.mosip.tf.packet.controller.PacketController;
import io.mosip.tf.packet.dto.AuthHistoryRequestDTO;
import io.mosip.tf.packet.dto.AuthLockOrUnLockRequestDto;
import io.mosip.tf.packet.dto.EuinRequestDTO;
import io.mosip.tf.packet.dto.RegStatusCheckResponseDTO;
import io.mosip.tf.packet.dto.RequestWrapper;
import io.mosip.tf.packet.dto.ResidentDocuments;
import io.mosip.tf.packet.dto.PacketCreateRequestDto;
import io.mosip.tf.packet.dto.ResidentUpdateResponseDTO;
import io.mosip.tf.packet.service.PacketCreatorService;
import io.mosip.tf.packet.util.AuditUtil;
import io.mosip.tf.packet.validator.RequestValidator;

import org.springframework.web.client.RestTemplate;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = ResidentTestBootApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application.properties")
public class ResidentControllerTest {

	@MockBean
	private PacketCreatorService residentService;

	@Mock
	CbeffImpl cbeff;

	@MockBean
	private RequestValidator validator;
	
	@Mock
	private AuditUtil audit;

	@MockBean
	private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> encryptor;

	@MockBean
	@Qualifier("selfTokenRestTemplate")
	private RestTemplate residentRestTemplate;

	@InjectMocks
    PacketController residentController;

	RequestWrapper<AuthLockOrUnLockRequestDto> authLockRequest;
	RequestWrapper<EuinRequestDTO> euinRequest;
	RequestWrapper<AuthHistoryRequestDTO> authHistoryRequest;

	/** The array to json. */
	private String authLockRequestToJson;
	private Gson gson;

	/** The mock mvc. */
	@Autowired
	private MockMvc mockMvc;
	


	@Before
	public void setUp() {
		MockitoAnnotations.initMocks(this);
		authLockRequest = new RequestWrapper<AuthLockOrUnLockRequestDto>();

		AuthLockOrUnLockRequestDto authLockRequestDto = new AuthLockOrUnLockRequestDto();
		authLockRequestDto.setIndividualId("5734728510");
		authLockRequestDto.setOtp("111111");
		authLockRequestDto.setTransactionID("1234567898");
		List<String> authTypes = new ArrayList<>();
		authTypes.add("bio-FIR");
		authLockRequestDto.setAuthType(authTypes);
		authLockRequest.setRequest(authLockRequestDto);
		euinRequest = new RequestWrapper<EuinRequestDTO>();
		euinRequest.setRequest(new EuinRequestDTO("5734728510", "1234567890", IdType.UIN.name(), "UIN", "111111"));

		gson = new GsonBuilder().serializeNulls().create();
		authLockRequestToJson = gson.toJson(authLockRequest);
		Mockito.doNothing().when(audit).setAuditRequestDto(Mockito.any());

	}

	@Test
	@WithUserDetails("resident")
	public void testGetRidStatusSuccess() throws Exception {
		RegStatusCheckResponseDTO dto = new RegStatusCheckResponseDTO();
		dto.setRidStatus("PROCESSED");
		Mockito.doReturn(dto).when(residentService).getRidStatus(Mockito.any());
		this.mockMvc
				.perform(post("/rid/check-status").contentType(MediaType.APPLICATION_JSON)
						.content(authLockRequestToJson))
				.andExpect(status().isOk()).andExpect(jsonPath("$.response.ridStatus", is("PROCESSED")));
	}


	@Test
	@WithUserDetails("resident")
	public void testRequestEuinBadRequest() throws Exception {

		MvcResult result = this.mockMvc.perform(post("/req/euin").contentType(MediaType.APPLICATION_JSON).content(""))
				.andExpect(status().isOk()).andReturn();
		assertTrue(result.getResponse().getContentAsString().contains("RES-SER-418"));
	}


	@Test
	@WithUserDetails("reg-admin")
	public void testRequestAuthHistoryBadRequest() throws Exception {

		MvcResult result = this.mockMvc
				.perform(post("/req/auth-history").contentType(MediaType.APPLICATION_JSON).content(""))
				.andExpect(status().isOk()).andReturn();
		assertTrue(result.getResponse().getContentAsString().contains("RES-SER-418"));
	}

	@Test
	@WithUserDetails("reg-admin")
	public void testRequestUINUpdate() throws Exception {
		PacketCreateRequestDto dto = new PacketCreateRequestDto();
		ResidentDocuments document = new ResidentDocuments();
		document.setName("POA");
		document.setValue("abecfsgdsdg");
		List<ResidentDocuments> list = new ArrayList<>();
		list.add(document);
		dto.setDocuments(list);
		dto.setIdentityJson("sdgfdgsfhfh");
		RequestWrapper<PacketCreateRequestDto> reqWrapper = new RequestWrapper<>();
		reqWrapper.setRequest(dto);
		reqWrapper.setId("mosip.resident.uin");
		reqWrapper.setVersion("v1");
		Mockito.when(residentService.createPacket(Mockito.any())).thenReturn(new ResidentUpdateResponseDTO());
		String requestAsString = gson.toJson(reqWrapper);
		this.mockMvc.perform(post("/req/update-uin").contentType(MediaType.APPLICATION_JSON).content(requestAsString))
				.andExpect(status().isOk());

	}
}
