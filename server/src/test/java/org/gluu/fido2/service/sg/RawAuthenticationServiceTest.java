package org.gluu.fido2.service.sg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.gluu.oxauth.model.fido.u2f.message.RawAuthenticateResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RawAuthenticationServiceTest {

    @InjectMocks
    private RawAuthenticationService rawAuthenticationService;

    @Test
    void parseRawAuthenticateResponse_validValues_valid() {
        String rawDataBase64 = "AQAAAAEwRgIhAN4auE9-U2YDhi8ByxIIv3G2hvDeFjEGU_x5SvfcIQyUAiEA4I_xMinmYAmH5qk5KMaYATFAryIpoVwARGvEFQTWE2Q";

        RawAuthenticateResponse response = rawAuthenticationService.parseRawAuthenticateResponse(rawDataBase64);
        assertNotNull(response);
        assertEquals(response.getCounter(), 1L);
    }
}
