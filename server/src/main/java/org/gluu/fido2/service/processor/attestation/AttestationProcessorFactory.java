/*
 * Copyright (c) 2018 Mastercard
 * Copyright (c) 2020 Gluu
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.gluu.fido2.service.processor.attestation;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Any;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.inject.Named;

import org.gluu.fido2.ctap.AttestationFormat;
import org.gluu.fido2.exception.Fido2RuntimeException;
import org.gluu.fido2.service.processors.AttestationFormatProcessor;

/**
 * The attestationObject contains base64url encoded buffer of CBOR encoded
 * attestation object. When parsed, the "fmt" value contains the attestation
 * format. 
 * AttestationProcessorFactory - Factory Class that returns Processor based on the fmt
 * 
 */
@ApplicationScoped
public class AttestationProcessorFactory {

    private Map<AttestationFormat, AttestationFormatProcessor> processorsMap;

    @Inject
    private void initCommandProcessors(@Any Instance<AttestationFormatProcessor> attestationFormatProcessors) {
        this.processorsMap = new EnumMap<>(AttestationFormat.class);
        for (AttestationFormatProcessor app : attestationFormatProcessors) {
            processorsMap.put(app.getAttestationFormat(), app);
        }
    }

    public AttestationFormatProcessor getCommandProcessor(String fmtFormat) {
        try {
            AttestationFormat attestationFormat = AttestationFormat.valueOf(fmtFormat.replace('-', '_'));
            return processorsMap.get(attestationFormat);
        } catch (Exception e) {
            throw new Fido2RuntimeException("Unsupported format " + e.getMessage());
        }
    }

    @Produces
    @ApplicationScoped
    @Named("supportedAttestationFormats")
    public List<String> getSupportedAttestationFormats() {
        return Arrays.stream(AttestationFormat.values()).map(f -> f.getFmt()).collect(Collectors.toList());
    }

}