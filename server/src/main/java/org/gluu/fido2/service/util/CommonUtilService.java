package org.gluu.fido2.service.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class CommonUtilService {

    public ByteArrayOutputStream writeOutputStreamByteList(List<byte[]> list) throws IOException {
        if (list.isEmpty()) {
            throw new IOException("List is empty");
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] bytes : list) {
            baos.write(bytes);
        }
        return baos;
    }
}
