package com.dpi.test;

import com.dpi.engine.DPIEngine;
import com.dpi.engine.MultiThreadedDPIEngine;
import com.dpi.extractor.SNIExtractor;
import com.dpi.types.IpUtil;
import org.junit.Test;
import java.io.File;
import java.util.Optional;

import static org.junit.Assert.*;

public class DpiEngineTest {

    @Test
    public void testIpUtilToLongAndToString() {
        long ipLong = IpUtil.toLong("192.168.1.1");
        assertEquals(0xC0A80101L, ipLong);
        assertEquals("192.168.1.1", IpUtil.toString(ipLong));
    }

    @Test
    public void testSNIExtractorWithSampleClientHello() {
        // Construct a synthetic TLS ClientHello with SNI "www.example.com"
        byte[] sniBytes = "www.example.com".getBytes();
        byte[] sniEntry = new byte[3 + sniBytes.length];
        sniEntry[0] = 0; // Hostname type
        sniEntry[1] = (byte) ((sniBytes.length >> 8) & 0xFF);
        sniEntry[2] = (byte) (sniBytes.length & 0xFF);
        System.arraycopy(sniBytes, 0, sniEntry, 3, sniBytes.length);

        byte[] sniList = new byte[2 + sniEntry.length];
        sniList[0] = (byte) ((sniEntry.length >> 8) & 0xFF);
        sniList[1] = (byte) (sniEntry.length & 0xFF);
        System.arraycopy(sniEntry, 0, sniList, 2, sniEntry.length);

        byte[] extension = new byte[4 + sniList.length];
        extension[0] = 0; // SNI type 0x0000
        extension[1] = 0;
        extension[2] = (byte) ((sniList.length >> 8) & 0xFF);
        extension[3] = (byte) (sniList.length & 0xFF);
        System.arraycopy(sniList, 0, extension, 4, sniList.length);

        byte[] extensionsHeader = new byte[2 + extension.length];
        extensionsHeader[0] = (byte) ((extension.length >> 8) & 0xFF);
        extensionsHeader[1] = (byte) (extension.length & 0xFF);
        System.arraycopy(extension, 0, extensionsHeader, 2, extension.length);

        byte[] clientHelloBody = new byte[2 + 32 + 1 + 2 + 1 + extensionsHeader.length];
        int pos = 0;
        clientHelloBody[pos++] = 0x03; clientHelloBody[pos++] = 0x03; // TLS 1.2
        pos += 32; // Random 32 bytes
        clientHelloBody[pos++] = 0; // Session ID length 0
        clientHelloBody[pos++] = 0; clientHelloBody[pos++] = 2; // Cipher suite len
        clientHelloBody[pos++] = 1; // Compression len
        System.arraycopy(extensionsHeader, 0, clientHelloBody, pos, extensionsHeader.length);

        byte[] handshake = new byte[4 + clientHelloBody.length];
        handshake[0] = 0x01; // Client Hello
        handshake[1] = 0;
        handshake[2] = (byte) ((clientHelloBody.length >> 8) & 0xFF);
        handshake[3] = (byte) (clientHelloBody.length & 0xFF);
        System.arraycopy(clientHelloBody, 0, handshake, 4, clientHelloBody.length);

        byte[] tlsRecord = new byte[5 + handshake.length];
        tlsRecord[0] = 0x16; // Handshake
        tlsRecord[1] = 0x03; tlsRecord[2] = 0x01; // TLS 1.0
        tlsRecord[3] = (byte) ((handshake.length >> 8) & 0xFF);
        tlsRecord[4] = (byte) (handshake.length & 0xFF);
        System.arraycopy(handshake, 0, tlsRecord, 5, handshake.length);

        Optional<String> extractedSni = SNIExtractor.extract(tlsRecord, 0, tlsRecord.length);
        assertTrue(extractedSni.isPresent());
        assertEquals("www.example.com", extractedSni.get());
    }

    @Test
    public void testSingleAndMultiEngineParityOnTestPcap() {
        File inputFile = new File("test_dpi.pcap");
        assertTrue("test_dpi.pcap must exist for testing", inputFile.exists());

        File singleOut = new File("test_single_out.pcap");
        File multiOut = new File("test_multi_out.pcap");

        DPIEngine singleEngine = new DPIEngine("test_dpi.pcap", singleOut.getPath());
        singleEngine.addBlockRule("app", "YouTube");
        singleEngine.addBlockRule("ip", "192.168.1.50");
        assertTrue(singleEngine.process());

        MultiThreadedDPIEngine multiEngine = new MultiThreadedDPIEngine("test_dpi.pcap", multiOut.getPath(), 4);
        multiEngine.addBlockRule("app", "YouTube");
        multiEngine.addBlockRule("ip", "192.168.1.50");
        assertTrue(multiEngine.process());

        assertTrue(singleOut.exists());
        assertTrue(multiOut.exists());
        assertEquals(singleOut.length(), multiOut.length());
        assertEquals(6489L, singleOut.length());
    }
}
