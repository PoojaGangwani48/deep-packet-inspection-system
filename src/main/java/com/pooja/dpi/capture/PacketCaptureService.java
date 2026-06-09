package com.pooja.dpi.capture;

import org.pcap4j.packet.*;
import org.pcap4j.core.*;

import java.util.List;

import com.pooja.dpi.entity.Packet;
import com.pooja.dpi.service.PacketService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class PacketCaptureService {

    @Autowired
    private PacketService packetService;

    private boolean isRunning = false;
    private PcapHandle handle;

    public void startCapture() {

        if (isRunning) {
            System.out.println(" Already Running...");
            return;
        }

        isRunning = true;

        new Thread(() -> {

            try {

                System.out.println(" Capture Thread Started...");

                List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

                if (interfaces == null || interfaces.isEmpty()) {
                    System.out.println(" No network interfaces found!");
                    return;
                }

                
                int index = 0;
                for (PcapNetworkInterface i : interfaces) {
                    System.out.println(index++ + " -> " + i.getName() + " | " + i.getDescription());
                }

                
                PcapNetworkInterface nif = interfaces.stream()
                	    .filter(i -> i.getDescription() != null &&
                	        !i.getDescription().toLowerCase().contains("virtual") &&
                	        !i.getDescription().toLowerCase().contains("loopback") &&
                	        (i.getDescription().toLowerCase().contains("wireless") ||
                	         i.getDescription().toLowerCase().contains("wi-fi") ||
                	         i.getDescription().toLowerCase().contains("qualcomm")))
                	    .findFirst()
                	    .orElseGet(() -> interfaces.stream()
                	        .filter(i -> i.getDescription() != null &&
                	            !i.getDescription().toLowerCase().contains("virtual"))
                	        .findFirst()
                	        .orElse(interfaces.get(0)));
                System.out.println(" Capturing on: " + nif.getDescription());

                handle = nif.openLive(
                        65536,
                        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                        50
                );

                handle.setFilter("ip", BpfProgram.BpfCompileMode.OPTIMIZE);

                while (isRunning) {

                    org.pcap4j.packet.Packet rawPacket = handle.getNextPacket();
                    if (rawPacket == null) continue;

                    IpPacket ipPacket = rawPacket.get(IpPacket.class);
                    if (ipPacket == null) continue;

                    Packet newPacket = new Packet();

                    newPacket.setSourceIp(ipPacket.getHeader().getSrcAddr().toString());
                    newPacket.setDestinationIp(ipPacket.getHeader().getDstAddr().toString());
                    newPacket.setTimestamp(LocalDateTime.now());
                    newPacket.setPacketSize(rawPacket.length());

                    String domain = null;

                    TcpPacket tcp = rawPacket.get(TcpPacket.class);
                    UdpPacket udp = rawPacket.get(UdpPacket.class);

                    if (tcp != null) {
                        newPacket.setPort(tcp.getHeader().getDstPort().valueAsInt());
                        newPacket.setProtocol("TCP");

                    } else if (udp != null) {
                        newPacket.setPort(udp.getHeader().getDstPort().valueAsInt());
                        newPacket.setProtocol("UDP");

                        
                        if (udp.getHeader().getDstPort().valueAsInt() == 53 ||
                            udp.getHeader().getSrcPort().valueAsInt() == 53) {

                            org.pcap4j.packet.Packet payload = udp.getPayload();

                            if (payload instanceof DnsPacket dns &&
                                dns.getHeader().getQuestions() != null &&
                                !dns.getHeader().getQuestions().isEmpty()) {

                                domain = dns.getHeader()
                                        .getQuestions()
                                        .get(0)
                                        .getQName()
                                        .getName();
                            }
                        }
                    }

                    if (domain != null) domain = domain.toLowerCase();
                    newPacket.setDomain(domain);

                    if (newPacket.getProtocol() == null) continue;

                    
                    System.out.println(" Packet: " + newPacket.getSourceIp() + " -> " + newPacket.getDestinationIp());

                    packetService.save(newPacket);
                }

                handle.close();

            } catch (Exception e) {
                System.out.println(" ERROR in Capture:");
                e.printStackTrace();
            }

        }).start();
    }

    public void stopCapture() {
        System.out.println(" Capture Stopped");
        isRunning = false;
    }
}