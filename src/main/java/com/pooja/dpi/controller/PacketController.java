package com.pooja.dpi.controller;


import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.pooja.dpi.entity.Packet;
import com.pooja.dpi.service.PacketService;

@RestController
@RequestMapping("/api/packets") 
public class PacketController {

    @Autowired
    private PacketService packetService;

    
    @PostMapping
    public Packet savePacket(@RequestBody Packet packet) {
        return packetService.save(packet);
    }

   
    @GetMapping
    public List<Packet> getAllPackets() {
        return packetService.getAllPackets();
    }

    
    @GetMapping("/suspicious")
    public List<Packet> getSuspiciousPackets() {
        return packetService.getSuspiciousPackets();
    }

    
    @GetMapping("/protocol/{protocol}")
    public List<Packet> getByProtocol(@PathVariable String protocol) {
        return packetService.getByProtocol(protocol);
    }

   
    @GetMapping("/source/{ip}")
    public List<Packet> getBySourceIp(@PathVariable String ip) {
        return packetService.getBySourceIp(ip);
    }

   
    @GetMapping("/port/{port}")
    public List<Packet> getByPort(@PathVariable Integer port) {
        return packetService.getByPort(port);
    }

  
    @GetMapping("/top-attackers")
    public List<Object[]> getTopAttackers() {
        return packetService.getTopAttackers();
    }

    
    @GetMapping("/dangerous-domains")
    public List<Object[]> getDangerousDomains() {
        return packetService.getDangerousDomains();
    }

 
    @GetMapping("/stats")
    public Map<String, Long> getStats() {
        return packetService.getPacketStats();
    }

    
    @GetMapping("/live")
    public List<Packet> getLivePackets() {
        return packetService.getLivePackets();
    }
    
    @PostMapping("/block")
    public String block(@RequestParam String value) {
        packetService.blockValue(value);
        return value + " blocked successfully";
    }

    @PostMapping("/unblock")
    public String unblock(@RequestParam String value) {
        packetService.unblockValue(value);

        return value + " unblocked successfully";
    }
}