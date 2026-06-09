package com.pooja.dpi.controller;

import java.util.Map;
import org.springframework.web.bind.annotation.RequestParam;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.pooja.dpi.service.PacketService;

@Controller
public class DashboardController {

    @Autowired
    private PacketService packetService;

    @GetMapping("/dashboard")
    public String dashboard(

            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String protocol,
            @RequestParam(required = false) String status,

            Model model) {

        Map<String, Long> stats =
                packetService.getPacketStats();

        model.addAttribute(
                "monitorPackets",
                stats.get("Monitor")
        );

        model.addAttribute(
                "suspiciousList",
                packetService.getSuspiciousPackets()
        );

        model.addAttribute(
                "totalPackets",
                stats.get("Total")
        );

        model.addAttribute(
                "normalPackets",
                stats.get("Safe")
        );

        model.addAttribute(
                "suspiciousPackets",
                stats.get("Suspicious")
        );




        if ((keyword != null && !keyword.isBlank())

                ||

            (protocol != null && !protocol.isBlank())

                ||

            (status != null && !status.isBlank())) {

            model.addAttribute(
                    "packets",

                    packetService.filterPackets(
                            keyword,
                            protocol,
                            status
                    )
            );

        } else {

            model.addAttribute(
                    "packets",
                    packetService.getLivePackets()
            );
        }



        model.addAttribute(
                "attackers",
                packetService.getTopAttackers()
        );

        model.addAttribute(
                "domains",
                packetService.getDangerousDomains()
        );

        model.addAttribute(
                "blockedDomains",
                packetService.getBlockedDomains()
        );

        model.addAttribute(
                "blockedIps",
                packetService.getBlockedIps()
        );

        return "dashboard";
    }

}