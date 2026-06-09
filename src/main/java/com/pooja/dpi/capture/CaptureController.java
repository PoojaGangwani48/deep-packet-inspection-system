package com.pooja.dpi.capture;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/api/capture")
public class CaptureController {

    @Autowired
    private PacketCaptureService packetCaptureService;

    
    @PostMapping("/start")
    public String startCapture(
            RedirectAttributes redirectAttributes) {

        packetCaptureService.startCapture();

        redirectAttributes.addFlashAttribute(
                "message",
                "Packet Capture Started Successfully"
        );

        return "redirect:/dashboard";
    }


    @PostMapping("/stop")
    public String stopCapture(
            RedirectAttributes redirectAttributes) {

        packetCaptureService.stopCapture();

        redirectAttributes.addFlashAttribute(
                "message",
                "Packet Capture Stopped Successfully"
        );

        return "redirect:/dashboard";
    }
}