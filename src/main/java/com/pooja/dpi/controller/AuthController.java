package com.pooja.dpi.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import com.pooja.dpi.entity.User;
import com.pooja.dpi.service.UserService;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    
    @GetMapping("/")
    public String home() {
        return "auth";
    }

    
    @PostMapping("/register")
    public String register(User user, Model model) {
        try {
            userService.register(user);
            model.addAttribute("msg", "Check console for verification link!");
        } catch (Exception e) {
            model.addAttribute("msg", e.getMessage());
        }
        return "auth";
    }

    
    @PostMapping("/login")
    public String login(@RequestParam String email,
                        @RequestParam String password,
                        Model model) {
        try {
            userService.login(email, password);
            return "redirect:/dashboard"; 
        } catch (Exception e) {
            model.addAttribute("msg", e.getMessage());
            return "auth";
        }
    }

    
    @GetMapping("/verify")
    public String verify(@RequestParam String token, Model model) {

        boolean status = userService.verifyUser(token);

        if (status) {
            model.addAttribute("msg", " Email verified! Now login.");
        } else {
            model.addAttribute("msg", " Invalid or expired link!");
        }

        return "auth";
    }
}