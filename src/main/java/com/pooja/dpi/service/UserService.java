package com.pooja.dpi.service;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.pooja.dpi.entity.User;
import com.pooja.dpi.repository.UserRepository;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EmailService emailService;

    
    public void register(User user) {

        
        if (userRepository.findByEmail(user.getEmail()) != null) {
            throw new RuntimeException("Email already registered!");
        }

       
        String token = UUID.randomUUID().toString();

        user.setVerificationToken(token);
        user.setVerified(false);

        userRepository.save(user);

        emailService.sendVerificationEmail(user.getEmail(), token);
    }

    
    public User login(String email, String password) {

        User user = userRepository.findByEmail(email);

        if (user == null) {
            throw new RuntimeException("User not found!");
        }

        if (!user.getPassword().equals(password)) {
            throw new RuntimeException("Wrong password!");
        }

        if (!user.isVerified()) {
            throw new RuntimeException("Please verify your email first!");
        }

        return user;
    }

    
    public boolean verifyUser(String token) {

        User user = userRepository.findByVerificationToken(token);

        if (user == null) {
            return false;
        }

        user.setVerified(true);
        user.setVerificationToken(null);
        userRepository.save(user);

        return true;
    }
}