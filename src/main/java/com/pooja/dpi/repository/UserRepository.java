package com.pooja.dpi.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.pooja.dpi.entity.User;

public interface UserRepository extends JpaRepository<User, Integer> {

    
    User findByEmail(String email);

    
    User findByVerificationToken(String token);
}