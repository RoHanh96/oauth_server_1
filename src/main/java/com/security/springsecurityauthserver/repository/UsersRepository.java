package com.security.springsecurityauthserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.springsecurityauthserver.model.Users;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<Users, Integer> {
    Optional<Users> findByName(String username);
}
