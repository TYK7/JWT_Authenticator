package com.example.jwtproject.repository;

import com.example.jwtproject.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    // For login with either username or email
    default Optional<User> findByUsernameOrEmail(String usernameOrEmail) {
        Optional<User> user = findByUsername(usernameOrEmail);
        if (user.isPresent()) {
            return user;
        }
        return findByEmail(usernameOrEmail);
    }
}
