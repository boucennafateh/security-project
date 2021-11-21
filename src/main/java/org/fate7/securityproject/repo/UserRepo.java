package org.fate7.securityproject.repo;

import org.fate7.securityproject.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<AppUser, Long> {
    AppUser findByUserName(String userName);
}
