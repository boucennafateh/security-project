package org.fate7.securityproject.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fate7.securityproject.model.AppUser;
import org.fate7.securityproject.model.Role;
import org.fate7.securityproject.repo.RoleRepo;
import org.fate7.securityproject.repo.UserRepo;
import org.fate7.securityproject.service.UserService;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Collection;
import java.util.List;

@Service @RequiredArgsConstructor @Transactional @Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;

    @Override
    public AppUser saveUser(AppUser user) {
        log.info("Saving user");
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving role");
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        log.info("adding role to a user");
        AppUser user = userRepo.findByUserName(userName);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public AppUser getUser(String userName) {
        log.info("Getting user");
        return userRepo.findByUserName(userName);
    }

    @Override
    public List<AppUser> getUsers() {
        log.info("Getting all users");
        log.info("Getting all users");
        return userRepo.findAll();
    }
}
