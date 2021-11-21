package org.fate7.securityproject.service;

import org.fate7.securityproject.model.AppUser;
import org.fate7.securityproject.model.Role;

import java.util.List;

public interface UserService {
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String userName, String roleName);
    AppUser getUser(String userName);
    List<AppUser> getUsers();

}
