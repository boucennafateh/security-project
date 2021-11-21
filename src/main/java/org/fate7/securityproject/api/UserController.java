package org.fate7.securityproject.api;


import lombok.RequiredArgsConstructor;
import org.fate7.securityproject.model.AppUser;
import org.fate7.securityproject.model.Role;
import org.fate7.securityproject.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController @RequiredArgsConstructor @RequestMapping("/api")
public class UserController {

    private final UserService userService;

    @GetMapping("/users")
    ResponseEntity<List<AppUser>> getUsers(){
        return ResponseEntity.ok()
                .body(userService.getUsers());
    }

    @PostMapping("/users")
    ResponseEntity<AppUser> saveUsers(@RequestBody AppUser user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/users").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/roles")
    ResponseEntity<Role> saveRole(@RequestBody Role role){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/roles").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/users/{user}/role/{role}")
    ResponseEntity<?> addRole(@PathVariable String user, @PathVariable String role){
        userService.addRoleToUser(user, role);
        return ResponseEntity.ok().build();
    }
}
