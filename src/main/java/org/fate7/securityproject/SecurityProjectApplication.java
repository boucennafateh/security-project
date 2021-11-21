package org.fate7.securityproject;

import org.fate7.securityproject.model.AppUser;
import org.fate7.securityproject.model.Role;
import org.fate7.securityproject.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.Arrays;

@SpringBootApplication
public class SecurityProjectApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityProjectApplication.class, args);
    }


    @Bean
    public static CommandLineRunner run(UserService userService){

        return args -> {

            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));

            userService.saveUser(new AppUser(null, "Fateh", "fateh", "fateh@gmail.com", "123", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Roufaida", "roufi", "roufaida@gmail.com", "123", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Mohammed", "moh", "mohammed@gmail.com", "123", new ArrayList<>()));

            userService.addRoleToUser("fateh", "ROLE_ADMIN");
            userService.addRoleToUser("fateh", "ROLE_USER");
            userService.addRoleToUser("roufi", "ROLE_USER");
            userService.addRoleToUser("moh", "ROLE_USER");


        };
    }

}
