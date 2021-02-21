package com.example.securityservice;

import com.example.securityservice.sec.entities.AppRole;
import com.example.securityservice.sec.entities.AppUser;
import com.example.securityservice.sec.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SecurityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityServiceApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner start(AccountService accountService){
        return args -> {
           accountService.addNewRole(new AppRole(null,"USER"));
            accountService.addNewRole(new AppRole(null,"ADMIN"));
            accountService.addNewRole(new AppRole(null,"CUSTOMER_MANAGER"));
            accountService.addNewRole(new AppRole(null,"PRODUCT_MANAGER"));
            accountService.addNewRole(new AppRole(null,"BILLS_MANAGER"));

            accountService.addNewUser(new AppUser(null,"user1","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"admin","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"hassan","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"wissal","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"fouad","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"karima","1234",new ArrayList<>()));

            accountService.addRoleToUser("user1","USER");
            accountService.addRoleToUser("admin","USER");
            accountService.addRoleToUser("admin","ADMIN");
            accountService.addRoleToUser("hassan","USER");
            accountService.addRoleToUser("hassan","CUSTOMER_MANAGER");
            accountService.addRoleToUser("wissal","USER");
            accountService.addRoleToUser("wissal","PRODUCT_MANAGER");
            accountService.addRoleToUser("fouad","USER");
            accountService.addRoleToUser("fouad","BILLS_MANAGER");
            accountService.addRoleToUser("karima","USER");
            accountService.addRoleToUser("karima","BILLS_MANAGER");

        };
    }
}
