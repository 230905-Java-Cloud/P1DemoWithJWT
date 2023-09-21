package com.revature.controllers;

import com.revature.models.AuthResponseDTO;
import com.revature.models.Employee;
import com.revature.models.LoginDTO;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.revature.utils.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth") //every request to 5000/p1/auth will go to this Class
@CrossOrigin()
public class AuthController {
    @Autowired
    AuthenticationManager authManager;
    @Autowired
    JwtTokenUtil jwtUtil;

    @PostMapping
    public ResponseEntity<Object> login(@RequestBody @Valid LoginDTO lDTO) {
        System.out.println(lDTO);
        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            lDTO.getUsername(), lDTO.getPassword())
            );

            Employee employee = (Employee) authentication.getPrincipal();
            System.out.println("EMPLOYEE: " + employee);
            String accessToken = jwtUtil.generateAccessToken(employee);
            System.out.println(accessToken);
            AuthResponseDTO response = new AuthResponseDTO(employee.getUsername(), accessToken);

            return ResponseEntity.ok().body(response);

        } catch (BadCredentialsException ex) {
            System.out.println("BAD CREDENTIALS");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    //TODO: This AuthController could arguably be the home to the addUser method, which is in EmployeeController.

}
