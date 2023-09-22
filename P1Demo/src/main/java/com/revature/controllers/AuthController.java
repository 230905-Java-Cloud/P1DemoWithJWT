package com.revature.controllers;

//This controler will handle all things related to auth (login and register)
//insertUser should probably go in here, since you need to be able to create a user before logging in as them

import com.revature.models.AuthResponseDTO;
import com.revature.models.Employee;
import com.revature.models.LoginDTO;
import com.revature.utils.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController //makes a class a bean and allows for automatic Java <-> JSON conversions
@RequestMapping("/auth") //any request going to 5000/p1/auth will go here
@CrossOrigin() //configuring this will allow requests from specified origins
public class AuthController {


    //autowire a JwtTokenUtil and AuthenticationManager
    private AuthenticationManager authManager;
    private JwtTokenUtil jwtUtil;

    @Autowired
    public AuthController(AuthenticationManager authManager, JwtTokenUtil jwtUtil) {
        this.authManager = authManager;
        this.jwtUtil = jwtUtil;
    }

    //this method accepts user login credentials in the RequestBody and Validates those credentials
    @PostMapping
    public ResponseEntity<Object> login(@RequestBody @Valid LoginDTO lDTO){

        try{

            //attempt to log in (notice no direct calls of the DAO)
            //this is where the username and password go to get validated
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(lDTO.getUsername(), lDTO.getPassword())
            );

            //build up the employee based on the validation
            Employee employee = (Employee) authentication.getPrincipal();

            //if the user is valid, generate our JWT!
            String accessToken = jwtUtil.generateAccessToken(employee);

            //generate our AuthResponseDTO and send it back with a 200 status code
            AuthResponseDTO aDTO = new AuthResponseDTO(employee.getUsername(), accessToken);

            return ResponseEntity.ok().body(aDTO);

        } catch (BadCredentialsException e){
            //if login fails, return a 401 (UNAUTHORIZED) and the exception message
            System.out.println("BAD CREDENTIALS!!");
            return ResponseEntity.status(401).body(e.getMessage());
        }

    }

    //TODO: add employee should also be part of auth. The WebSecurityConfig will allow all requests to /auth

    //otherwise, we wouldn't be able to create an employee without logging in.
    ///but... we need to create an employee to log in as them!

}