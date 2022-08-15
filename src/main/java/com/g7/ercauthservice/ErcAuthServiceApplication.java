package com.g7.ercauthservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class ErcAuthServiceApplication{

	public static void main(String[] args) {
		SpringApplication.run(ErcAuthServiceApplication.class, args);
	}


}
