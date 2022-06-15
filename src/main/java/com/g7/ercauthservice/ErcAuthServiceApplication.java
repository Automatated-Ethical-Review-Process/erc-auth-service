package com.g7.ercauthservice;

import com.g7.ercauthservice.service.DefaultDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class ErcAuthServiceApplication implements CommandLineRunner {

	@Autowired
	private DefaultDataService defaultDataService;
	public static void main(String[] args) {
		SpringApplication.run(ErcAuthServiceApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		defaultDataService.insertRolesToDB();
		defaultDataService.insertUsersToDB();
	}
}
