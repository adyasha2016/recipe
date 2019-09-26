package com.tcs.demo.recipe.config;

import java.util.ArrayList;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.service.VendorExtension;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig {
	@Bean
	public Docket productApi() {
		return new Docket(DocumentationType.SWAGGER_2)
				.select()                 
				.apis(RequestHandlerSelectors.basePackage("com.tcs.demo.recipe.controller"))
				.paths(PathSelectors.ant("/api/**"))
				.build()
				.apiInfo(metaData());
	}

	private ApiInfo metaData() {
		@SuppressWarnings("rawtypes")
		ApiInfo apiInfo = new ApiInfo(
				"Recipe Application",
				"API which allows users to manage their favourite recipe with basic CRUD operations",
				"1.0",
				"Terms of service",
				new Contact("Dhiraj", "https://github.com/dhi37th/reciperepository.git", ""),
				"",
				"", new ArrayList<VendorExtension>());
		return apiInfo;
	}
}
