/**
 * 
 */
package com.tcs.demo.recipe.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.multipart.MultipartFile;

/**
 * File uploading utility.
 * @author Dhiraj
 *
 */
public class FileUploadUtil {
	private static final  Logger LOGGER = LogManager.getLogger(FileUploadUtil.class);

	private static final String FOLDER_TO_UPLOAD = System.getProperty("user.home");

	private FileUploadUtil() {
		throw new IllegalStateException("Utility class");
	}

	public  static String uploadFile(MultipartFile file) throws IOException{
		if(file.isEmpty()) {
			throw new IllegalArgumentException("File to upload is empty");
		}
		byte[] bytes  = file.getBytes();
		Path path = Paths.get(FOLDER_TO_UPLOAD ,"recipeImages", file.getOriginalFilename());

		LOGGER.info("Attempting to save file "+file.getOriginalFilename()+" to "+path.getParent());

		if (!path.getParent().toFile().exists()) //create directory if it does not exist. Mostly during first time upload
			Files.createDirectories(path.getParent());
		Files.write(path, bytes,StandardOpenOption.CREATE);
		return path.toString(); 
	}
}
