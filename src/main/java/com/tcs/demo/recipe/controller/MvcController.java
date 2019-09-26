/**
 * 
 */
package com.tcs.demo.recipe.controller;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Base64;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.vault.config.VaultProperties;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.CertificateBundle;
import org.springframework.vault.support.VaultCertificateRequest;
import org.springframework.vault.support.VaultCertificateResponse;
import org.springframework.vault.support.VaultHealth;
import org.springframework.vault.support.VaultResponseSupport;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.tcs.demo.recipe.bean.User;
import com.tcs.demo.recipe.service.UserService;
import com.tcs.demo.recipe.util.EncryptionUtil;
import lombok.Data;

/**
 * Home page redirection controller
 * 
 * @author Dhiraj
 *
 */

@RestController

public class MvcController {

  private final static Logger logger = LoggerFactory.getLogger(MvcController.class);

  @Autowired
  UserService userService;

  final VaultOperations vaultOperations;
  final VaultProperties vaultProperties;

  public MvcController(VaultOperations vaultOperations, VaultProperties vaultProperties) {
    super();
    this.vaultOperations = vaultOperations;
    this.vaultProperties = vaultProperties;
  }

  @GetMapping({"/", "/home"})
  public ModelAndView returnHomePage(Principal user, HttpServletResponse response)
      throws UnsupportedEncodingException, GeneralSecurityException {
    
    getOrRequestCertificate(vaultProperties, vaultOperations);
    
    User sessionUser = userService.getUserByLoginId(user.getName());
    response.addCookie(new Cookie("ed", sessionUser.getUsrId().toString()));
    String encodedBasic = Base64.getEncoder().encodeToString(
        (sessionUser.getUsrLoginId() + ":" + EncryptionUtil.decrypt(sessionUser.getUsrPassword()))
            .getBytes());
    response.addCookie(new Cookie("ba", encodedBasic)); // basic authentication header value of
                                                        // encoded username:password


    return new ModelAndView("redirect:home.html");

  }
  
  /**
   * Request SSL Certificate from Vault or retrieve cached certificate.
   * <p>
   * If {@link VaultPkiProperties#isReuseValidCertificate()} is enabled this method
   * attempts to read a cached Certificate from Vault at {@code secret/$
   * spring.application.name}/cert/${spring.cloud.vault.pki.commonName}}. Valid
   * certificates will be reused until they expire. A new certificate is requested and
   * cached if no valid certificate is found.
   *
   * @param vaultProperties
   * @param vaultOperations
   * @param pkiProperties
   * @return the {@link CertificateBundle}.
   */
  public CertificateBundle getOrRequestCertificate(
          VaultProperties vaultProperties, VaultOperations vaultOperations) {

    System.out.println("getOrRequestCertificate in MvcController-->");
      CertificateBundle validCertificate = findValidCertificate(vaultProperties,
              vaultOperations);

      /*if (!pkiProperties.isReuseValidCertificate()) {
          return validCertificate;
      }*/

      String cacheKey = createCacheKey(vaultProperties);
      vaultOperations.delete(cacheKey);

      VaultCertificateResponse certificateResponse = requestCertificate(
              vaultOperations);

      VaultHealth health = vaultOperations.opsForSys().health();
      storeCertificate(cacheKey, vaultOperations, health, certificateResponse);
      System.out.println("certificateResponse.getData(): "+certificateResponse.getData());

      return certificateResponse.getData();
  }
  
  private static void storeCertificate(String cacheKey,
      VaultOperations vaultOperations, VaultHealth health,
      VaultCertificateResponse certificateResponse) {

  CertificateBundle certificateBundle = certificateResponse.getData();
  long expires = (health.getServerTimeUtc() + certificateResponse
          .getLeaseDuration()) - 60;

  CachedCertificateBundle cachedCertificateBundle = new CachedCertificateBundle();

  cachedCertificateBundle.setExpires(expires);
  cachedCertificateBundle.setTimeRequested(health.getServerTimeUtc());
  cachedCertificateBundle.setPrivateKey(certificateBundle.getPrivateKey());
  cachedCertificateBundle.setCertificate(certificateBundle.getCertificate());
  cachedCertificateBundle.setIssuingCaCertificate(certificateBundle
          .getIssuingCaCertificate());
  cachedCertificateBundle.setSerialNumber(certificateBundle.getSerialNumber());

  vaultOperations.write(cacheKey, cachedCertificateBundle);
}

  private VaultCertificateResponse requestCertificate(VaultOperations vaultOperations) {

    logger.info("Requesting SSL certificate from Vault for: {}", "www.demo.com");

    VaultCertificateRequest certificateRequest =
        VaultCertificateRequest.builder().commonName("www.demo.com").build();

    VaultCertificateResponse certificateResponse =
        vaultOperations.opsForPki("pki").issueCertificate("web-certs", certificateRequest);
    System.out.println("RequestId-->" + certificateResponse.getRequestId());
    System.out.println("getLeaseDuration-->" + certificateResponse.getLeaseDuration());
    System.out.println("LeaseId-->" + certificateResponse.getLeaseId());
    System.out.println("Auth-->" + certificateResponse.getAuth());
    System.out.println("SerialNumber-->" + certificateResponse.getData().getSerialNumber());
    System.out.println("Issuing certificate-->" + certificateResponse.getData().getCertificate());
    System.out
        .println("CA certificate-->" + certificateResponse.getData().getIssuingCaCertificate());
    System.out.println("Private key-->" + certificateResponse.getData().getPrivateKey());

    System.out.println("wrapinfo-->" + certificateResponse.getWrapInfo());
    return certificateResponse;
  }

  /**
   * Find a valid, possibly cached, {@link CertificateBundle}.
   *
   * @param vaultProperties
   * @param vaultOperations
   * @param pkiProperties
   * @return the {@link CertificateBundle} or {@literal null}.
   */
  public CertificateBundle findValidCertificate(VaultProperties vaultProperties,
      VaultOperations vaultOperations) {

    /*
     * if (!pkiProperties.isReuseValidCertificate()) { return requestCertificate(vaultOperations,
     * pkiProperties).getData(); }
     */
    System.out.println("findValidCertificate-->");
    String cacheKey = createCacheKey(vaultProperties);
    System.out.println("cacheKey-->"+cacheKey);

    VaultResponseSupport<CachedCertificateBundle> readResponse =
        vaultOperations.read(cacheKey, CachedCertificateBundle.class);
    
    System.out.println("readResponse: "+readResponse);
    
    //System.out.println("serial number: "+readResponse.getData().getSerialNumber());

    VaultHealth health = vaultOperations.opsForSys().health();
    if (isValid(health, readResponse)) {

      logger.info("Found valid SSL certificate in Vault for: {}", "www.demo.com");

      return getCertificateBundle(readResponse);
    }

    return null;
  }

  private static String createCacheKey(VaultProperties vaultProperties) {

    return String.format("secret/%s/cert/%s", "application", "www.demo.com");
  }

  private static boolean isValid(VaultHealth health,
      VaultResponseSupport<CachedCertificateBundle> readResponse) {

    if (readResponse != null) {

      CachedCertificateBundle cachedCertificateBundle = readResponse.getData();
      if (health.getServerTimeUtc() < cachedCertificateBundle.getExpires()) {
        return true;
      }
    }

    return false;
  }

  private static CertificateBundle getCertificateBundle(
      VaultResponseSupport<CachedCertificateBundle> readResponse) {

    CachedCertificateBundle cachedCertificateBundle = readResponse.getData();

    return CertificateBundle.of(cachedCertificateBundle.getSerialNumber(),
        cachedCertificateBundle.getCertificate(), cachedCertificateBundle.getIssuingCaCertificate(),
        cachedCertificateBundle.getPrivateKey());
  }

  @Data
  static class CachedCertificateBundle {

    private String certificate;

    @JsonProperty("serial_number")
    private String serialNumber;

    @JsonProperty("issuing_ca")
    private String issuingCaCertificate;

    @JsonProperty("private_key")
    private String privateKey;

    @JsonProperty("time_requested")
    private long timeRequested;

    @JsonProperty("expires")
    private long expires;
  }
}
