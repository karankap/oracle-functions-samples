/*
# oci-apigw-authorizer-idcs-java version 1.0.
#
# Copyright (c) 2020 Oracle, Inc.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
*/

package com.example.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.text.ParseException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Validates access tokens */
public class AccessTokenValidator {

  private static final ConfigurableJWTProcessor JWT_PROCESSOR = new DefaultJWTProcessor();
  private static final Map<String, JWKSet> TENANT_PUBLIC_KEY_CACHE = new ConcurrentHashMap<>();
  //  private static JWKSet jwk;
  //  private static boolean isSafe = false;
  //  private static JWKSource keySource;
  //  private static JWSKeySelector keySelector;

  //  public void init() {
  //    if (!AccessTokenValidator.isSafe) {
  //      try {
  //        jwk = JWKUtil.getJWK();
  //        keySource = new ImmutableJWKSet(jwk);
  //        keySelector = new JWSVerificationKeySelector(JWSAlgorithm.RS256, keySource);
  //        JWT_PROCESSOR.setJWSKeySelector(keySelector);
  //        AccessTokenValidator.isSafe = true;
  //        Logger.getLogger(AccessTokenValidator.class.getName())
  //            .log(Level.INFO, "Signing Key from IDCS successfully loaded!");
  //      } catch (Exception ex) {
  //        Logger.getLogger(AccessTokenValidator.class.getName())
  //            .log(Level.SEVERE, "Error loading Signing Key from IDCS", ex);
  //        AccessTokenValidator.isSafe = false;
  //      }
  //    }
  //  }

  // checks if the token is valid
  public JWTClaimsSet validate(final String accessToken) {
    SignedJWT signedJWT = null;
    try {
      signedJWT = SignedJWT.parse(accessToken);
    } catch (Exception e) {
      e.printStackTrace();
      throw new InvalidTokenException(e.getMessage());
    }

    final String tenant = getClaimFromToken(signedJWT, "tenant");
    System.out.println("Received tenant as " + tenant);
    if (tenant == null) {
      throw new InvalidTokenException("Invalid tenant received in the token");
    }

    JWKSet jwkSet = TENANT_PUBLIC_KEY_CACHE.get(tenant.toLowerCase());
    if (jwkSet == null) {
      System.out.println(
          "Cache miss for tenant "
              + tenant
              + ", Cache size currently is "
              + TENANT_PUBLIC_KEY_CACHE.size());

      try {
        final String JWKSURL = getClaimFromToken(signedJWT, "tenant_iss");
        jwkSet = JWKUtil.getJWK(accessToken, JWKSURL);
        TENANT_PUBLIC_KEY_CACHE.put(tenant.toLowerCase(), jwkSet);
        System.out.println("Cache updated for tenant " + tenant);
      } catch (Exception e) {
        e.printStackTrace();
        throw new JWKSLoadException(e.getMessage());
      }
    } else {
      System.out.println(
          "JWKSet found in cache for tenant "
              + tenant
              + ", Cache size currently is "
              + TENANT_PUBLIC_KEY_CACHE.size());
    }

    if (jwkSet != null) {
      return validate(accessToken, jwkSet);
    } else {
      return null;
    }
  }

  private String getClaimFromToken(final SignedJWT signedJWT, final String claimName) {
    String claimValue = null;
    Map<String, Object> claims = null;

    try {
      claims = signedJWT.getJWTClaimsSet().getClaims();
    } catch (ParseException e) {
      e.printStackTrace();
      throw new InvalidTokenException(e.getMessage());
    }

    if (claims != null && claims.containsKey(claimName)) {
      claimValue = claims.get(claimName) == null ? null : "" + claims.get(claimName);
    }

    return claimValue;
  }

  private JWTClaimsSet validate(final String accessToken, final JWKSet jwkSet) {
    try {
      final JWKSource keySource = new ImmutableJWKSet(jwkSet);
      final JWSKeySelector keySelector =
          new JWSVerificationKeySelector(JWSAlgorithm.RS256, keySource);

      JWT_PROCESSOR.setJWSKeySelector(keySelector);

      SecurityContext ctx = null;
      JWTClaimsSet claimsSet = JWT_PROCESSOR.process(accessToken, ctx);

      // VALIDATE AUDIENCE
      if (claimsSet.getAudience().indexOf(ResourceServerConfig.SCOPE_AUD) >= 0) {
        // CORRECT AUDIENCE
        return claimsSet;
      } else {
        throw new InvalidTokenException("Incorrect audience");
      }
    } catch (JOSEException ex) {
      ex.printStackTrace();
      throw new InvalidTokenException(ex.getMessage());
    } catch (BadJOSEException ex) {
      ex.printStackTrace();
      throw new InvalidTokenException(ex.getMessage());
      // BadJWEException, BadJWSException, BadJWTException
      // Bad JSON Web Encryption (JWE) exception. Used to indicate a JWE-protected object that
      // couldn't be successfully decrypted or its integrity has been compromised.
      // Bad JSON Web Signature (JWS) exception. Used to indicate an invalid signature or
      // hash-based message authentication code (HMAC).
      // Bad JSON Web Token (JWT) exception.
    } catch (ParseException ex) {
      ex.printStackTrace();
      throw new InvalidTokenException(ex.getMessage());
    }
  }
}
