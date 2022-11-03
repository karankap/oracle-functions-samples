/*
# oci-apigw-authorizer-idcs-java version 1.0.
#
# Copyright (c) 2020 Oracle, Inc.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
*/

package com.example.utils;

/**
 * It contains the resource server configuration and constants Like a properties file, but simpler
 */
public class ResourceServerConfig {

  // YOUR IDENTITY DOMAIN AND APPLICATION CREDENTIALS
  public static final String CLIENT_ID = "6b1b1674c50847a58b29aaccfbf9a6d6";
  public static final String CLIENT_SECRET = "e7880c7a-dc19-4014-ba8d-ddaf70d17f9d";
  public static final String IDCS_URL =
      "https://idcs-c19bfd1381b34052943e54d02014b5fc.identity.oraclecloud.com";

  // INFORMATION ABOUT THE TARGET APPLICATION
  public static final String SCOPE_AUD = "https://luldljodckrrqg6jiplllszpbi.apigateway.us-phoenix-1.oci.customer-oci.com";

  // TEST CLIENT CREDENTIALS
  public static final String TEST_CLIENT_ID = "";
  public static final String TEST_CLIENT_SECRET = "";
  public static final String TEST_CLIENT_SCOPE = "http://service1urn:opc:resource:consumer::all";

  // INFORMATION ABOUT IDENTITY CLOUD SERVICES
//  public static final String JWK_URL = IDCS_URL + "/admin/v1/SigningCert/jwk";
  public static final String JWK_URL = "/admin/v1/SigningCert/jwk";
  public static final String TOKEN_URL = IDCS_URL + "/oauth2/v1/token";

  // PROXY
  public static final boolean HAS_PROXY = false;
  public static final String PROXY_HOST = "http://my.proxy.com";
  public static final int PROXY_PORT = 80;
}