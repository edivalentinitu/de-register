package com.cyverse.keycloak.ldap.service;

import com.cyverse.keycloak.http.ListenerHttpClient;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.jboss.logging.Logger;
import org.keycloak.models.UserModel;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.Map;

/**
 *  LDAP Service in Keycloak context.
 */
public class LdapService {
    private static final Logger logger = Logger.getLogger(LdapService.class);
    private final ListenerHttpClient httpClient;
    private static final String LDAP_ENDPOINT = "/api/users/ldap";

    public LdapService(ListenerHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Adds user to LDAP.
     *
     * @param user the UserModel that comes from Keycloak data-model
     */
    public void addLdapUser(UserModel user) {
        logger.debug("Try adding user to LDAP: " + user.getUsername());

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> data = Map.of(
                "username", user.getUsername(),
                "firstName", user.getFirstName(),
                "lastName", user.getLastName(),
                "email", user.getEmail()
        );

        try {
            String jsonBody = mapper.writeValueAsString(data);

            HttpResponse<String> response =
                    httpClient.getHttpClient()
                            .send(httpClient
                                            .getRequestPOST(LDAP_ENDPOINT, jsonBody),
                                    HttpResponse.BodyHandlers.ofString());

            logger.debug("API RESPONSE STATUS CODE: " + response.statusCode());

            if (response.statusCode() == HttpStatus.SC_CREATED) {
                logger.info("Successfully added user " + user.getUsername() + " to LDAP");
            }
        } catch (JsonProcessingException jsonExc) {
            logger.error("Got exception trying to build API client body data: " + user.getUsername() + "\n" + jsonExc.getMessage());
        } catch (IOException | InterruptedException httpExc) {
            logger.error("Got exception from HTTP request to API client: " + httpExc.getMessage());
        }
    }

}