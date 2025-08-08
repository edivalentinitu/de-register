package com.cyverse.api;

import com.cyverse.api.config.ApiServiceConfig;
import com.cyverse.api.config.IrodsServiceConfig;
import com.cyverse.api.config.LdapServiceConfig;
import com.cyverse.api.controllers.HealthController;
import com.cyverse.api.controllers.IrodsController;
import com.cyverse.api.controllers.LdapController;
import com.cyverse.api.exceptions.ExceptionHandler;
import com.cyverse.api.services.IrodsService;
import com.cyverse.api.services.LdapService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.javalin.Javalin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class Application {
    private static final Logger logger = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        Javalin app = Javalin.create()
                .start(7000);
        try {
            initControllers(app, args[0]);
        } catch (Exception e) {
            logger.error("Error at initialization: {}", e.getMessage());
            System.exit(1);
        }

        ExceptionHandler.handle(app);
        logger.info("API started.");
    }

    private static void initControllers(Javalin app, String configFile) throws Exception {
        logger.info("Initializing controllers");
        HealthController healthController = new HealthController();
        app.get("/", healthController::getHealthy);

        // configs
        ApiServiceConfig appConfig = loadConfig(configFile);
        appConfig.verifyFieldsAreSet();

        // services
        IrodsService irodsService = new IrodsService(appConfig.getIrodsServiceConfig());
        LdapService ldapService = new LdapService(appConfig.getLdapServiceConfig());
        ldapService.init();

        // controllers
        IrodsController irodsController = new IrodsController(irodsService);
        app.post("/api/users/irods", irodsController::addIrodsUser);
        app.put("/api/users/irods", irodsController::grantUserAccess);

        LdapController ldapController = new LdapController(ldapService);
        app.put("/api/users/ldap", ldapController::updateLdapUser);
        app.put("/api/ǵroups/ldap", ldapController::addLdapUserToGroup);
    }

    private static ApiServiceConfig loadConfig(String filePath) throws Exception {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        return mapper.readValue(new File(filePath), ApiServiceConfig.class);
    }
}