package com.cyverse.api.exceptions;

import com.cyverse.api.controllers.IrodsController;
import io.javalin.Javalin;
import io.javalin.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(ExceptionHandler.class);

    public static void handle(Javalin app) {
        // HTTP exceptions
        app.exception(ResourceAlreadyExistsException.class, (e, ctx) -> {
            logger.warn("Resource already exists: {}", e.getMessage());
            ctx.status(HttpStatus.CONFLICT);
        });

        app.exception(UserException.class, (e, ctx) -> {
            logger.error("Bad request error: {}", e.getMessage());
            ctx.status(HttpStatus.BAD_REQUEST);
        });

        app.exception(Exception.class, (e, ctx) -> {
            logger.error("Internal server error: {}", e.getMessage());
            ctx.status(HttpStatus.INTERNAL_SERVER_ERROR);
        });
    }
}
