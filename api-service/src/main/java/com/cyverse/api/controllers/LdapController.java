package com.cyverse.api.controllers;

import com.cyverse.api.exceptions.ResourceAlreadyExistsException;
import com.cyverse.api.exceptions.UserException;
import com.cyverse.api.models.UserModel;
import com.cyverse.api.services.LdapService;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;

import javax.naming.NamingException;
import java.security.NoSuchAlgorithmException;

public class LdapController {

    private LdapService ldapService;

    public LdapController(LdapService ldapService) {
        this.ldapService = ldapService;
    }

    public void updateLdapUser(Context ctx)
            throws UserException, ResourceAlreadyExistsException,
            NamingException, NoSuchAlgorithmException {
        UserModel user = ctx.bodyAsClass(UserModel.class);
        user.validateUsername();
        ldapService.completeLdapUserAttributes(user);
        ctx.status(HttpStatus.OK);
    }

    public void addLdapUserToGroup(Context ctx)
            throws UserException, ResourceAlreadyExistsException, NamingException {
        UserModel request = ctx.bodyAsClass(UserModel.class);
        request.validateUsername();
        if (request.getGroup() == null) {
            throw new UserException("Group is missing");
        }
        ldapService.addLdapUserToGroup(request.getUsername(), request.getGroup());
        ctx.status(HttpStatus.OK);
    }
}
