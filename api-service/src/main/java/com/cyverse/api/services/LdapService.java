package com.cyverse.api.services;

import com.cyverse.api.config.LdapServiceConfig;
import com.cyverse.api.exceptions.ResourceAlreadyExistsException;
import com.cyverse.api.models.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Hashtable;
import java.util.Objects;
import java.util.Optional;

/**
 * LDAP service based on javax.naming library.
 */
public class LdapService {
    private static final Logger logger = LoggerFactory.getLogger(LdapService.class);
    private final LdapServiceConfig ldapConfig;
    private final Hashtable<String, String> env;

    public LdapService(LdapServiceConfig config) {
        this.ldapConfig = config;
        this.env = new Hashtable<>();
    }

    /**
     * Init the LDAP environment.
     */
    public void init() {
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapConfig.getHost());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, ldapConfig.getAdmin());
        env.put(Context.SECURITY_CREDENTIALS, ldapConfig.getPassword());
    }

    /**
     * Adds attributes to an already existing LDAP user if it exists.
     *
     * @param user the user registered in LDAP
     */
    public void completeLdapUserAttributes(UserModel user)
            throws ResourceAlreadyExistsException, NamingException,
            NoSuchAlgorithmException {
        logger.debug("Try adding attributes to LDAP user: {}", user.getUsername());

        String entryDN = "uid=" + user.getUsername() +",ou=People," + ldapConfig.getBaseDN();
        try {
            Attributes attrs = getUserAttributes(user);
            ModificationItem[] newAttrs = new ModificationItem[attrs.size()+1];
            NamingEnumeration<?> resultedAttrs = attrs.getAll();

            int i = 0;
            while (resultedAttrs.hasMore()) {
                Attribute toAdd = (Attribute) resultedAttrs.next();
                newAttrs[i++] =
                    new ModificationItem(
                            DirContext.ADD_ATTRIBUTE,
                            toAdd
                    );
            }

            modifyAttrsExtraOperation(entryDN, newAttrs);
            logger.info("LDAP user successfully updated: {}", user.getUsername());
        } catch (NamingException e) {
            if (e instanceof AttributeInUseException) {
                throw new ResourceAlreadyExistsException("Attribute already in use: " + e.getMessage());
            }
            logger.error("Error adding LDAP user: {}\n{} ", user.getUsername(), e.getMessage());
            throw e;
        }
    }

    /**
     * Add an existing user to an LDAP Group.
     *
     * @param username the user to add to the group
     * @param group the group to add to
     */
    public void addLdapUserToGroup(String username, String group) throws ResourceAlreadyExistsException, NamingException {
        logger.debug("Try adding user: {} to LDAP Group: {}", username, group);

        // Get everyoneGroup from this config - to not duplicate ldap configs across services
        if (Objects.equals(group, "everyone")) {
            group = ldapConfig.getEveryoneGroup();
        }

        String groupDn = "cn=" + group + ",ou=Groups," + ldapConfig.getBaseDN();

        try {
            ModificationItem[] mods = new ModificationItem[1];
            mods[0] = new ModificationItem(
                    DirContext.ADD_ATTRIBUTE,
                    new BasicAttribute("memberUid", username)
            );
            modifyAttrsSimple(groupDn, mods);
            logger.info("LDAP user: {} added successfully to group: {}", username, group);
        } catch (NamingException e) {
            if (e instanceof AttributeInUseException) {
                String msg = "User is already a member of the group.";
                logger.warn(msg);
                throw new ResourceAlreadyExistsException(msg);
            } else {
                throw e;
            }
        }
    }

    protected void modifyAttrsExtraOperation(String name, ModificationItem[] items) throws NamingException {
        DirContext ctx = new InitialDirContext(env);
        // TODO custom exception with message for empty optional
        items[items.length-1] = new ModificationItem(
                DirContext.ADD_ATTRIBUTE,
                new BasicAttribute("uidNumber", getLastAssignedUid(ctx).orElseThrow())
        );
        ctx.modifyAttributes(name, items);
        ctx.close();
    }

    protected void modifyAttrsSimple(String name, ModificationItem[] items) throws NamingException {
        DirContext ctx = new InitialDirContext(env);
        ctx.modifyAttributes(name, items);
        ctx.close();
    }

    // TODO Consider moving these to a cfg file.
    private Attributes getUserAttributes(UserModel user) throws NoSuchAlgorithmException {
        Attribute objClass = new BasicAttribute("objectClass");
        objClass.add("posixAccount");
        // TODO set shadow properties?
        objClass.add("shadowAccount");

        Attributes attrs = new BasicAttributes(true);

        attrs.put(objClass);
        attrs.put("givenName", user.getFirstName());
        attrs.put("sn", user.getFirstName());
        attrs.put("cn", user.getFirstName() + " " + user.getLastName());
        attrs.put("mail", user.getEmail());
        // TODO Check and see if there is a better way to set the gidNumber
        attrs.put("gidNUmber", "10013");
        attrs.put("homeDirectory", "/home/" + user.getUsername());
        attrs.put("loginShell", "/bin/bash");
        attrs.put("userPassword", generateSSHAHash(ldapConfig.getFirstLoginPassword()));

        // TODO Just for testing now. Decide if needed
        attrs.put("title", "University/College Staff");
        attrs.put("o", "Graz University of Technology");

        return attrs;
    }

    /**
     * Get last LDAP UID assigned to a user.
     * Build a context search, perform it and get the maximum UID present in the configured LDAP
     * host.
     *
     * @return Optional UID number
     */
    private Optional<String> getLastAssignedUid(DirContext ctx) {
        String searchFilter = "(uidNumber=*)";

        try {

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(new String[]{"uidNumber"});

            NamingEnumeration<SearchResult> results =
                    ctx.search(ldapConfig.getBaseDN(), searchFilter, searchControls);

            long maxUid = 0;
            while (results.hasMore()) {
                SearchResult result = results.next();
                Attributes attrs = result.getAttributes();
                Attribute uidNumberAttr = attrs.get("uidNumber");
                long uidParsed = Long.parseLong((String) uidNumberAttr.get());
                if (uidParsed > maxUid) {
                    maxUid = uidParsed;
                }
            }

            return Optional.of(String.valueOf(++maxUid));
        } catch (NamingException e) {
            logger.error("Error searching uids: {}", e.getMessage());
        }
        return Optional.empty();
    }

    protected String generateSSHAHash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] passwordBytes = password.getBytes();

        // salt
        byte[] salt = new byte[4];
        new SecureRandom().nextBytes(salt);

        md.update(passwordBytes);
        md.update(salt);

        byte[] hashedPassword = md.digest();

        byte[] combined = new byte[hashedPassword.length + salt.length];
        System.arraycopy(hashedPassword, 0, combined, 0, hashedPassword.length);
        System.arraycopy(salt, 0, combined, hashedPassword.length, salt.length);

        return "{SSHA}" + Base64.getEncoder().encodeToString(combined);
    }
}
