package com.cyverse.api.services;

import com.cyverse.api.config.LdapServiceConfig;
import com.cyverse.api.exceptions.ResourceAlreadyExistsException;
import com.cyverse.api.models.UserModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import static org.mockito.internal.verification.VerificationModeFactory.times;

public class LdapServiceTest {
    @Mock
    private LdapServiceConfig config;

    @Spy
    @InjectMocks
    LdapService ldapService;

    @BeforeEach
    void init() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testUpdateLdapUser() throws NamingException, NoSuchAlgorithmException,
            ResourceAlreadyExistsException {
        UserModel user = new UserModel();
        user.setUsername("test_user");
        user.setEmail("test_user@test.com");
        user.setFirstName("test");
        user.setLastName("user");

        doReturn("dc=example,dc=org").when(config).getBaseDN();
        doReturn("testpass").when(config).getFirstLoginPassword();
        doReturn("{SSHA}testpasshashed1234").when(ldapService).generateSSHAHash("testpass");

        String expectedEntryDN = "uid=test_user,ou=People,dc=example,dc=org";
        ModificationItem[] expectedMods = buildMods(user);

        doNothing().when(ldapService).modifyAttrsExtraOperation(eq(expectedEntryDN), any());

        ldapService.completeLdapUserAttributes(user);
        verify(ldapService, times(1)).modifyAttrsExtraOperation(
                eq(expectedEntryDN), argThat(mods -> {
                    try {
                        return sameMods(expectedMods, mods);
                    } catch (NamingException e) {
                        return false;
                    }
                }));
    }

    @Test
    void testUpdateLdapUserAttributeAlreadyExists() throws NamingException, NoSuchAlgorithmException {
        UserModel user = new UserModel();
        user.setUsername("test_user");
        user.setEmail("test_user@test.com");
        user.setFirstName("test");
        user.setLastName("user");

        doReturn("dc=example,dc=org").when(config).getBaseDN();
        doReturn("testpass").when(config).getFirstLoginPassword();
        doReturn("{SSHA}testpasshashed1234").when(ldapService).generateSSHAHash("testpass");

        String expectedEntryDN = "uid=test_user,ou=People,dc=example,dc=org";

        doThrow(AttributeInUseException.class).when(ldapService).modifyAttrsExtraOperation(eq(expectedEntryDN), any());

        assertThrows(ResourceAlreadyExistsException.class, () -> ldapService.completeLdapUserAttributes(user));
    }

    @Test
    void testAddLdapUserToGroup() throws ResourceAlreadyExistsException, NamingException {
        String testUser = "test_user";
        String group = "everyone";

        doReturn("everyone").when(config).getEveryoneGroup();
        doReturn("dc=example,dc=org").when(config).getBaseDN();

        String expectedGroupDN = "cn=everyone,ou=Groups,dc=example,dc=org";
        doNothing().when(ldapService).modifyAttrsSimple(any(), any());

        ldapService.addLdapUserToGroup(testUser, group);

        verify(ldapService, times(1)).modifyAttrsSimple(
                eq(expectedGroupDN),
                argThat(mods ->
                mods.length == 1 &&
                        mods[0].getModificationOp() == DirContext.ADD_ATTRIBUTE &&
                        "memberUid".equals(mods[0].getAttribute().getID()) &&
                        mods[0].getAttribute().contains("test_user")));
    }

    @Test
    void testAddLdapUserToGroupAlreadyExists() throws NamingException {
        String testUser = "test_user";
        String group = "everyone";

        doReturn("everyone").when(config).getEveryoneGroup();
        doReturn("dc=example,dc=org").when(config).getBaseDN();

        String expectedGroupDN = "cn=everyone,ou=Groups,dc=example,dc=org";
        doThrow(AttributeInUseException.class).when(ldapService).modifyAttrsSimple(eq(expectedGroupDN),
                argThat(mods ->
                mods.length == 1 &&
                        mods[0].getModificationOp() == DirContext.ADD_ATTRIBUTE &&
                        "memberUid".equals(mods[0].getAttribute().getID()) &&
                        mods[0].getAttribute().contains("test_user")));

        assertThrows(ResourceAlreadyExistsException.class, () -> ldapService.addLdapUserToGroup(testUser, group));
    }

    private boolean sameMods(ModificationItem[] items1, ModificationItem[] items2) throws NamingException {
        if (items1.length != items2.length) {
            return false;
        }

        for (int i = 0; i < items1.length-1; i++) {
            if ((items1[i].getModificationOp() != items2[i].getModificationOp())
                    || (!Objects.equals(items1[i].getAttribute().getID(), items2[i].getAttribute().getID()))
                    || (!Objects.equals(items1[i].getAttribute().get().toString(), items2[i].getAttribute().get().toString()))) {
                return false;
            }
        }

        return true;
    }

    private ModificationItem[] buildMods(UserModel user) throws NamingException {
        Attribute objClass = new BasicAttribute("objectClass");
        objClass.add("posixAccount");
        objClass.add("shadowAccount");

        Attributes attrs = new BasicAttributes(true);

        attrs.put(objClass);
        attrs.put("givenName", user.getFirstName());
        attrs.put("sn", user.getFirstName());
        attrs.put("cn", user.getFirstName() + " " + user.getLastName());
        attrs.put("mail", user.getEmail());
        attrs.put("gidNUmber", "10013");
        attrs.put("homeDirectory", "/home/" + user.getUsername());
        attrs.put("loginShell", "/bin/bash");
        attrs.put("userPassword", "{SSHA}testpasshashed1234");
        attrs.put("title", "University/College Staff");
        attrs.put("o", "Graz University of Technology");

        ModificationItem[] mods = new ModificationItem[attrs.size()+1];
        NamingEnumeration<?> attrsIter = attrs.getAll();
        int i = 0;
        while (attrsIter.hasMore()) {
            Attribute toAdd = (Attribute) attrsIter.next();
            mods[i++] =
                    new ModificationItem(
                            DirContext.ADD_ATTRIBUTE,
                            toAdd
                    );
        }
        return mods;
    }
}
