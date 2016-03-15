/*
 * Copyright (C) 2015 Glyptodon LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.glyptodon.guacamole.auth.json.user;

import com.google.inject.Inject;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import org.codehaus.jackson.map.ObjectMapper;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.auth.json.ConfigurationService;
import org.glyptodon.guacamole.auth.json.CryptoService;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.ConnectionGroup;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.Directory;
import org.glyptodon.guacamole.net.auth.User;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroup;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroupDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for deriving Guacamole extension API data from UserData objects.
 *
 * @author Michael Jumper
 */
public class UserDataService {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(UserDataService.class);

    /**
     * ObjectMapper for deserializing UserData objects.
     */
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Service for retrieving configuration information regarding the
     * JSONAuthenticationProvider.
     */
    @Inject
    private ConfigurationService confService;

    /**
     * Service for handling cryptography-related operations.
     */
    @Inject
    private CryptoService cryptoService;

    /**
     * The identifier reserved for the root connection group.
     */
    public static final String ROOT_CONNECTION_GROUP = "ROOT";

    /**
     * The name of the HTTP parameter from which base64-encoded, encrypted JSON
     * data should be read. The value of this parameter, when decoded and
     * decrypted, must be valid JSON prepended with the 32-byte raw binary
     * signature generated through signing the JSON with the secret key using
     * HMAC/SHA-256.
     */
    public static final String ENCRYPTED_DATA_PARAMETER = "data";

    /**
     * Derives a new UserData object from the data contained within the given
     * Credentials. If no such data is present, or the data present is invalid,
     * null is returned.
     *
     * @param credentials
     *     The Credentials from which the new UserData object should be
     *     derived.
     *
     * @return
     *     A new UserData object derived from the data contained within the
     *     given Credentials, or null if no such data is present or if the data
     *     present is invalid.
     */
    public UserData fromCredentials(Credentials credentials) {

        // Pull HTTP request, if available
        HttpServletRequest request = credentials.getRequest();
        if (request == null)
            return null;

        // Pull base64-encoded, encrypted JSON data from HTTP request, if any
        // such data is present
        String base64 = request.getParameter(ENCRYPTED_DATA_PARAMETER);
        if (base64 == null)
            return null;

        // Decrypt base64-encoded parameter
        String json;
        try {

            // Decrypt using defined encryption key
            byte[] decrypted = cryptoService.decrypt(
                cryptoService.createEncryptionKey(confService.getSecretKey()),
                DatatypeConverter.parseBase64Binary(base64)
            );

            // Abort if decrypted value cannot possibly have a signature AND data
            if (decrypted.length <= CryptoService.SIGNATURE_LENGTH) {
                logger.warn("Submitted data is too small to contain both a signature and JSON.");
                return null;
            }

            // Split data into signature and JSON portions
            byte[] receivedSignature = Arrays.copyOf(decrypted, CryptoService.SIGNATURE_LENGTH);
            byte[] receivedJSON = Arrays.copyOfRange(decrypted, CryptoService.SIGNATURE_LENGTH, decrypted.length);

            // Produce signature for decrypted data
            byte[] correctSignature = cryptoService.sign(
                cryptoService.createSignatureKey(confService.getSecretKey()),
                receivedJSON
            );

            // Verify signatures
            if (!Arrays.equals(receivedSignature, correctSignature)) {
                logger.warn("Signature of submitted data is incorrect.");
                return null;
            }

            // Convert from UTF-8
            json = new String(receivedJSON, "UTF-8");

        }

        // Fail if base64 data is not valid
        catch (IllegalArgumentException e) {
            logger.warn("Submitted data is not proper base64.");
            logger.debug("Invalid base64 data.", e);
            return null;
        }

        // Handle lack of standard UTF-8 support (should never happen)
        catch (UnsupportedEncodingException e) {
            logger.error("Unexpected lack of support for UTF-8: {}", e.getMessage());
            logger.debug("Unable to decode base64 data as UTF-8.", e);
            return null;
        }

        // Fail if decryption or key retrieval fails for any reason
        catch (GuacamoleException e) {
            logger.error("Decryption of received data failed: {}", e.getMessage());
            logger.debug("Unable to decrypt received data.", e);
            return null;
        }

        // Deserialize UserData from submitted JSON data
        try {

            // Deserialize UserData, but reject if expired
            UserData userData = mapper.readValue(json, UserData.class);
            if (userData.isExpired())
                return null;

            return userData;

        }

        // Fail UserData creation if JSON is invalid/unreadable
        catch (IOException e) {
            logger.error("Received JSON is invalid: {}", e.getMessage());
            logger.debug("Error parsing UserData JSON.", e);
            return null;
        }

    }

    /**
     * Returns the identifiers of all users readable by the user whose data is
     * given by the provided UserData object. As users of the
     * JSONAuthenticationProvider can only see themselves, this will always
     * simply be a set of the user's own username.
     *
     * @param userData
     *     All data associated with the user whose accessible user identifiers
     *     are being retrieved.
     *
     * @return
     *     A set containing the identifiers of all users readable by the user
     *     whose data is given by the provided UserData object.
     */
    public Set<String> getUserIdentifiers(UserData userData) {

        // Each user can only see themselves
        return Collections.singleton(userData.getUsername());

    }

    /**
     * Returns the user object of the user to whom the given UserData object
     * belongs.
     *
     * @param userData
     *     All data associated with the user whose own user object is being
     *     retrieved.
     *
     * @return
     *     The user object of the user to whom the given UserData object
     *     belongs.
     */
    public User getUser(UserData userData) {

        // Pull username from user data
        String username = userData.getUsername();

        // Build user object with READ access to all available data
        return new SimpleUser(
            username,
            getUserIdentifiers(userData),
            getConnectionIdentifiers(userData),
            getConnectionGroupIdentifiers(userData)
        );

    }

    /**
     * Returns a Directory containing all users accessible by the user whose
     * data is given by the provided UserData object. As users of the
     * JSONAuthenticationProvider can only see themselves, this will always
     * contain only the user's own user object.
     *
     * @param userData
     *     All data associated with the user whose user directory is being
     *     retrieved.
     *
     * @return
     *     A Directory containing all users accessible by the user whose data
     *     is given by the provided UserData object.
     */
    public Directory<User> getUserDirectory(UserData userData) {

        // Get own user object
        User self = getUser(userData);

        // Return directory containing only self
        return new SimpleDirectory<User>(Collections.singletonMap(
            self.getIdentifier(),
            self
        ));

    }

    /**
     * Returns the identifiers of all connections readable by the user whose
     * data is given by the provided UserData object. If the provided UserData
     * is not expired, this will be the set of all connection identifiers
     * within the UserData. If the UserData is expired, this will be an empty
     * set.
     *
     * @param userData
     *     All data associated with the user whose accessible connection
     *     identifiers are being retrieved.
     *
     * @return
     *     A set containing the identifiers of all connections readable by the
     *     user whose data is given by the provided UserData object.
     */
    public Set<String> getConnectionIdentifiers(UserData userData) {

        // Do not return any connections if empty or expired
        Map<String, UserData.Connection> connections = userData.getConnections();
        if (connections == null || userData.isExpired())
            return Collections.<String>emptySet();

        // Return all available connection identifiers
        return connections.keySet();

    }

    /**
     * Returns a Directory containing all connections accessible by the user
     * whose data is given by the provided UserData object. If the given
     * UserData object is not expired, this Directory will contain absolutely
     * all connections defined within the given UserData. If the given UserData
     * object is expired, this Directory will be empty.
     *
     * @param userData
     *     All data associated with the user whose connection directory is
     *     being retrieved.
     *
     * @return
     *     A Directory containing all connections accessible by the user whose
     *     data is given by the provided UserData object.
     */
    public Directory<Connection> getConnectionDirectory(UserData userData) {

        // Do not return any connections if empty or expired
        Map<String, UserData.Connection> connections = userData.getConnections();
        if (connections == null || userData.isExpired())
            return new SimpleDirectory<Connection>();

        // Convert UserData.Connection objects to normal Connections
        Map<String, Connection> directoryContents = new HashMap<String, Connection>();
        for (Map.Entry<String, UserData.Connection> entry : connections.entrySet()) {

            // Pull connection and associated identifier
            String identifier = entry.getKey();
            UserData.Connection connection = entry.getValue();

            // Create Guacamole connection containing the defined identifier
            // and parameters
            Connection guacConnection = new UserDataConnection(
                userData,
                identifier,
                connection
            );

            // All connections are within the root group
            guacConnection.setParentIdentifier(ROOT_CONNECTION_GROUP);

            // Add corresponding Connection to directory
            directoryContents.put(identifier, guacConnection);

        }

        return new SimpleDirectory<Connection>(directoryContents);

    }

    /**
     * Returns the identifiers of all connection groups readable by the user
     * whose data is given by the provided UserData object. This will always be
     * a set containing only the root connection group identifier. The
     * JSONAuthenticationProvider does not define any other connection groups.
     *
     * @param userData
     *     All data associated with the user whose accessible connection group
     *     identifiers are being retrieved.
     *
     * @return
     *     A set containing the identifiers of all connection groups readable
     *     by the user whose data is given by the provided UserData object.
     */
    public Set<String> getConnectionGroupIdentifiers(UserData userData) {

        // The only connection group available is the root group
        return Collections.singleton(ROOT_CONNECTION_GROUP);

    }

    /**
     * Returns the root connection group, containing all connections defined
     * within the provided UserData object. If the provided UserData object is
     * expired, this connection group will be empty.
     *
     * @param userData
     *     All data associated with the user whose root connection group is
     *     being retrieved.
     *
     * @return
     *     The root connection group.
     */
    public ConnectionGroup getRootConnectionGroup(UserData userData) {

        // The root group contains all connections and no groups
        return new SimpleConnectionGroup(
            ROOT_CONNECTION_GROUP,
            ROOT_CONNECTION_GROUP,
            getConnectionIdentifiers(userData),
            Collections.<String>emptyList()
        );

    }

    /**
     * Returns a Directory containing all connection groups accessible by the
     * user whose data is given by the provided UserData object. This Directory
     * will always contain only the root connection group.
     *
     * @param userData
     *     All data associated with the user whose connection group directory
     *     is being retrieved.
     *
     * @return
     *     A Directory containing all connection groups accessible by the user
     *     whose data is given by the provided UserData object.
     */
    public Directory<ConnectionGroup> getConnectionGroupDirectory(UserData userData) {

        // Expose only the root group in the connection group directory
        return new SimpleConnectionGroupDirectory(
            Collections.singleton(getRootConnectionGroup(userData))
        );

    }

}
