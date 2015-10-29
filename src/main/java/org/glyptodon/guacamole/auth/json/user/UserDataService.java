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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.ConnectionGroup;
import org.glyptodon.guacamole.net.auth.Directory;
import org.glyptodon.guacamole.net.auth.User;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnection;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroup;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroupDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleUser;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;

/**
 * Service for deriving Guacamole extension API data from UserData objects.
 *
 * @author Michael Jumper
 */
public class UserDataService {

    /**
     * The identifier reserved for the root connection group.
     */
    public static final String ROOT_CONNECTION_GROUP = "ROOT";

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

            // Create new configuration for given protocol
            GuacamoleConfiguration config = new GuacamoleConfiguration();
            config.setProtocol(connection.getProtocol());

            // Add all parameter name/value pairs
            Map<String, String> parameters = connection.getParameters();
            if (parameters != null)
                config.setParameters(parameters);

            // Add corresponding Connection to directory
            directoryContents.put(identifier, new SimpleConnection(
                identifier,
                identifier,
                config
            ));

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
