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

import java.util.Map;
import org.codehaus.jackson.annotate.JsonIgnore;

/**
 * All data associated with a particular user, as parsed from the JSON supplied
 * within the encrypted blob provided during authentication.
 *
 * @author Michael Jumper
 */
public class UserData {

    /**
     * The username of the user associated with this data.
     */
    private String username;

    /**
     * The time after which this data is no longer valid and must not be used.
     * This is a UNIX-style epoch timestamp, stored as the number of
     * milliseconds since midnight of January 1, 1970 UTC.
     */
    private Long expires;

    /**
     * All connections accessible by this user. The key of each entry is both
     * the connection identifier and the connection name.
     */
    private Map<String, Connection> connections;

    /**
     * The data associated with a Guacamole connection stored within a UserData
     * object.
     *
     * @author Michael Jumper
     */
    public static class Connection {

        /**
         * The protocol that this connection should use, such as "vnc" or "rdp".
         */
        private String protocol;

        /**
         * Map of all connection parameter values, where each key is the parameter
         * name. Legal parameter names are dictated by the specified protocol and
         * are documented within the Guacamole manual:
         *
         * http://guac-dev.org/doc/gug/configuring-guacamole.html#connection-configuration
         */
        private Map<String, String> parameters;

        /**
         * Returns the protocol that this connection should use, such as "vnc"
         * or "rdp".
         *
         * @return
         *     The name of the protocol to use, such as "vnc" or "rdp".
         */
        public String getProtocol() {
            return protocol;
        }

        /**
         * Sets the protocol that this connection should use, such as "vnc"
         * or "rdp".
         *
         * @param protocol
         *     The name of the protocol to use, such as "vnc" or "rdp".
         */
        public void setProtocol(String protocol) {
            this.protocol = protocol;
        }

        /**
         * Returns a map of all parameter name/value pairs, where the key of
         * each entry in the map is the corresponding parameter name. Changes
         * to this map directly affect the parameters associated with this
         * connection.
         *
         * @return
         *     A map of all parameter name/value pairs associated with this
         *     connection.
         */
        public Map<String, String> getParameters() {
            return parameters;
        }

        /**
         * Replaces all parameters associated with this connection with the
         * name/value pairs in the provided map, where the key of each entry
         * in the map is the corresponding parameter name. Changes to this map
         * directly affect the parameters associated with this connection.
         *
         * @param parameters
         *     The map of all parameter name/value pairs to associate with this
         *     connection.
         */
        public void setParameters(Map<String, String> parameters) {
            this.parameters = parameters;
        }

    }

    /**
     * Returns the username of the user associated with the data stored in this
     * object.
     *
     * @return
     *     The username of the user associated with the data stored in this
     *     object.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username of the user associated with the data stored in this
     * object.
     *
     * @param username
     *     The username of the user to associate with the data stored in this
     *     object.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the time after which the data stored in this object is invalid
     * and must not be used. The time returned is a UNIX-style epoch timestamp
     * whose value is the number of milliseconds since midnight of January 1,
     * 1970 UTC. If this object does not expire, null is returned.
     *
     * @return
     *     The time after which the data stored in this object is invalid and
     *     must not be used, or null if this object does not expire.
     */
    public Long getExpires() {
        return expires;
    }

    /**
     * Sets the time after which the data stored in this object is invalid
     * and must not be used. The time provided MUST be a UNIX-style epoch
     * timestamp whose value is the number of milliseconds since midnight of
     * January 1, 1970 UTC. If this object should not expire, the value
     * provided should be null.
     *
     * @param expires
     *     The time after which the data stored in this object is invalid and
     *     must not be used, or null if this object does not expire.
     */
    public void setExpires(Long expires) {
        this.expires = expires;
    }

    /**
     * Returns all connections stored within this UserData object. Each of
     * these connections is accessible by the user specified by getUsername().
     * The key of each entry within the map is the identifier and human-readable
     * name of the corresponding connection.
     *
     * @return
     *     A map of all connections stored within this UserData object, where
     *     the key of each entry is the identifier of the corresponding
     *     connection.
     */
    public Map<String, Connection> getConnections() {
        return connections;
    }

    /**
     * Replaces all connections stored within this UserData object with the
     * given connections. Each of these connections will be accessible by the
     * user specified by getUsername(). The key of each entry within the map is
     * the identifier and human-readable name of the corresponding connection.
     *
     * @param connections
     *     A map of all connections to be stored within this UserData object,
     *     where the key of each entry is the identifier of the corresponding
     *     connection.
     */
    public void setConnections(Map<String, Connection> connections) {
        this.connections = connections;
    }

    /**
     * Returns whether the data within this UserData object is expired, and
     * thus must not be used, according to the timestamp returned by
     * getExpires().
     *
     * @return
     *     true if the data within this UserData object is expired and must not
     *     be used, false otherwise.
     */
    @JsonIgnore
    public boolean isExpired() {

        // Do not bother comparing if this UserData object does not expire
        Long expirationTimestamp = getExpires();
        if (expirationTimestamp == null)
            return false;

        // Otherwise, compare expiration timestamp against system time
        return System.currentTimeMillis() > expirationTimestamp;

    }

}
