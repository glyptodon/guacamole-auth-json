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

package org.glyptodon.guacamole.auth.json;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleServerException;
import org.glyptodon.guacamole.properties.GuacamoleProperty;

/**
 * A GuacamoleProperty whose value is a SecretKey. The key will be generated
 * using the AES key generation algorithm from the decoded bytes of the hex-
 * encoded value of the property.
 *
 * @author Michael Jumper
 */
public abstract class SecretKeyProperty implements GuacamoleProperty<SecretKey> {

    /**
     * The name of the key generation algorithm used by this property.
     */
    public static final String KEY_ALGORITHM = "AES";

    @Override
    public SecretKey parseValue(String value) throws GuacamoleException {

        // If no property provided, return null.
        if (value == null)
            return null;

        try {

            // Read value as hex
            byte[] keyBytes = DatatypeConverter.parseHexBinary(value);

            // Return parsed key
            return new SecretKeySpec(keyBytes, KEY_ALGORITHM);

        }

        // Fail parse if hex invalid
        catch (IllegalArgumentException e) {
            throw new GuacamoleServerException("Invalid hexadecimal value for key.", e);
        }

    }

}
