package org.neuclear.xml.xmlsec;

import org.neuclear.commons.crypto.Base64;

import java.security.PublicKey;

/**
 * Created by IntelliJ IDEA.
 * User: pelleb
 * Date: Jan 13, 2004
 * Time: 8:53:09 PM
 * To change this template use Options | File Templates.
 */
public class InvalidSignatureException extends Exception {
    public InvalidSignatureException(byte[] a, byte[] b) {
        super("Digest: '" + Base64.encode(a) + "' not equal to: " + Base64.encode(b));
    }

    public InvalidSignatureException(PublicKey pub) {
        super("Public Key: " + pub.toString() + " didnt sign this signature");
    }

    protected InvalidSignatureException(String title) {
        super(title);
    }
}
