package org.neuclear.xml.xmlsec;

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
        super("Digest: '" + new String(a) + "' not equal to: " + new String(b));
    }

    public InvalidSignatureException(PublicKey pub) {
        super("Public Key: " + pub.toString() + " didnt sign this signature");
    }

    protected InvalidSignatureException(String title) {
        super(title);
    }
}
