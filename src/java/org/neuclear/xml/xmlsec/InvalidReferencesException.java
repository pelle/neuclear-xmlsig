package org.neuclear.xml.xmlsec;

/**
 * Created by IntelliJ IDEA.
 * User: pelleb
 * Date: Mar 19, 2004
 * Time: 2:16:55 PM
 * To change this template use File | Settings | File Templates.
 */
public class InvalidReferencesException extends InvalidSignatureException {
    public InvalidReferencesException(int count) {
        super("Invalid reference count: " + count);
    }

    public InvalidReferencesException() {
        super("Invalid reference type");
    }

}
