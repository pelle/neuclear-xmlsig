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
    public InvalidSignatureException(byte a[],byte b[]) {
        super("Digest: '"+a+"' not equal to: "+b);
    }
    public InvalidSignatureException(PublicKey pub){
        super("Publick Key: "+pub.toString()+ " didnt sign this signature");
    }
}