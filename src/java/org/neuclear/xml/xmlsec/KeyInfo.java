/*
 */
package org.neuclear.xml.xmlsec;

import org.dom4j.Element;
import org.neuclear.commons.crypto.Base64;
import org.neuclear.commons.crypto.CryptoException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public final class KeyInfo extends AbstractXMLSigElement {
    /**
     * Currently only RSA
     * 20030218 Also DSA
     */
    public KeyInfo(final PublicKey pub) {
        super(TAG_NAME);
        this.pub = pub;
        final Element kv = XMLSecTools.createElementInSignatureSpace("KeyValue");
        getElement().add(kv);
        if (pub instanceof RSAPublicKey) {
            final RSAPublicKey rsakey = (RSAPublicKey) pub;
            final Element rsav = XMLSecTools.createElementInSignatureSpace("RSAKeyValue");
            kv.add(rsav);
            final Element mod = XMLSecTools.bigIntToElement("Modulus", rsakey.getModulus());
            rsav.add(mod);
            final Element exp = XMLSecTools.bigIntToElement("Exponent", rsakey.getPublicExponent());
            rsav.add(exp);
        } else if ( pub instanceof DSAPublicKey ) {
        	final DSAPublicKey dsaKey = (DSAPublicKey) pub;
        	final Element dsav = XMLSecTools.createElementInSignatureSpace("DSAKeyValue");
        	kv.add(dsav);
      		final DSAParams dsaParams = dsaKey.getParams();
        	final Element p = XMLSecTools.bigIntToElement("P", dsaParams.getP());
        	dsav.add(p); //optional and tied to Q
        	final Element q = XMLSecTools.bigIntToElement("Q", dsaParams.getQ());
        	dsav.add(q); //optional and tied to P
        	final Element g = XMLSecTools.bigIntToElement("G", dsaParams.getG());
        	dsav.add(g); //optional
        	final Element y = XMLSecTools.bigIntToElement("Y", dsaKey.getY());
        	dsav.add(y);
        	//J = (P-1) / Q
        	//seed and pgenCounter
        }
    }

    public KeyInfo(final Element elem) throws XMLSecurityException {
        super(elem);
        if (!elem.getQName().equals(getQName()))
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not a valid: " + XMLSecTools.NS_DS.getPrefix() + ":" + TAG_NAME);
    }

  /**
   * Method getPublicKey
   *
   * @return
   * @throws XMLSecurityException
   */
	public final PublicKey getPublicKey()
		throws XMLSecurityException,CryptoException
	{
		if ( pub == null ) {
			try {
				final KeyFactory keyFactory;
				
				final Element kvElement = getElement().element(XMLSecTools.createQName("KeyValue"));
				if ( kvElement == null )
					throw new XMLSecurityException("KeyInfo doesn't contains a KeyValue element.");
					
				Element algElement = kvElement.element(XMLSecTools.createQName("RSAKeyValue"));
				if ( algElement == null ) {
					algElement = kvElement.element(XMLSecTools.createQName("DSAKeyValue"));
					if ( algElement == null )
						throw new XMLSecurityException("KeyInfo doesn't contains a [DSA|RSA]KeyValue element. "+
							"Sorry, we currently only support RSA and DSA keys");
				}
				
				if ( algElement.getName().equalsIgnoreCase("RSAKeyValue") ) {
					keyFactory = KeyFactory.getInstance("RSA");
					final Element mod = algElement.element(XMLSecTools.createQName("Modulus"));
					final Element exp = algElement.element(XMLSecTools.createQName("Exponent"));
					if ((mod == null) || (exp == null))
						throw new XMLSecurityException("KeyInfo Didn't contain a valid RSA Key");
					final RSAPublicKeySpec rsaKeyspec =
							new RSAPublicKeySpec(XMLSecTools.decodeBigIntegerFromElement(mod), XMLSecTools.decodeBigIntegerFromElement(exp));
					final PublicKey pk = keyFactory.generatePublic(rsaKeyspec);

					pub = pk;
				} else if ( algElement.getName().equalsIgnoreCase("DSAKeyValue") ) {
					keyFactory = KeyFactory.getInstance("DSA");
					final Element p = algElement.element(XMLSecTools.createQName("P"));
					final Element q = algElement.element(XMLSecTools.createQName("Q"));
					final Element g = algElement.element(XMLSecTools.createQName("G"));
					final Element y = algElement.element(XMLSecTools.createQName("Y"));
					if ( p == null || q == null || g == null || y == null )
						throw new XMLSecurityException("KeyInfo didn't contain a valid DSA Key");
					final DSAPublicKeySpec dsaPublicKeySpec = new DSAPublicKeySpec(XMLSecTools.decodeBigIntegerFromElement(y),
																																	XMLSecTools.decodeBigIntegerFromElement(p),
																																	XMLSecTools.decodeBigIntegerFromElement(q),
																																	XMLSecTools.decodeBigIntegerFromElement(g));
					final PublicKey pk = keyFactory.generatePublic(dsaPublicKeySpec);
					
					pub = pk;
				}
			} catch (NoSuchAlgorithmException ex) {
				XMLSecTools.rethrowException(ex);
			} catch (InvalidKeySpecException ex) {
				XMLSecTools.rethrowException(ex);
			}
		}
		return pub;
	}
	
    public final String getTagName() {
        return TAG_NAME;
    }

    private static final String TAG_NAME = "KeyInfo";
    private PublicKey pub;
}
