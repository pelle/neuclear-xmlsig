/*
 */
package org.neuclear.xml.xmlsec;

import org.dom4j.Element;
import org.neuclear.commons.crypto.Base64;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.commons.crypto.keyresolvers.KeyResolverFactory;
import org.neuclear.commons.crypto.signers.SetPublicKeyCallBack;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Iterator;

public final class KeyInfo extends AbstractXMLSigElement {
    /**
     * Currently only RSA
     * 20030218 Also DSA
     */
    public KeyInfo(final PublicKey pub) {
        super(TAG_NAME);
        this.pub = pub;
        final Element kv = XMLSecTools.createElementInSignatureSpace("KeyValue");
        addElement(kv);
        if (pub instanceof RSAPublicKey) {
            final RSAPublicKey rsakey = (RSAPublicKey) pub;
            final Element rsav = XMLSecTools.createElementInSignatureSpace("RSAKeyValue");
            kv.add(rsav);
            kv.addText("\n");
            final Element mod = XMLSecTools.bigIntToElement("Modulus", rsakey.getModulus());
            rsav.add(mod);
            rsav.addText("\n");
            final Element exp = XMLSecTools.bigIntToElement("Exponent", rsakey.getPublicExponent());
            rsav.add(exp);
            rsav.addText("\n");
        } else if (pub instanceof DSAPublicKey) {
            final DSAPublicKey dsaKey = (DSAPublicKey) pub;
            final Element dsav = XMLSecTools.createElementInSignatureSpace("DSAKeyValue");
            kv.add(dsav);
            kv.addText("\n");
            final DSAParams dsaParams = dsaKey.getParams();
            final Element p = XMLSecTools.bigIntToElement("P", dsaParams.getP());
            dsav.add(p); //optional and tied to Q
            dsav.addText("\n");
            final Element q = XMLSecTools.bigIntToElement("Q", dsaParams.getQ());
            dsav.add(q); //optional and tied to P
            dsav.addText("\n");
            final Element g = XMLSecTools.bigIntToElement("G", dsaParams.getG());
            dsav.add(g); //optional
            dsav.addText("\n");
            final Element y = XMLSecTools.bigIntToElement("Y", dsaKey.getY());
            dsav.add(y);
            dsav.addText("\n");
            //J = (P-1) / Q
            //seed and pgenCounter
        }
    }

    public KeyInfo(final PublicKey pub, final String name) {
        this(pub);
        appendKeyName(name);
    }

    public KeyInfo(final String name) {
        super(TAG_NAME);
        appendKeyName(name);
    }

    private void appendKeyName(final String name) {
        final Element kv = XMLSecTools.createElementInSignatureSpace("KeyName");
        kv.addText(name);
        addElement(kv);
    }

    public KeyInfo(final X509Certificate cert) throws CertificateEncodingException {
        super(TAG_NAME);
        final Element kv = XMLSecTools.createElementInSignatureSpace("X509Data");
        kv.add(XMLSecTools.base64ToElement("X509Certificate", cert.getEncoded()));
        addElement(kv);
    }

    public KeyInfo(final Element elem) throws XMLSecurityException {
        super(elem);
        if (!elem.getQName().equals(XMLSecTools.createQName(TAG_NAME)))
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not a valid: " + XMLSecTools.NS_DS.getPrefix() + ":" + TAG_NAME);
    }

    /**
     * Method getPublicKey
     *
     * @return
     * @throws XMLSecurityException
     */
    public final String getKeyName()
            throws XMLSecurityException {
        if (pub == null) {
            Iterator iter = getElement().elementIterator();
            while (iter.hasNext() && pub == null) {
                Element element = (Element) iter.next();
                if (element.getName().equals("KeyName"))
                    return element.getTextTrim();
                else if (element.getName().equals("X509Data"))
                    return "x509v3:" + Base64.encode(extractX509(element).getSerialNumber());
                if (element.getName().equals("KeyValue"))
                    return "sha1:" + Base64.encode(CryptoTools.digest(parseKeyValue(element).getEncoded()));
            }
        }
        return null;
    }

    /**
     * Method getPublicKey
     * 
     * @return 
     * @throws XMLSecurityException 
     */
    public final PublicKey getPublicKey()
            throws XMLSecurityException {
        if (pub == null) {
            Iterator iter = getElement().elementIterator();
            while (iter.hasNext() && pub == null) {
                Element element = (Element) iter.next();
                if (element.getName().equals("KeyValue"))
                    pub = parseKeyValue(element);
                else if (element.getName().equals("KeyName"))
                    pub = parseKeyName(element);
                else if (element.getName().equals("X509Data"))
                    pub = parseX509(element);
            }
        }
        return pub;
    }

    private PublicKey parseKeyName(final Element element) {
        final String name = element.getTextTrim();
        return KeyResolverFactory.getInstance().resolve(name);
    }

    private PublicKey parseX509(final Element element) throws XMLSecurityException {
        return extractX509(element).getPublicKey();
    }

    private X509Certificate extractX509(final Element element) throws XMLSecurityException {
        Element x509Data = element.element("X509Certificate");
        if (x509Data != null) {
            try {
                byte encoded[] = XMLSecTools.decodeBase64Element(x509Data);
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(encoded));
                return cert;
            } catch (CertificateException e) {
                throw new XMLSecurityException(e);

            }
        }
        throw new XMLSecurityException("No X509Certificate included");
    }

    private PublicKey parseKeyValue(final Element kvElement) throws XMLSecurityException {
        try {
            final KeyFactory keyFactory;

            Element algElement = kvElement.element(XMLSecTools.createQName("RSAKeyValue"));
            if (algElement == null) {
                algElement = kvElement.element(XMLSecTools.createQName("DSAKeyValue"));
                if (algElement == null)
                    throw new XMLSecurityException("KeyInfo doesn't contains a [DSA|RSA]KeyValue element. " +
                            "Sorry, we currently only support RSA and DSA keys");
            }

            if (algElement.getName().equalsIgnoreCase("RSAKeyValue")) {
                keyFactory = KeyFactory.getInstance("RSA");
                final Element mod = algElement.element(XMLSecTools.createQName("Modulus"));
                final Element exp = algElement.element(XMLSecTools.createQName("Exponent"));
                if ((mod == null) || (exp == null))
                    throw new XMLSecurityException("KeyInfo Didn't contain a valid RSA Key");
                final RSAPublicKeySpec rsaKeyspec =
                        new RSAPublicKeySpec(XMLSecTools.decodeBigIntegerFromElement(mod), XMLSecTools.decodeBigIntegerFromElement(exp));
                final PublicKey pk = keyFactory.generatePublic(rsaKeyspec);

                return pk;
            } else if (algElement.getName().equalsIgnoreCase("DSAKeyValue")) {
                keyFactory = KeyFactory.getInstance("DSA");
                final Element p = algElement.element(XMLSecTools.createQName("P"));
                final Element q = algElement.element(XMLSecTools.createQName("Q"));
                final Element g = algElement.element(XMLSecTools.createQName("G"));
                final Element y = algElement.element(XMLSecTools.createQName("Y"));
                if (p == null || q == null || g == null || y == null)
                    throw new XMLSecurityException("KeyInfo didn't contain a valid DSA Key");
                final DSAPublicKeySpec dsaPublicKeySpec = new DSAPublicKeySpec(XMLSecTools.decodeBigIntegerFromElement(y),
                        XMLSecTools.decodeBigIntegerFromElement(p),
                        XMLSecTools.decodeBigIntegerFromElement(q),
                        XMLSecTools.decodeBigIntegerFromElement(g));
                return keyFactory.generatePublic(dsaPublicKeySpec);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new XMLSecurityException(ex);
        } catch (InvalidKeySpecException ex) {
            throw new XMLSecurityException(ex);
        }
        return null;
    }

    public static class CreateKeyInfoCallBack implements SetPublicKeyCallBack {
        private PublicKey pub;

        public void setPublicKey(PublicKey pub) {
            this.pub = pub;
        }

        public KeyInfo createKeyInfo() {
            return new KeyInfo(pub);
        }

    }

    private static final String TAG_NAME = "KeyInfo";
    private PublicKey pub;
}
