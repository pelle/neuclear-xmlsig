package org.neuclear.xml.xmlsec;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Feb 8, 2003
 * Time: 12:15:24 PM
 * $Id: QuickEmbeddedSignature.java,v 1.1 2003/11/11 16:33:28 pelle Exp $
 * $Log: QuickEmbeddedSignature.java,v $
 * Revision 1.1  2003/11/11 16:33:28  pelle
 * Initial revision
 *
 * Revision 1.12  2003/11/08 22:21:17  pelle
 * Fixed a few things with regards to the SOAPTools class.
 *
 * Revision 1.11  2003/11/08 20:27:02  pelle
 * Updated the Signer interface to return a key type to be used for XML SignatureInfo. Thus we now support DSA sigs yet again.
 *
 * Revision 1.10  2003/10/29 21:15:53  pelle
 * Refactored the whole signing process. Now we have an interface called Signer which is the old SignerStore.
 * To use it you pass a byte array and an alias. The sign method then returns the signature.
 * If a Signer needs a passphrase it uses a PassPhraseAgent to present a dialogue box, read it from a command line etc.
 * This new Signer pattern allows us to use secure signing hardware such as N-Cipher in the future for server applications as well
 * as SmartCards for end user applications.
 *
 * Revision 1.9  2003/02/24 03:26:30  pelle
 * XMLSignature class has been tested as working for Enveloped Signatures.
 * It is still failing verification on home grown Enveloping Signatures.
 * It failes while checking reference validity. This means there is something strange about the Digest is initially
 * calculated for Enveloping signatures.
 *
 * Revision 1.8  2003/02/24 00:41:07  pelle
 * Cleaned up a lot of code for new fixed processing model.
 * It all still work as before, but will be easier to modify the Reference processing model which is the only
 * main thing todo besides X509 and HMAC-SHA1 support.
 *
 * Revision 1.7  2003/02/23 23:21:46  pelle
 * Yeah. We figured it out. We now have interop.
 * Granted not on all features as yet, but definitely on simple signatures.
 * I'm checking in Ramses' fix to QuickEmbeddedSignature and my fixes to the verification process.
 *
 * Revision 1.6  2003/02/22 16:54:30  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.5  2003/02/20 13:26:42  pelle
 * Adding all of the modification from Rams?s Morales ramses@computer.org to support DSASHA1 Signatures
 * Thanks Rams?s good work.
 * So this means there is now support for:
 * - DSA KeyInfo blocks
 * - DSA Key Generation within CryptoTools
 * - Signing using DSASHA1
 *
 * Revision 1.4  2003/02/11 14:50:24  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 *
 * Revision 1.3  2003/02/08 20:55:08  pelle
 * Some documentation changes.
 * Major reorganization of code. The code is slowly being cleaned up in such a way that we can
 * get rid of the org.neuclear.utils package and split out the org.neuclear.xml.soap package.
 * Got rid of tons of unnecessary dependencies.
 *
 * Revision 1.2  2003/02/08 19:11:10  pelle
 * Cleaned stuff up a bit.
 *
 * Revision 1.1  2003/02/08 18:48:37  pelle
 * The Signature phase has been rewritten.
 * There now is a new Class called QuickEmbeddedSignature which is more in line with my original idea for this library.
 * It simply has a template of the xml and signs it in a standard way.
 * The original XMLSignature class is still used for verification and will in the future handle more thoroughly
 * all the various flavours of XMLSig.
 * XMLSecTools has got different flavours of canonicalize now. Including one where you can pass it a Canonicaliser to use.
 * Of the new Canonicalizer's are CanonicalizerWithComments, which I accidently left out of the last commit.
 * And CanonicalizerWithoutSignature which leaves out the Signature in the Canonicalization phase and is thus
 * a lot more efficient than the previous approach.
 *
 */

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.neuclear.commons.crypto.Base64;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.commons.crypto.Signer;
import org.neuclear.commons.crypto.CryptoException;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

/**
 * This a class to quickly create NeuDist format standard signatures
 */
public class QuickEmbeddedSignature extends XMLSignature {
    public QuickEmbeddedSignature(KeyPair keypair, Element root, String uri) throws XMLSecurityException, CryptoException {
        this(keypair.getPrivate(), root, uri);
        Element sig = getElement();
        KeyInfo key = new KeyInfo(keypair.getPublic());
        sig.add(key.getElement());
    }

    public QuickEmbeddedSignature(PrivateKey key, Element root, String uri) throws XMLSecurityException, CryptoException {
        super(getSignatureElement(root, key));
        Element sig = getElement();

        getSi().getReference().setDigest();

        byte[] canonicalizedSignedInfo = XMLSecTools.canonicalize(sig.element("SignedInfo"));
        sig.add(XMLSecTools.base64ToElement("SignatureValue", CryptoTools.sign(key, canonicalizedSignedInfo)));
    }

    public QuickEmbeddedSignature(String name, Signer signer, Element root, String uri) throws XMLSecurityException, CryptoException {
        super(getSignatureElement(root,signer.getKeyType(name)));
        Element sig = getElement();

        getSi().getReference().setDigest();

        byte[] canonicalizedSignedInfo = XMLSecTools.canonicalize(sig.element("SignedInfo"));
        sig.add(XMLSecTools.base64ToElement("SignatureValue", signer.sign(name, canonicalizedSignedInfo)));
    }


    private synchronized static Element getRSASigElement(Element root) throws DocumentException {
        if (SIGNATURETEMPLATE == null)
            SIGNATURETEMPLATE = DocumentHelper.parseText(SIGNATURETEMPLATE_TEXT).getRootElement();
        Element sig = SIGNATURETEMPLATE.createCopy();
        root.add(sig);
        return sig;
    }

    //overloading, because maybe there is another class calling the original static method
    private static Element getSignatureElement(Element root, PrivateKey key) throws XMLSecurityException {
        if (key instanceof RSAPrivateKey)
            return getSignatureElement(root,SignatureInfo.SIG_ALG_RSA);
        if (key instanceof DSAPrivateKey)
            return getSignatureElement(root,SignatureInfo.SIG_ALG_DSA);
        return null;
    }
    //overloading, because maybe there is another class calling the original static method
    private static Element getSignatureElement(Element root, int keytype) throws XMLSecurityException {
        Element signatureElement = null;
        try {
            if (keytype == SignatureInfo.SIG_ALG_DSA)
                return getRSASigElement(root);
            if (keytype == SignatureInfo.SIG_ALG_DSA)
                return getDSASigElement(root);
            return null;

        } catch (DocumentException e) {
            throw new XMLSecurityException(e);
        }
    }

    private synchronized static Element getDSASigElement(Element root) throws DocumentException {
        Element signatureElement;
        if (DSASIGNATURETEMPLATE == null)
            DSASIGNATURETEMPLATE =
                    DocumentHelper.parseText(DSASIGNATURETEMPLATE_TEXT).getRootElement();
        signatureElement = DSASIGNATURETEMPLATE.createCopy();
        root.add(signatureElement);
        return signatureElement;
    }

    private static Element SIGNATURETEMPLATE;
    private static String SIGNATURETEMPLATE_TEXT = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
            "<ds:SignedInfo>" +
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>" +
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>" +
            "<ds:Reference URI=\"\">" +
            "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" +
            "</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
            "</ds:Reference>" +
            "</ds:SignedInfo></ds:Signature>";

    private static Element DSASIGNATURETEMPLATE;
    private static String DSASIGNATURETEMPLATE_TEXT = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
            "<ds:SignedInfo>" +
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>" +
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#dsa-sha1\"/>" +
            "<ds:Reference URI=\"\">" +
            "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" +
            "</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
            "</ds:Reference>" +
            "</ds:SignedInfo></ds:Signature>";


    public static void main(String args[]) {
        try {
            KeyPair kp = CryptoTools.createKeyPair();
//            KeyInfo keyinfo=new KeyInfo(kp.getPublic());
            Document doc = DocumentHelper.parseText("<test>One Two<test2/></test>");
            XMLSignature xmlsig = new QuickEmbeddedSignature(kp, doc.getRootElement(), "uri:test");
            doc.getRootElement().add(xmlsig.getElement());
            System.out.println(doc.asXML());
            System.out.println("Starting benchmarks");
            long start = new Date().getTime();
            for (int i = 0; i < 1000; i++) {
                doc = DocumentHelper.parseText("<test>One Two<test2/></test>");
                XMLSecTools.signElement("uri:test", doc.getRootElement(), kp.getPrivate());
            }
            long end = new Date().getTime();
            System.out.println("1000 signatures took " + (end - start) + "ms or " + (end - start) / 1000 + "ms per signature");
            String signed = doc.asXML();
            start = new Date().getTime();
            for (int i = 0; i < 1000; i++) {
                doc = DocumentHelper.parseText(signed);
                XMLSecTools.verifySignature(doc.getRootElement(), kp.getPublic());
            }
            end = new Date().getTime();
            System.out.println("1000 verifies took " + (end - start) + "ms or " + (end - start) / 1000 + "ms per signature");
        } catch (DocumentException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (XMLSecurityException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (CryptoException e) {
            e.printStackTrace();  //TODO Handle exception
        }

    }
}
