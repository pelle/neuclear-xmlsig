/* $Id: XMLSecTools.java,v 1.4 2003/11/21 04:44:31 pelle Exp $
 * $Log: XMLSecTools.java,v $
 * Revision 1.4  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.3  2003/11/15 01:57:42  pelle
 * More work all around on web applications.
 *
 * Revision 1.2  2003/11/11 21:18:08  pelle
 * Further vital reshuffling.
 * org.neudist.crypto.* and org.neudist.utils.* have been moved to respective areas under org.neuclear.commons
 * org.neuclear.signers.* as well as org.neuclear.passphraseagents have been moved under org.neuclear.commons.crypto as well.
 * Did a bit of work on the Canonicalizer and changed a few other minor bits.
 *
 * Revision 1.1.1.1  2003/11/11 16:33:30  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.14  2003/11/09 03:27:09  pelle
 * More house keeping and shuffling about mainly pay
 *
 * Revision 1.13  2003/10/29 21:15:53  pelle
 * Refactored the whole signing process. Now we have an interface called Signer which is the old SignerStore.
 * To use it you pass a byte array and an alias. The sign method then returns the signature.
 * If a Signer needs a passphrase it uses a PassPhraseAgent to present a dialogue box, read it from a command line etc.
 * This new Signer pattern allows us to use secure signing hardware such as N-Cipher in the future for server applications as well
 * as SmartCards for end user applications.
 *
 * Revision 1.12  2003/09/26 23:52:47  pelle
 * Changes mainly in receiver and related fun.
 * First real neuclear stuff in the payment package. Added TransferContract and AssetControllerReceiver.
 *
 * Revision 1.11  2003/02/24 13:32:24  pelle
 * Final doc changes for 0.8
 *
 * Revision 1.10  2003/02/24 03:26:30  pelle
 * XMLSignature class has been tested as working for Enveloped Signatures.
 * It is still failing verification on home grown Enveloping Signatures.
 * It failes while checking reference validity. This means there is something strange about the Digest is initially
 * calculated for Enveloping signatures.
 *
 * Revision 1.9  2003/02/22 16:54:30  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.8  2003/02/21 22:48:16  pelle
 * New Test Infrastructure
 * Added test keys in src/testdata/keys
 * Modified tools to handle these keys
 *
 * Revision 1.7  2003/02/20 13:26:42  pelle
 * Adding all of the modification from Rams?s Morales ramses@computer.org to support DSASHA1 Signatures
 * Thanks Rams?s good work.
 * So this means there is now support for:
 * - DSA KeyInfo blocks
 * - DSA Key Generation within CryptoTools
 * - Signing using DSASHA1
 *
 * Revision 1.6  2003/02/11 14:50:24  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 *
 * Revision 1.5  2003/02/08 20:55:08  pelle
 * Some documentation changes.
 * Major reorganization of code. The code is slowly being cleaned up in such a way that we can
 * get rid of the org.neuclear.utils package and split out the org.neuclear.xml.soap package.
 * Got rid of tons of unnecessary dependencies.
 *
 * Revision 1.4  2003/02/08 18:48:37  pelle
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
 * Revision 1.3  2003/02/07 21:15:17  pelle
 * Much improved Canonicalizer and Test Suite.
 * I've added the merlin-xmldsig-eight Canonicalization test suite.
 * All tests still dont work.
 *
 * Revision 1.2  2003/01/21 03:14:11  pelle
 * Mainly clean ups through out and further documentation.
 *
 * Revision 1.1  2003/01/18 18:12:32  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.7  2003/01/16 19:16:09  pelle
 * Major Structural Changes.
 * We've split the test classes out of the normal source tree, to enable Maven's test support to work.
 * WARNING
 * for Development purposes the code does not as of this commit until otherwise notified actually verifysigs.
 * We are reworking the XMLSig library and need to continue work elsewhere for the time being.
 * DO NOT USE THIS FOR REAL APPS
 *
 * Revision 1.6  2002/12/17 21:41:04  pelle
 * First part of refactoring of SignedNamedObject and SignedObject Interface/Class parings.
 *
 * Revision 1.5  2002/12/17 20:34:44  pelle
 * Lots of changes to core functionality.
 * First of all I've refactored most of the Resolving and verification code. I have a few more things to do
 * on it before I'm happy.
 * There is now a NSResolver class, which handles all the namespace resolution. I took most of the functionality
 * for this out of SignedNamedObject.
 * Then there is the veriifer, which verifies a given SignedNamedObject using the NSResolver.
 * This has simplified the SignedNamedObject classes drastically, leaving them as mainly data objects, which is what they
 * should be.
 * I have also gone around and tightened up security on many different classes, making clases and/or methods final where appropriate.
 * NSCache now operates using http://www.waterken.com's fantastic ADT collections library.
 * Something important has been added, which is a SignRequest named object. This signed object, embeds an unsigned
 * named object for signing by an end users' signing service.
 * Now were almost ready to start seriously implementing AssetIssuers and Transfers, which will be the most important
 * part of the framework.
 *
 * Revision 1.4  2002/12/04 13:52:48  pelle
 * Biggest change is a fix to the Canonicalization Writer It should be a lot more compliant with C14N now.
 * I think the only thing left to do is to sort the element attributes.
 *
 * Revision 1.3  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.xmlsec;

/**
 * @author pelleb
 * @version $Revision: 1.4 $
 */

import org.dom4j.*;
import org.dom4j.io.XMLWriter;
import org.neuclear.commons.crypto.Base64;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.c14.Canonicalizer;
import org.neuclear.xml.c14.CanonicalizerWithoutSignature;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Iterator;
import java.util.StringTokenizer;

/**
 * Tools for dealing with XMLSig's.<p>
 * Usage:<pre>
 * KeyPair kp = ..... // Get RSA Key Pair
 * Element someElement = ..... // Get Dom4j Element somehow
 * XMLSecTools.signElement("uri:helloworld",someElement,kp);
 * <p/>
 * if (XMLSecTools.verifySignature(someElement,kp.getPublicKey())) // Do something
 * </pre>
 * In addition there are handy methods for dealing with KeyInfo elements for generating Key's from xml.
 */
public final class XMLSecTools {
    public static final String XMLDSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";
    public static final Namespace NS_DS = DocumentHelper.createNamespace("ds", XMLDSIG_NAMESPACE);


    /**
     * Signs an element with a given keypair and envelopes the signature within.
     * 
     * @param baseURI Unique ID of the Element to be signed
     * @param root    Element to be signed
     * @param keypair RSA/DSA KeyPair
     * @throws XMLSecurityException 
     */
    public static XMLSignature signElement(final String baseURI, final Element root, final KeyPair keypair) throws XMLSecurityException, CryptoException {//, KeyStoreException {
        final XMLSignature sig = new QuickEmbeddedSignature(keypair, root, baseURI);
        return sig;
    }

    /**
     * Signs an element with a given Private Key and "Envelopes" the signature within.
     * 
     * @param baseURI Unique ID of the Element to be signed
     * @param root    Element to be signed
     * @param key     RSA Private Key
     * @throws XMLSecurityException 
     */
    public static XMLSignature signElement(final String baseURI, final Element root, final PrivateKey key) throws XMLSecurityException, CryptoException {//, KeyStoreException {
        final XMLSignature sig = new QuickEmbeddedSignature(key, root, baseURI);
        return sig;
    }

    /**
     * Signs an element with a given Private Key and "Envelopes" the signature within.
     * 
     * @param baseURI Unique ID of the Element to be signed
     * @param root    Element to be signed
     * @param name    Alias of key to be used for signing
     * @param signer  NeuClear Signer
     * @throws XMLSecurityException 
     */
    public static XMLSignature signElement(final String baseURI, final Element root, final String name, final org.neuclear.commons.crypto.signers.Signer signer) throws XMLSecurityException, CryptoException {//, KeyStoreException {
        final XMLSignature sig = new QuickEmbeddedSignature(name, signer, root, baseURI);
        return sig;
    }

    /**
     * Signs an element with a given keypair and embeds the element within the Signature.
     * 
     * @param baseURI Unique ID of the Element to be signed
     * @param root    Element to be signed
     * @param keypair RSA/DSA KeyPair
     * @throws XMLSecurityException 
     */
    public static XMLSignature signElementEnveloping(final String baseURI, final Element root, final KeyPair keypair) throws XMLSecurityException, CryptoException {//, KeyStoreException {
        final XMLSignature sig = new XMLSignature(keypair, root, baseURI, Reference.XMLSIGTYPE_ENVELOPING);
        return sig;
    }

    /**
     * Signs an element with a given Private Key and embeds the element within the Signature.
     * 
     * @param baseURI Unique ID of the Element to be signed
     * @param root    Element to be signed
     * @param key     RSA Private Key
     * @throws XMLSecurityException 
     */
    public static XMLSignature signElementEnveloping(final String baseURI, final Element root, final PrivateKey key) throws XMLSecurityException, CryptoException {//, KeyStoreException {
        final XMLSignature sig = new XMLSignature(key, null, root, baseURI, Reference.XMLSIGTYPE_ENVELOPING);
        return sig;
    }

    /**
     * Creates a KeyInfo Element containing the public key of a key stored in the given keystore.
     * 
     * @param ks KeyStore to use
     * @param s  Identifier of Key
     * @return Element containg valid KeyInfo
     * @throws KeyStoreException 
     */
    public static Element createKeyInfo(final KeyStore ks, final String s) throws KeyStoreException {
        Certificate puk = null;
        puk = ks.getCertificate(s);
        return createKeyInfo(puk.getPublicKey());
    }

    /**
     * Creates a KeyInfo Element containing the XML Encoded KeyInfo of a given public key.
     * 
     * @param pub RSA PublicKey to encode
     * @return Element containg valid KeyInfo
     */
    public static Element createKeyInfo(final PublicKey pub) {//throws KeyStoreException {
        final KeyInfo ki = new KeyInfo(pub);
        return ki.getElement();
    }

    /**
     * Used to create a QName within the XMLSignature Standard's namespace
     * 
     * @param name 
     * @return valid QName
     */
    public static QName createQName(final String name) {
        return DocumentHelper.createQName(name, NS_DS);
    }

    /**
     * Used to create an Element within the XMLSignature Standard's namespace
     * 
     * @param elementName 
     * @return 
     */
    public static org.dom4j.Element createElementInSignatureSpace(final String elementName) {
        return DocumentHelper.createElement(createQName(elementName));
    }

    /**
     * Attempts to find a Signature within an element
     * 
     * @param elem Element to search.
     * @return XMLSignature object
     * @throws XMLSecurityException 
     */
    public static XMLSignature getXMLSignature(final Element elem) throws XMLSecurityException {
        final QName qname = XMLSecTools.createQName("Signature");
        Element xmlSigElement = elem.element(qname);
        if (xmlSigElement == null || (isInXMLSigNS(xmlSigElement))) {
            if (elem.getQName().equals(qname)) // This is an Enveloping Signature
                xmlSigElement = elem;
            else
                throw new XMLSecurityException("No Signature Found");
        }
        return new XMLSignature(xmlSigElement);
    }

    public static boolean isInXMLSigNS(final Element xmlSigElement) {
        return !xmlSigElement.getNamespaceURI().equals(XMLSecTools.XMLDSIG_NAMESPACE);
    }

    /**
     * Verifies the signature of a given element
     * 
     * @param elem Element to verify
     * @param pub  Public Key to verify against
     * @return true if it verifies
     * @throws XMLSecurityException 
     */
    public static boolean verifySignature(final Element elem, final PublicKey pub) throws XMLSecurityException, CryptoException {
        final XMLSignature sig = getXMLSignature(elem);
        return sig.verifySignature(pub);
    }

    /**
     * Verifies the signature of a given element
     * 
     * @param elem Element to verify
     * @param pubs Array of Public Key to verify against
     * @return true if it verifies
     * @throws XMLSecurityException 
     */
    public static boolean verifySignature(final Element elem, final PublicKey[] pubs) throws XMLSecurityException, CryptoException {
        final XMLSignature sig = getXMLSignature(elem);
        return sig.verifySignature(pubs);
    }

    /**
     * Verifies the signature of a given element. Note this requires an embedded KeyInfo part within the
     * Signature Element.
     * 
     * @param elem Element to verify
     * @return true if it verifies
     * @throws XMLSecurityException 
     */
    public static boolean verifySignature(final Element elem) throws XMLSecurityException, CryptoException {
        final XMLSignature sig = getXMLSignature(elem);
        return sig.verifySignature();
    }

    /**
     * This takes a node and outputs it as a byte array. Note this is not canonicalized
     * 
     * @param node Dom4J node to canonicalize
     * @return byte array of signature
     */
    public static byte[] getElementBytes(final Node node) {
        try {
            final StringWriter out = new StringWriter();
            final XMLWriter writer = new XMLWriter(out);
            writer.write(node);
            return out.toString().getBytes();
        } catch (IOException e) {
            throw new RuntimeException("Weird IOException while generating textual representation: " + e.getMessage());
        }

    }

    /**
     * This is canonicalizes a node and outputs it as a byte array
     * 
     * @param node Dom4J node to canonicalize
     * @return byte array of signature
     */
    public static byte[] canonicalize(final Object node) {
        return canonicalize(new Canonicalizer(), node);
    }

    /**
     * This canonicalizes an object while leaving out any embedded signatures.
     * 
     * @param node 
     * @return 
     */
    public static byte[] canonicalizeEmbeddedSignature(final Object node) {
        return canonicalize(new CanonicalizerWithoutSignature(), node);
    }

    /**
     * Canonicalizes an object based on the given Canonicalizer
     * 
     * @param canon 
     * @param node  
     * @return 
     */
    public static byte[] canonicalize(final Canonicalizer canon, final Object node) {
        try {

            return canon.canonicalize(node);
        } catch (IOException e) {
            throw new RuntimeException("Weird IOException while generating textual representation: " + e.getMessage());
        }

    }

    /**
     * Canonicalises a subset of the node based on the given xpath. Remember this doesnt necesarily return a wellformed
     * XML Document. It depends on the given xpath.
     * 
     * @param node  
     * @param xpath 
     * @return 
     */
    public static byte[] canonicalizeSubset(final Node node, final String xpath) {
        try {

            final Canonicalizer canon = new Canonicalizer();
            return canon.canonicalizeSubset(node, xpath);
        } catch (IOException e) {
            throw new RuntimeException("Weird IOException while generating textual representation: " + e.getMessage());
        }

    }

    /**
     * Creates a textual representation of an element and encodes the results as a base64.<p>
     * This is useful when passing xml as hidden html form fields.
     * 
     * @param elem Element to Encode
     * @return String containing Base64 encoded Element
     */
    public static String encodeElementBase64(final Element elem) {
        return Base64.encode(getElementBytes(elem));
    }

    /**
     * Creates a textual representation of an element and encodes the results as a base64.<p>
     * This is useful when passing xml as hidden html form fields.
     * 
     * @param elem SignedElement to Encode
     * @return String containing Base64 encoded Element
     * @throws XMLException 
     */
    public static String encodeElementBase64(final SignedElement elem) throws XMLException {
        return Base64.encode(elem.canonicalize());
    }

    /**
     * Decodes a Base64 encoded xml element.
     * 
     * @param b64 the Encoded string
     * @return Element
     * @throws XMLSecurityException is thrown if there is a problem parsing the string
     */
    public static Element decodeElementBase64(final String b64) throws XMLSecurityException, CryptoException {
        try {
            final byte[] xmlbytes = Base64.decode(b64);
            return DocumentHelper.parseText(new String(xmlbytes)).getRootElement();
        } catch (DocumentException e) {
            throw new XMLSecurityException(e);
        }

    }

    public static void rethrowException(final Throwable e) throws XMLSecurityException {
        throw new XMLSecurityException(e);
    }

    /**
     * Method decodeBigIntegerFromElement
     * 
     * @param element 
     * @return 
     */
    public static BigInteger decodeBigIntegerFromElement(final Element element)
            throws CryptoException {
        return new BigInteger(1, decodeBase64Element(element));
    }

    /**
     * Method decodeBigIntegerFromText
     * 
     * @param text 
     * @return 
     */
    public static BigInteger decodeBigIntegerFromText(final Text text)
            throws CryptoException {
        return new BigInteger(1, Base64.decode(text.getText()));
    }

    /**
     * This method takes an (empty) Element and a BigInteger and adds the
     * base64 encoded BigInteger to the Element.
     * 
     * @param biginteger 
     * @return Text
     */
    public static Text createTextWithBigInteger(
            final BigInteger biginteger) {

        String encodedInt = Base64.encode(biginteger);

        if (encodedInt.length() > 76) {
            encodedInt = "\n" + encodedInt + "\n";
        }

        return DocumentHelper.createText(encodedInt);
    }

    /**
     * Method decodeBase64Element
     * <p/>
     * Takes the <CODE>Text</CODE> children of the Element and interprets
     * them as input for the <CODE>Base64.decodeBase64Element()</CODE> function.
     * 
     * @param element 
     * @return 
     */
    public static byte[] decodeBase64Element(final Element element) throws CryptoException {

        final Iterator iter = element.nodeIterator();
        final StringBuffer sb = new StringBuffer();

        while (iter.hasNext()) {
            final Node node = (Node) iter.next();
            if (node instanceof Text) {
                final String text = node.getText();
                final StringTokenizer tok = new StringTokenizer(text, " \n\r\t", false);
                while (tok.hasMoreTokens())
                    sb.append(tok.nextToken());
            }
        }

        return Base64.decode(sb.toString());
    }

    /**
     * Method base64ToElement
     * 
     * @param localName 
     * @param bytes     
     * @return 
     */
    public static Element base64ToElement(final String localName,
                                          final byte[] bytes) {

        final Element el = createElementInSignatureSpace(localName);
        final Text text = DocumentHelper.createText(Base64.encodeClean(bytes));

        el.add(text);

        return el;
    }

    /**
     * Method base64ToElement
     * 
     * @param localName 
     * @param big       
     * @return 
     */
    public static Element bigIntToElement(final String localName,
                                          final BigInteger big) {
//        System.out.println("JDK toByteArray(): "+encode(big.toByteArray()));
//        System.out.println("getBytes(): "+encode(getBytes(big)));

        return base64ToElement(localName, Base64.getBytes(big));
    }
/*
    public static void main(String args[]){
        SAXReader reader = new SAXReader();
        try {

            reader.setValidation(false);
            reader.setStripWhitespaceText(false);
            reader.setMergeAdjacentText(false);
            reader.setStringInternEnabled(false);

            reader.setIncludeExternalDTDDeclarations(false);
            Document document = reader.read(System.in);
//            if (reader.getXMLFilter()!=null)
//                    System.out.println("XMLFilter: "+reader.getXMLFilter().getClass().toString());
//            if (reader.getXMLReader()!=null)
//                System.out.println("XMLReader: "+reader.getXMLReader().getClass().toString());
            System.out.println("Original:");
            System.out.println(document.asXML());
            System.out.println("C14n:");

            System.out.write(getElementBytes(document));
        } catch (DocumentException e) {
            System.err.println("There was no input");
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (IOException e) {

            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }

    }
*/
}
