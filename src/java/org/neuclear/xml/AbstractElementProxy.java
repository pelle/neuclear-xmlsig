/*
 * $Id: AbstractElementProxy.java,v 1.12 2004/03/19 22:21:51 pelle Exp $
 * $Log: AbstractElementProxy.java,v $
 * Revision 1.12  2004/03/19 22:21:51  pelle
 * Changes in the XMLSignature class, which is now Abstract there are currently 3 implementations for:
 * - Enveloped
 * - DataObjects - (Enveloping)
 * - Any for interop testing mainly.
 *
 * Revision 1.11  2004/03/02 23:30:43  pelle
 * Renamed SignatureInfo to SignedInfo as that is the name of the Element.
 * Made some changes in the Canonicalizer to make all the output verify in Aleksey's xmlsec library.
 * Unfortunately this breaks example 3 of merlin-eight's canonicalization interop tests, because dom4j afaik
 * can't tell the difference between <test/> and <test xmlns=""/>.
 * Changed XMLSignature it is now has less repeated code.
 *
 * Revision 1.10  2004/02/19 00:27:59  pelle
 * Discovered several incompatabilities with the xmlsig implementation. Have been working on getting it working.
 * Currently there is still a problem with enveloping signatures and it seems enveloped signatures done via signers.
 *
 * Revision 1.9  2004/02/18 00:13:49  pelle
 * Many, many clean ups. I've readded Targets in a new method.
 * Gotten rid of NamedObjectBuilder and revamped Identity and Resolvers
 *
 * Revision 1.8  2003/12/16 15:04:49  pelle
 * Added SignedMessage contract for signing simple textual contracts.
 * Added NeuSender, updated SmtpSender and Sender to take plain email addresses (without the mailto:)
 * Added AbstractObjectCreationTest to make it quicker to write unit tests to verify
 * NamedObjectBuilder/SignedNamedObject Pairs.
 * Sample application has been expanded with a basic email application.
 * Updated docs for sample web app.
 * Added missing LGPL LICENSE.txt files to signer and sample app
 *
 * Revision 1.7  2003/12/11 23:56:53  pelle
 * Trying to test the ReceiverServlet with cactus. Still no luck. Need to return a ElementProxy of some sort.
 * Cleaned up some missing fluff in the ElementProxy interface. getTagName(), getQName() and getNameSpace() have been killed.
 *
 * Revision 1.6  2003/12/11 16:29:19  pelle
 * Updated various builders to use the new helper methods in AbstractElementProxy hopefully making them more readable.
 *
 * Revision 1.5  2003/12/11 16:16:05  pelle
 * Some changes to make the xml a bit more readable.
 * Also added some helper methods in AbstractElementProxy to make it easier to build objects.
 *
 * Revision 1.4  2003/12/10 23:57:05  pelle
 * Did some cleaning up in the builders
 * Fixed some stuff in IdentityCreator
 * New maven goal to create executable jarapp
 * We are close to 0.8 final of ID, 0.11 final of XMLSIG and 0.5 of commons.
 * Will release shortly.
 *
 * Revision 1.3  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.2  2003/11/19 23:33:17  pelle
 * Signers now can generatekeys via the generateKey() method.
 * Refactored the relationship between SignedNamedObject and NamedObjectBuilder a bit.
 * SignedNamedObject now contains the full xml which is returned with getEncoded()
 * This means that it is now possible to further receive on or process a SignedNamedObject, leaving
 * NamedObjectBuilder for its original purposes of purely generating new Contracts.
 * NamedObjectBuilder.sign() now returns a SignedNamedObject which is the prefered way of processing it.
 * Updated all major interfaces that used the old model to use the new model.
 *
 * Revision 1.1.1.1  2003/11/11 16:33:20  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.7  2003/11/09 03:27:09  pelle
 * More house keeping and shuffling about mainly pay
 *
 * Revision 1.6  2003/09/26 23:52:47  pelle
 * Changes mainly in receiver and related fun.
 * First real neuclear stuff in the payment package. Added TransferContract and AssetControllerReceiver.
 *
 * Revision 1.5  2003/02/24 13:32:23  pelle
 * Final doc changes for 0.8
 *
 * Revision 1.4  2003/02/24 03:26:20  pelle
 * XMLSignature class has been tested as working for Enveloped Signatures.
 * It is still failing verification on home grown Enveloping Signatures.
 * It failes while checking reference validity. This means there is something strange about the Digest is initially
 * calculated for Enveloping signatures.
 *
 * Revision 1.3  2003/02/14 21:13:59  pelle
 * The AbstractElementProxy has a new final method .asXML()
 * which is similar to DOM4J's but it outputs the xml in the compact format and not the pretty format, thus not causing problems with Canonicalization.
 * You can now also easily get the digest of a SignedElement with the new .getEncoded() value.
 *
 * Revision 1.2  2003/02/11 14:47:02  pelle
 * Added benchmarking code.
 * DigestValue is now a required part.
 * If you pass a keypair when you sign, you get the PublicKey included as a KeyInfo block within the signature.
 *
 * Revision 1.1  2003/01/18 18:12:31  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.5  2002/12/17 21:41:02  pelle
 * First part of refactoring of SignedNamedObject and SignedObject Interface/Class parings.
 *
 * Revision 1.4  2002/12/17 20:34:43  pelle
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
 * Revision 1.3  2002/10/10 21:29:31  pelle
 * Oops. XML-Signature's SignedInfo element I had coded as SignedInfo
 * As I thought Canonicalisation doesnt seem to be standard.
 * Updated the SignedServlet to default to using ~/.neuclear/signers.ks
 *
 * Revision 1.2  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 * User: pelleb
 * Date: Sep 10, 2002
 * Time: 11:49:42 AM
* TODO: Replace ElementProxy Interface with AbstractElementProxy

 */
package org.neuclear.xml;

import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.neuclear.xml.xmlsec.XMLSecTools;
import org.neuclear.xml.xmlsec.XMLSecurityException;

public abstract class AbstractElementProxy implements ElementProxy {
    protected AbstractElementProxy(final String name, final String prefix, final String nsURI) {
        this(name, DocumentHelper.createNamespace(prefix, nsURI));
    }

    protected AbstractElementProxy(final String name, final Namespace ns) {
        this(DocumentHelper.createQName(name, ns));
    }

    protected AbstractElementProxy(final QName qname) {
        this.element = DocumentHelper.createElement(qname);
    }

    protected AbstractElementProxy(final Element elem) {
        element = elem;
    }

    private final Element element;

    public final Element getElement() {
        return element;
    }

    /**
     * Adds another AbstractElementProxy as a child element to this Element
     * 
     * @param child 
     */
    protected final Element addElement(final AbstractElementProxy child) {
        addElement(child.getElement());
        return child.getElement();
    }

    /**
     * Adds another Element as a child element to this Element
     * 
     * @param child 
     */
    protected final Element addElement(final Element child) {
        element.add(child);
        addLineBreak();
        return element;
    }

    /**
     * Adds another Element with the given QName to this Element
     * 
     * @param child 
     */
    protected final Element addElement(final QName child) {
        Element element = DocumentHelper.createElement(child);
        addElement(element);
        return element;
    }

    /**
     * Adds another Element with the given name and the same Namespace as this element to this element.
     * 
     * @param child 
     */
    protected final Element addElement(final String child) {
        Element element = DocumentHelper.createElement(createQName(child));
        addElement(element);
        return element;
    }

    /**
     * Adds another Element with the given name and the same Namespace as this element to this element.
     *
     * @param child
     */
    protected final Element addElement(final String child, final String text) {
        Element elem = addElement(child);
        elem.addText(text);
        return elem;
    }

    /**
     * Creates a QName in this object namespace
     * 
     * @param child 
     * @return 
     */
    protected final QName createQName(final String child) {
        return DocumentHelper.createQName(child, this.element.getNamespace());
    }

    /**
     * Adds a linebreak to the xml, making it easier to read for humans
     */
    protected final void addLineBreak() {
        element.addText("\n");
    }

    /**
     * Adds an attribute with the same namespace as the elment
     * 
     * @param name  
     * @param value 
     */
    protected final void createAttribute(String name, String value) {
        element.addAttribute(createQName(name), value);
    }

/*
    public final QName getQName() {
        return element.getQName();
    }
*/

    public final String asXML() throws XMLException {
        return XMLTools.asXML(element);
    }

    public byte[] canonicalize() throws XMLSecurityException {
        return XMLSecTools.canonicalize(element);
    }
/*

    public final String getTagName() {
        return element.getName();
    }

    public final Namespace getNS() {
        return element.getNamespace();
    }
*/

    static final Namespace XMLNS = DocumentHelper.createNamespace("xmlns", "http://www.w3.org/XML/1998/namespace");

}
