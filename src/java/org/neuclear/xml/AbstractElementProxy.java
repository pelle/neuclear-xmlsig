/*
 * $Id: AbstractElementProxy.java,v 1.2 2003/11/19 23:33:17 pelle Exp $
 * $Log: AbstractElementProxy.java,v $
 * Revision 1.2  2003/11/19 23:33:17  pelle
 * Signers now can generatekeys via the generateKey() method.
 * Refactored the relationship between SignedNamedObject and NamedObjectBuilder a bit.
 * SignedNamedObject now contains the full xml which is returned with getEncoded()
 * This means that it is now possible to further send on or process a SignedNamedObject, leaving
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
 * Oops. XML-Signature's SignedInfo element I had coded as SignatureInfo
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

public abstract class AbstractElementProxy implements ElementProxy {
    protected AbstractElementProxy(String name, String prefix, String nsURI) {
        this(name, DocumentHelper.createNamespace(prefix, nsURI));
    }

    protected AbstractElementProxy(String name, Namespace ns) {
        this(DocumentHelper.createQName(name, ns));
    }

    protected AbstractElementProxy(QName qname) {
        this.element = DocumentHelper.createElement(qname);
    }

    protected AbstractElementProxy(Element elem) {
        element = elem;
    }

    private Element element;

    public final Element getElement() {
        return element;
    }

    protected void addElement(AbstractElementProxy child) throws XMLException {
        addElement(child.getElement());
    }

    protected void addElement(Element child) throws XMLException {
        element.add(child);
        element.addText("\n");
    }

    public final QName getQName() {
        return new QName(getTagName(), getNS());
    }

    public final String asXML() throws XMLException {
        return XMLTools.asXML(element);
    }

    public byte[] canonicalize() throws XMLException {
        return XMLSecTools.canonicalize(this);
    }

    public abstract String getTagName();

    public abstract Namespace getNS();

    static Namespace XMLNS = DocumentHelper.createNamespace("xmlns", "http://www.w3.org/XML/1998/namespace");

}
