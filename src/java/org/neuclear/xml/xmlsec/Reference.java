/* $Id: Reference.java,v 1.2 2003/11/19 23:33:17 pelle Exp $
 * $Log: Reference.java,v $
 * Revision 1.2  2003/11/19 23:33:17  pelle
 * Signers now can generatekeys via the generateKey() method.
 * Refactored the relationship between SignedNamedObject and NamedObjectBuilder a bit.
 * SignedNamedObject now contains the full xml which is returned with getEncoded()
 * This means that it is now possible to further send on or process a SignedNamedObject, leaving
 * NamedObjectBuilder for its original purposes of purely generating new Contracts.
 * NamedObjectBuilder.sign() now returns a SignedNamedObject which is the prefered way of processing it.
 * Updated all major interfaces that used the old model to use the new model.
 *
 * Revision 1.1.1.1  2003/11/11 16:33:26  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.14  2003/02/24 13:32:24  pelle
 * Final doc changes for 0.8
 *
 * Revision 1.13  2003/02/24 12:57:37  pelle
 * Sorted out problem with signing enveloping signatures.
 * Canonicalizer needs a Document. If there isn't a Document the xpath wont work and returns false.
 * Thus always have a document for an element.
 *
 * Revision 1.12  2003/02/24 03:26:30  pelle
 * XMLSignature class has been tested as working for Enveloped Signatures.
 * It is still failing verification on home grown Enveloping Signatures.
 * It failes while checking reference validity. This means there is something strange about the Digest is initially
 * calculated for Enveloping signatures.
 *
 * Revision 1.11  2003/02/24 00:41:07  pelle
 * Cleaned up a lot of code for new fixed processing model.
 * It all still work as before, but will be easier to modify the Reference processing model which is the only
 * main thing todo besides X509 and HMAC-SHA1 support.
 *
 * Revision 1.10  2003/02/23 23:21:46  pelle
 * Yeah. We figured it out. We now have interop.
 * Granted not on all features as yet, but definitely on simple signatures.
 * I'm checking in Ramses' fix to QuickEmbeddedSignature and my fixes to the verification process.
 *
 * Revision 1.9  2003/02/22 16:54:30  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.8  2003/02/21 22:48:15  pelle
 * New Test Infrastructure
 * Added test keys in src/testdata/keys
 * Modified tools to handle these keys
 *
 * Revision 1.7  2003/02/16 00:24:21  pelle
 * getEncoded() was broken in Reference.java
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
 * Revision 1.4  2003/02/08 19:11:10  pelle
 * Cleaned stuff up a bit.
 *
 * Revision 1.3  2003/02/08 18:48:37  pelle
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
 * Revision 1.2  2003/02/01 01:48:26  pelle
 * Fixed the XPath Transform.
 * Has the beginning of a processing framework for the Reference class.
 *
 * Revision 1.1  2003/01/18 18:12:32  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.4  2002/10/10 21:29:31  pelle
 * Oops. XML-Signature's SignedInfo element I had coded as SignatureInfo
 * As I thought Canonicalisation doesnt seem to be standard.
 * Updated the SignedServlet to default to using ~/.neuclear/signers.ks
 *
 * Revision 1.3  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.xmlsec;

/**
 * @author pelleb
 * @version $Revision: 1.2 $
 */

import org.dom4j.Element;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.Base64;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.XMLTools;
import org.neuclear.xml.c14.Canonicalizer;
import org.neuclear.xml.c14.CanonicalizerWithComments;
import org.neuclear.xml.c14.CanonicalizerWithoutSignature;
import org.neuclear.xml.transforms.Transform;

import java.io.File;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class Reference extends AbstractXMLSigElement {

    /**
     * Currently only RSA
     */
    public Reference(Element root, String uri, SignatureInfo si, int sigtype) throws XMLException {
        super(Reference.TAG_NAME);
        this.root = root;
        this.si = si;
        xmlsigType = sigtype;

//        findRefElement();
        if (root == null)
            loadReference(uri);
        if (getSigType() == XMLSIGTYPE_ENVELOPED)
            addTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        else if (getSigType() == XMLSIGTYPE_ENVELOPING) {
            root = si.getSig().getElement().element("Object");
//            System.out.println(new String(canonicalizeReference()));// Just debugging here
        }
        addTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

        Element digMethod = XMLSecTools.createElementInSignatureSpace("DigestMethod");
        digMethod.addAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
        addElement(digMethod);
        setDigest();
    }

    public Reference(Element elem, SignatureInfo si) throws XMLSecurityException {
        super(elem);
        if (!elem.getQName().getName().equals(TAG_NAME))
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not a valid: " + XMLSecTools.NS_DS.getPrefix() + ":" + TAG_NAME);
        this.si = si;
        // Here we will try to get work out Root
        findRefElement();
        // TODO parse Transforms
    }

    private void findRefElement() throws XMLSecurityException {
        Element sigElement = si.getSig().getElement();
        Element objectElem = sigElement.element(XMLSecTools.createQName("Object"));

        if (objectElem != null) {  // Enveloping
            xmlsigType = XMLSIGTYPE_ENVELOPING;
            List contents = objectElem.content();
            if (contents.size() == 1)
                root = contents.get(0);
            else
                root = contents;
            root = objectElem;
        } else if (sigElement.getParent() != null) { // Enveloped
            xmlsigType = XMLSIGTYPE_ENVELOPED;
            root = getElement().getDocument();
        } else {// Detached
            xmlsigType = XMLSIGTYPE_DETACHED;
            loadReference(getElement().attributeValue("URI"));
        }
    }

    private void loadReference(String refuri) throws XMLSecurityException {
        if (Utility.isEmpty(refuri))
            throw new XMLSecurityException("XMLSignature is not linked to Document");
        try {
            root = XMLTools.loadDocument(new File(refuri)).getRootElement();
        } catch (XMLException e) {
            XMLSecTools.rethrowException(e);
        }
    }

    private void addTransform(String algorithm) throws XMLException {
        if (transforms == null) {
            transforms = new LinkedList();
//        if (transformsElement==null)
            transformsElement = XMLSecTools.createElementInSignatureSpace("Transforms");
            addElement(transformsElement);
        }

//        Transform tran = TransformerFactory.make(algorithm);
//        if (tran == null) {
//            System.err.println("Couldn't resolve Transform: " + algorithm);
//            tran = new ClearTransform();
//        }
//        transforms.add(tran);
        transformsElement.addElement(XMLSecTools.createQName("Transform")).addAttribute("Algorithm", algorithm);
    }

    /**
     * Method getEncoded
     * This returns the Digest
     * 
     * @return 
     * @throws XMLSecurityException 
     */
    public byte[] getDigest() throws XMLSecurityException, CryptoException {
        Element sv = (Element) getElement().element(XMLSecTools.createQName("DigestValue"));
        if (sv != null)
            return XMLSecTools.decodeBase64Element(sv);
        return null;
    }

    void setDigest() throws XMLSecurityException {
        Element sv = (Element) getElement().element(XMLSecTools.createQName("DigestValue"));
        byte dig[] = generateRefenceDigest();
        if (sv == null)
            getElement().add(XMLSecTools.base64ToElement("DigestValue", dig));
        else
            sv.addText(Base64.encode(dig));
    }

    //TODO Rewrite this bit
    private final Object performTransforms() {
//        Element subject = root;//(Element) root.clone();
        Object subject = root;
        Iterator iter = transforms.iterator();
        while (iter.hasNext() && root != null) {
            Transform transform = (Transform) iter.next();
            subject = transform.transformNode(subject);
        }
        return subject;
    }

    private Canonicalizer getCanonicalizer() {
        if (getSigType() == Reference.XMLSIGTYPE_ENVELOPED)
            return new CanonicalizerWithoutSignature();
        else if (c14nType == Canonicalizer.C14NTYPE_WITH_COMMENTS)
            return new CanonicalizerWithComments();
        return new Canonicalizer();
    }

    private Object getReferenceElement() {
        return root;
    }

    protected final byte[] canonicalizeReference() {
        return XMLSecTools.canonicalize(getCanonicalizer(), getReferenceElement());
    }

    protected final byte[] generateRefenceDigest() {
        return CryptoTools.digest(canonicalizeReference());
    }

    public final boolean verifyReferences() throws XMLSecurityException, CryptoException {
        return CryptoTools.equalByteArrays(generateRefenceDigest(), getDigest());
    }

    public String getTagName() {
        return TAG_NAME;
    }

    public int getSigType() {
        return xmlsigType;
    }

    private Object root;
    private SignatureInfo si;

    private static String TAG_NAME = "Reference";
    private List transforms;
    private Element transformsElement;
    private int xmlsigType = 0;

    public final static int XMLSIGTYPE_ENVELOPED = 0;
    public final static int XMLSIGTYPE_ENVELOPING = 1;
    public final static int XMLSIGTYPE_DETACHED = 2;

    private int c14nType;


    //   private PublicKey pub;
}
