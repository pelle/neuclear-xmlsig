/* $Id: Reference.java,v 1.17 2004/03/19 22:21:51 pelle Exp $
 * $Log: Reference.java,v $
 * Revision 1.17  2004/03/19 22:21:51  pelle
 * Changes in the XMLSignature class, which is now Abstract there are currently 3 implementations for:
 * - Enveloped
 * - DataObjects - (Enveloping)
 * - Any for interop testing mainly.
 *
 * Revision 1.16  2004/03/08 23:51:03  pelle
 * More improvements on the XMLSignature. Now uses the Transforms properly, References properly.
 * All the major elements have been refactored to be cleaner and more correct.
 *
 * Revision 1.15  2004/03/05 23:47:17  pelle
 * Attempting to make Reference and SignedInfo more compliant with the standard.
 * SignedInfo can now contain more than one reference.
 * Reference is on the way to becoming more flexible and two support more than one transform.
 * I am adding Crypto Channels to commons to help this out and to hopefully speed things up as well.
 *
 * Revision 1.14  2004/03/03 23:23:24  pelle
 * Interops with enveloped signatures.
 *
 * Revision 1.13  2004/03/02 23:50:45  pelle
 * minor changes.
 * receiver didnt get checked in by idea in recent refactoring.
 *
 * Revision 1.12  2004/03/02 23:30:43  pelle
 * Renamed SignatureInfo to SignedInfo as that is the name of the Element.
 * Made some changes in the Canonicalizer to make all the output verify in Aleksey's xmlsec library.
 * Unfortunately this breaks example 3 of merlin-eight's canonicalization interop tests, because dom4j afaik
 * can't tell the difference between <test/> and <test xmlns=""/>.
 * Changed XMLSignature it is now has less repeated code.
 *
 * Revision 1.11  2004/03/02 18:39:57  pelle
 * Done some more minor fixes within xmlsig, but mainly I've removed the old Source and Store patterns and sub packages. This is because
 * they really are no longer necessary with the new non naming naming system.
 *
 * Revision 1.10  2004/02/19 00:27:59  pelle
 * Discovered several incompatabilities with the xmlsig implementation. Have been working on getting it working.
 * Currently there is still a problem with enveloping signatures and it seems enveloped signatures done via signers.
 *
 * Revision 1.9  2004/01/15 00:01:46  pelle
 * Problem fixed with Enveloping signatures.
 *
 * Revision 1.8  2004/01/14 17:07:59  pelle
 * KeyInfo containing X509Certificates now work correctly.
 * 10 out of 16 of merlin's tests now work. The missing ones are largely due to key resolution issues. (Read X509)
 *
 * Revision 1.7  2004/01/14 16:34:27  pelle
 * New model of references and signatures now pretty much works.
 * I am still not 100% sure on the created enveloping signatures. I need to do more testing.
 *
 * Revision 1.6  2004/01/14 06:42:38  pelle
 * Got rid of the verifyXXX() methods
 *
 * Revision 1.5  2004/01/13 23:37:59  pelle
 * Refactoring parts of the core of XMLSignature. There shouldnt be any real API changes.
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
 * Oops. XML-Signature's SignedInfo element I had coded as SignedInfo
 * As I thought Canonicalisation doesnt seem to be standard.
 * Updated the SignedServlet to default to using ~/.neuclear/signers.ks
 *
 * Revision 1.3  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.xmlsec;

/**
 * The Reference class implements the W3C XML Signature Spec Reference Object.
 * The basic contract says that once it has been instantiated the digest value within is valid.
 * @author pelleb
 * @version $Revision: 1.17 $
 */

import org.dom4j.Element;
import org.dom4j.Node;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.xml.XMLTools;
import org.neuclear.xml.c14.Canonicalizer;
import org.neuclear.xml.transforms.EnvelopedSignatureTransform;
import org.neuclear.xml.transforms.Transform;
import org.neuclear.xml.transforms.TransformerFactory;

import java.io.IOException;
import java.net.URL;
import java.util.List;

public final class Reference extends AbstractXMLSigElement {

    /**
     * Creates a Reference to a Element, with the given signature type:
     * <ul>
     * <li>
     * Reference.XMLSIGTYPE_ENVELOPED
     * <li>
     * Reference.XMLSIGTYPE_ENVELOPING
     * <ul>
     */
    public Reference(final Element root, boolean enveloped) throws XMLSecurityException {
        this(root, createTransformerArray(enveloped));
    }

    private static Transform[] createTransformerArray(boolean enveloped) {
        if (enveloped)
            return new Transform[]{new EnvelopedSignatureTransform(), new Canonicalizer()};
        else
            return new Transform[]{new Canonicalizer()};
    }

    public Reference(final Element elem, final Transform transforms[]) throws XMLSecurityException {
        this(elem, calculateDigest(elem, transforms), transforms);
        final String id = Utility.denullString(elem.attributeValue("Id"), elem.attributeValue("ID"));
        if (!Utility.isEmpty(id))
            createAttribute("URI", "#" + elem.attributeValue("Id"));
    }

    /**
     * Creates a simple Reference to an Element for use in an Enveloped Signature.
     *
     * @param root
     * @return
     * @throws XMLSecurityException
     */
    public static Reference createEnvelopedReference(final Element root) throws XMLSecurityException {
        return new Reference(root, true);
    }

    /**
     * Creates a simple Reference to an element which already is inside an Object tag and has a URI.
     *
     * @param root
     * @return
     * @throws XMLSecurityException
     */
    public static Reference createEnvelopingObjectReference(final Element root) throws XMLSecurityException {
        return new Reference(root, false);
    }

    public static Reference createExternalReference(final String url) throws XMLSecurityException {
        return new Reference(url);
    }

    private static byte[] calculateDigest(final Element elem, final Transform[] transforms) throws XMLSecurityException {
        Object obj = elem;
        for (int i = 0; i < (transforms.length - 1); i++)
            obj = transforms[i].transformNode(obj);
        if (transforms[transforms.length - 1] instanceof Canonicalizer)
            return CryptoTools.digest(((Canonicalizer) transforms[transforms.length - 1]).canonicalize(obj));
        throw new XMLSecurityException("Final transform must be a Canonicalizer");
    }

    private Reference(Element elem, byte[] digest, Transform transforms[]) {
        super(Reference.TAG_NAME);
        this.refObject = elem;
        if (transforms != null && transforms.length > 0) {
            Element transformsElement = addElement("Transforms");
            for (int i = 0; i < transforms.length; i++) {
                transformsElement.add(transforms[i].getElement());
            }
        }
        addElement("DigestMethod").addAttribute(XMLSecTools.createQName("Algorithm"), "http://www.w3.org/2000/09/xmldsig#sha1");
        getElement().add(XMLSecTools.base64ToElement("DigestValue", digest));

    }

    public Reference(String url) throws XMLSecurityException {
        this(null, digest(url), null);
        createAttribute("URI", url);
    }


    private static byte[] digest(String url) throws XMLSecurityException {
        try {
            return CryptoTools.digest(new URL(url).openStream());
        } catch (IOException e) {
            throw new XMLSecurityException(e);
        }
    }


    /**
     * Build this from XML Reference Element
     *
     * @param elem
     * @throws XMLSecurityException
     */
    public Reference(final Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(elem);
        if (!elem.getQName().getName().equals(TAG_NAME))
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not a valid: " + XMLSecTools.NS_DS.getPrefix() + ":" + TAG_NAME);
        byte[] digest = XMLSecTools.decodeBase64Element(getElement().element(XMLSecTools.createQName("DigestValue")));
        final byte[] dig2;
        refObject = findRefElement(elem);
        if (refObject == null) {
            String uri = elem.attributeValue("URI");
            dig2 = digest(uri);
        } else {
            Node node = refObject;
            final Element trelem = elem.element(XMLSecTools.createQName("Transforms"));
            Canonicalizer canon = null;
            if (trelem != null) {
                final List list = trelem.elements(XMLSecTools.createQName("Transform"));
                for (int i = 0; i < list.size(); i++) {
                    Transform o = TransformerFactory.make((Element) list.get(i));
                    if (i == list.size() - 1 && o instanceof Canonicalizer)
                        canon = (Canonicalizer) TransformerFactory.make((Element) list.get(list.size() - 1));
                    else
                        node = (Node) o.transformNode(node);
                }
            }
            if (canon == null)
                canon = new Canonicalizer();
            dig2 = createDigest(canon, node);
        }
        if (!CryptoTools.equalByteArrays(digest, dig2))
            throw new InvalidSignatureException(digest, dig2);
    }

    private static byte[] createDigest(final Canonicalizer canon, Object root) throws XMLSecurityException {
        final byte[] value = canon.canonicalize(root);
//        System.out.println("Canonicalized Reference:");
//        System.out.println(new String(value));
//        System.out.println("------");
        return CryptoTools.digest(value);
    }

    private static int findSignatureType(Element elem) {
        final String id = elem.attributeValue("URI");
        if (!Utility.isEmpty(id) && id.length() > 1) {
            if (id.startsWith("#"))
                return XMLSIGTYPE_ENVELOPING;
            return XMLSIGTYPE_DETACHED;
        }
        return XMLSIGTYPE_ENVELOPED;
    }

    private static Element findRefElement(Element elem) throws XMLSecurityException {
        final String id = elem.attributeValue("URI");
        if (!Utility.isEmpty(id) && id.length() > 1) {
            if (id.startsWith("#")) {
//                System.out.println("Ref: "+id.substring(1));
                return XMLTools.getByID(elem, id.substring(1));//.createCopy();
            }
            // Non Local URI, we dont set the referenced element
            return null;

        }
        // if URI is null or "" the data object is the root element
        return elem.getDocument().getRootElement();
    }

    public Element getReferencedElement() {
        return refObject;
    }

    public String getUri() {
        return getElement().attributeValue("URI");
    }

    public final Element refObject;

    private static final String TAG_NAME = "Reference";
    public final static int XMLSIGTYPE_ENVELOPED = 0;
    public final static int XMLSIGTYPE_ENVELOPING = 1;
    public final static int XMLSIGTYPE_DETACHED = 2;

}
