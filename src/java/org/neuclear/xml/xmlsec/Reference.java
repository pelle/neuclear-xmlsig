/* $Id: Reference.java,v 1.10 2004/02/19 00:27:59 pelle Exp $
 * $Log: Reference.java,v $
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
 * The Reference class implements the W3C XML Signature Spec Reference Object.
 * The basic contract says that once it has been instantiated the digest value within is valid.
 * @author pelleb
 * @version $Revision: 1.10 $
 */

import org.dom4j.Element;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.XMLTools;
import org.neuclear.xml.c14.Canonicalizer;
import org.neuclear.xml.c14.CanonicalizerWithoutSignature;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

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
    public Reference(final Element root, final int sigtype) throws XMLSecurityException {
        super(Reference.TAG_NAME);
        final Canonicalizer canon;
        Element transformsElement = addElement("Transforms");
//        final Element object;
        if (sigtype == XMLSIGTYPE_ENVELOPED){
            createAttribute("URI","");
            canon=new CanonicalizerWithoutSignature();
            transformsElement.addElement(XMLSecTools.createQName("Transform")).addAttribute("Algorithm","http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        } else if (sigtype == XMLSIGTYPE_ENVELOPING){
            canon= new Canonicalizer();
        } else {
            throw new XMLSecurityException("Unsupported Signature Method");
        }
        transformsElement.addElement(XMLSecTools.createQName("Transform")).addAttribute("Algorithm","http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

        type=sigtype;
        final String id = Utility.denullString(root.attributeValue("Id"),root.attributeValue("ID"));
        if (!Utility.isEmpty(id))
            createAttribute("URI","#"+id);

        addDigest(canon,root);
    }


    public Reference(final String uri) throws XMLSecurityException {
        super(Reference.TAG_NAME);
        type=XMLSIGTYPE_DETACHED;
        createAttribute("URI",uri);
        addDigest(new Canonicalizer(),loadReference(uri));
    }
    /**
     * Build this from XML Reference Element
     * @param elem
     * @throws XMLSecurityException
     */
    public Reference(final Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(elem);
        if (!elem.getQName().getName().equals(TAG_NAME))
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not a valid: " + XMLSecTools.NS_DS.getPrefix() + ":" + TAG_NAME);
        type=findSignatureType(elem);

        byte digest[]=XMLSecTools.decodeBase64Element(getElement().element(XMLSecTools.createQName("DigestValue")));

        final Object object=findRefElement(elem);
        if (object==null)
            throw new XMLSecurityException("Couldnt Dereference Object:\n "+elem.asXML());
        final Canonicalizer canon;
        if (type==XMLSIGTYPE_ENVELOPED)
            canon=new CanonicalizerWithoutSignature();
        else
            canon=new Canonicalizer();

        final byte dig2[] = createDigest(canon, object);
        if (!CryptoTools.equalByteArrays(digest,dig2))
            throw new InvalidSignatureException(digest,dig2);
    }
    private void addDigest(final Canonicalizer canon, Object root) throws XMLSecurityException {
        addElement("DigestMethod").addAttribute(XMLSecTools.createQName("Algorithm"),"http://www.w3.org/2000/09/xmldsig#sha1");
        getElement().add(XMLSecTools.base64ToElement("DigestValue",createDigest(canon,root)));
    }

    private static byte[] createDigest(final Canonicalizer canon, Object root) throws XMLSecurityException {
        final byte[] value = canon.canonicalize(root);
//        System.out.println("Canonicalized:");
//        System.out.println(new String(value));
//        System.out.println("------");
        return  CryptoTools.digest(value);
    }

    private static int findSignatureType(Element elem) {
        final String id=elem.attributeValue("URI");
         if (!Utility.isEmpty(id)&&id.length()>1){
             if (id.startsWith("#"))
                 return XMLSIGTYPE_ENVELOPING;
             return XMLSIGTYPE_DETACHED;
         }
        return XMLSIGTYPE_ENVELOPED;
    }

    private static Object findRefElement(Element elem) throws XMLSecurityException {
        final String id=elem.attributeValue("URI");
        if (!Utility.isEmpty(id)&&id.length()>1){
            if (id.startsWith("#")){
//                System.out.println("Ref: "+id.substring(1));
                return XMLTools.getByID(elem,id.substring(1));
            }
            // Non Local URI, we need to load it
            return loadReference(id);

        }
        // if URI is null or "" the data object is the root element
        return elem.getDocument().getRootElement();
    }

    private static Object loadReference(final String refuri) throws XMLSecurityException {
        if (Utility.isEmpty(refuri))
            throw new XMLSecurityException("XMLSignature is not linked to Document");
        try {
            URL url= new URL(refuri);
            String ref=url.getRef();
            if (ref!=null) // If we have a reference part it is XML
                return  XMLTools.loadDocument(url).getRootElement().elementByID(ref);
            BufferedInputStream is=new BufferedInputStream(url.openStream());
            ByteArrayOutputStream os=new ByteArrayOutputStream(is.available());
            byte input[]=new byte[is.available()];
            int count=0;
            while((count=is.read(input))>=0){
                os.write(input,0,count);
            }
            is.close();
            return new String(os.toByteArray());
        } catch (XMLException e) {
            throw new XMLSecurityException(e);
        } catch (MalformedURLException e) {
            throw new XMLSecurityException(e);
        } catch (IOException e) {
            throw new XMLSecurityException(e);
        }
    }



    public String getUri(){
        return getElement().attributeValue("URI");
    }

    private final int type;
    private static final String TAG_NAME = "Reference";

    public final static int XMLSIGTYPE_ENVELOPED = 0;
    public final static int XMLSIGTYPE_ENVELOPING = 1;
    public final static int XMLSIGTYPE_DETACHED = 2;

}
