package org.neuclear.xml.xmlsec;

import junit.framework.TestCase;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.commons.test.JunitTools;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.XMLTools;

import java.io.File;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 20, 2003
 * Time: 3:49:27 PM
 * $Id: SimpleXMLSigTest.java,v 1.3 2003/11/18 23:35:18 pelle Exp $
 * $Log: SimpleXMLSigTest.java,v $
 * Revision 1.3  2003/11/18 23:35:18  pelle
 * Payment Web Application is getting there.
 *
 * Revision 1.2  2003/11/11 21:18:08  pelle
 * Further vital reshuffling.
 * org.neudist.crypto.* and org.neudist.utils.* have been moved to respective areas under org.neuclear.commons
 * org.neuclear.signers.* as well as org.neuclear.passphraseagents have been moved under org.neuclear.commons.crypto as well.
 * Did a bit of work on the Canonicalizer and changed a few other minor bits.
 * <p/>
 * Revision 1.1.1.1  2003/11/11 16:33:32  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 * <p/>
 * Revision 1.9  2003/10/21 22:30:34  pelle
 * Renamed NeudistException to NeuClearException and moved it to org.neuclear.commons where it makes more sense.
 * Unhooked the XMLException in the xmlsig library from NeuClearException to make all of its exceptions an independent hierarchy.
 * Obviously had to perform many changes throughout the code to support these changes.
 * <p/>
 * Revision 1.8  2003/02/24 12:57:56  pelle
 * Sorted out problem with signing enveloping signatures.
 * Canonicalizer needs a Document. If there isn't a Document the xpath wont work and returns false.
 * Thus always have a document for an element.
 * <p/>
 * Revision 1.7  2003/02/24 03:26:30  pelle
 * XMLSignature class has been tested as working for Enveloped Signatures.
 * It is still failing verification on home grown Enveloping Signatures.
 * It failes while checking reference validity. This means there is something strange about the Digest is initially
 * calculated for Enveloping signatures.
 * <p/>
 * Revision 1.6  2003/02/21 22:48:20  pelle
 * New Test Infrastructure
 * Added test keys in src/testdata/keys
 * Modified tools to handle these keys
 * <p/>
 * Revision 1.5  2003/02/20 13:26:42  pelle
 * Adding all of the modification from Rams?s Morales ramses@computer.org to support DSASHA1 Signatures
 * Thanks Rams?s good work.
 * So this means there is now support for:
 * - DSA KeyInfo blocks
 * - DSA Key Generation within CryptoTools
 * - Signing using DSASHA1
 * <p/>
 * Revision 1.4  2003/02/11 14:50:26  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 * <p/>
 * Revision 1.3  2003/02/08 20:55:09  pelle
 * Some documentation changes.
 * Major reorganization of code. The code is slowly being cleaned up in such a way that we can
 * get rid of the org.neuclear.utils package and split out the org.neuclear.xml.soap package.
 * Got rid of tons of unnecessary dependencies.
 * <p/>
 * Revision 1.2  2003/02/08 18:48:38  pelle
 * The Signature phase has been rewritten.
 * There now is a new Class called QuickEmbeddedSignature which is more in line with my original idea for this library.
 * It simply has a template of the xml and signs it in a standard way.
 * The original XMLSignature class is still used for verification and will in the future handle more thoroughly
 * all the various flavours of XMLSig.
 * XMLSecTools has got different flavours of canonicalize now. Including one where you can pass it a Canonicaliser to use.
 * Of the new Canonicalizer's are CanonicalizerWithComments, which I accidently left out of the last commit.
 * And CanonicalizerWithoutSignature which leaves out the Signature in the Canonicalization phase and is thus
 * a lot more efficient than the previous approach.
 * <p/>
 * Revision 1.1  2003/01/21 03:14:12  pelle
 * Mainly clean ups through out and further documentation.
 */
public class SimpleXMLSigTest extends TestCase {
    public SimpleXMLSigTest(String s) throws SecurityException, NoSuchAlgorithmException, CryptoException {
        super(s);
        signer = JunitTools.getTestRSAKey();
        dsaSigner = JunitTools.getTestDSAKey();
    }

    public void testRSASignXML() throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText(TESTXML);
        XMLSignature sig = new XMLSignature(signer, doc.getRootElement(), "http://testsigs");
        File outputFile = new File("target/testdata/homegrown/signature-enveloped-rsa.xml");
        XMLTools.writeFile(outputFile, doc);

        doc = XMLTools.loadDocument(outputFile);
        assertTrue("Test if Signature is valid", XMLSecTools.verifySignature(doc.getRootElement()));
    }

    public void testRSAEnvelopingSignXML() throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText(TESTXML);
        XMLSignature sig = new XMLSignature(signer, doc.getRootElement(), "http://testsigs", Reference.XMLSIGTYPE_ENVELOPING);
        File outputFile = new File("target/src/testdata/homegrown/signature-enveloping-rsa.xml");
        XMLTools.writeFile(outputFile, sig.getElement());

        doc = XMLTools.loadDocument(outputFile);
        assertTrue("Test if Signature is valid", XMLSecTools.verifySignature(doc.getRootElement()));
    }

    public void testDSAEnvelopingSignXML() throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText(TESTXML);
        XMLSignature sig = new XMLSignature(dsaSigner, doc.getRootElement(), "http://testsigs", Reference.XMLSIGTYPE_ENVELOPING);
        File outputFile = new File("target/src/testdata/homegrown/signature-enveloping-dsa.xml");
        XMLTools.writeFile(outputFile, sig.getElement());

        doc = XMLTools.loadDocument(outputFile);
        assertTrue("Test if Signature is valid", XMLSecTools.verifySignature(doc.getRootElement()));
    }

    public void testDSASignXML()
            throws DocumentException, XMLException, CryptoException {
        assertTrue("Test if public key is really DSA", dsaSigner.getPublic() instanceof DSAPublicKey);
        Document doc = DocumentHelper.parseText(TESTXML);
        XMLSignature sig = new XMLSignature(dsaSigner, doc.getRootElement(), "http://testDSAsigs");

        File outputFile = new File("target/src/testdata/homegrown/signature-enveloped-dsa.xml");
        XMLTools.writeFile(outputFile, doc);

        doc = XMLTools.loadDocument(outputFile);
        assertTrue("Test if DSA Signature is valid", XMLSecTools.verifySignature(doc.getRootElement()));
    }

    public void testQuickRSASignXML() throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText(TESTXML);
        XMLSecTools.signElement("http://testsigs", doc.getRootElement(), signer);
        File outputFile = new File("target/src/testdata/homegrown/signature-enveloped-rsa-quick.xml");
        XMLTools.writeFile(outputFile, doc);

        doc = XMLTools.loadDocument(outputFile);
        assertTrue("Test if RSA Signature is valid", XMLSecTools.verifySignature(doc.getRootElement()));
    }

    public void testQuickDSASignXML()
            throws DocumentException, XMLException, CryptoException {
        assertTrue("Test if public key is really DSA", dsaSigner.getPublic() instanceof DSAPublicKey);
        Document doc = DocumentHelper.parseText(TESTXML);
        XMLSecTools.signElement("http://testDSAsigs", doc.getRootElement(), dsaSigner);

        File outputFile = new File("target/testdata/homegrown/signature-enveloped-dsa-quick.xml");
        XMLTools.writeFile(outputFile, doc);

        doc = XMLTools.loadDocument(outputFile);
        assertTrue("Test if DSA Signature is valid", XMLSecTools.verifySignature(doc.getRootElement()));
    }


    public void testBadSignXML() throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText(TESTXML);

        XMLSecTools.signElement("http://testsigs", doc.getRootElement(), signer);
        assertTrue("Test if Signature is valid", XMLSecTools.verifySignature(doc.getRootElement(), signer.getPublic()));
        doc.getRootElement().addElement("BadElement");
        assertTrue("Test that Signature is invalid", !XMLSecTools.verifySignature(doc.getRootElement(), signer.getPublic()));

    }

    public void testBadDSASignXML()
            throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText(TESTXML);

        XMLSecTools.signElement("http://testDSAsigs", doc.getRootElement(), dsaSigner);
        assertTrue("Test if DSA Signature is valid", XMLSecTools.verifySignature(doc.getRootElement(), dsaSigner.getPublic()));
        doc.getRootElement().addElement("BadElement");
        assertTrue("Test that DSA Signature is invalid", !XMLSecTools.verifySignature(doc.getRootElement(), signer.getPublic()));
    }

    KeyPair signer, dsaSigner;
    final static String TESTXML = "<test><test2></test2></test>";

}
