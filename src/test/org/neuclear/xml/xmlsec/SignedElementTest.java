package org.neuclear.xml.xmlsec;

import junit.framework.TestCase;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.InvalidPassphraseException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;
import org.neuclear.commons.crypto.signers.TestCaseSigner;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.XMLTools;

import java.io.File;

/*
NeuClear Distributed Transaction Clearing Platform
(C) 2003 Pelle Braendgaard

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

$Id: SignedElementTest.java,v 1.1 2004/04/28 00:23:48 pelle Exp $
$Log: SignedElementTest.java,v $
Revision 1.1  2004/04/28 00:23:48  pelle
Fixed the strange verification error
Added bunch of new unit tests to support this.
Updated Signer's dependencies and version number to be a 0.9 release.
Implemented ThreadLocalSession session management for Hibernate ledger.
Various other minor changes.

*/

/**
 * User: pelleb
 * Date: Apr 27, 2004
 * Time: 7:25:54 PM
 */
public class SignedElementTest extends TestCase {
    public SignedElementTest(String string) throws InvalidPassphraseException {
        super(string);
        signer = new TestCaseSigner();
        new File("target/testdata/signedelements").mkdirs();

    }

    public void testCreateSimple() throws XMLException, NonExistingSignerException, UserCancellationException {
        SignedElement elem = new SignedElement("test");
        elem.sign("bob", signer);
        final File outputFile = new File("target/testdata/signedelements/simple1.xml");
        XMLTools.writeFile(outputFile, elem.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);

    }

    public void testCreateSimpleWithNS() throws XMLException, NonExistingSignerException, UserCancellationException {
        SignedElement elem = new SignedElement("test", "t", "http://test.org");
        elem.sign("bob", signer);
        final File outputFile = new File("target/testdata/signedelements/simplens.xml");
        XMLTools.writeFile(outputFile, elem.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);
    }

    public void testCreateComplex() throws XMLException, NonExistingSignerException, UserCancellationException {
        SignedElement elem = new SignedElement("test");
        elem.getElement().addElement("hello").setText("world");
        elem.sign("bob", signer);
        final File outputFile = new File("target/testdata/signedelements/complex.xml");
        XMLTools.writeFile(outputFile, elem.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);

    }

    public void testCreateComplexWithNS() throws XMLException, NonExistingSignerException, UserCancellationException {
        SignedElement elem = new SignedElement("test", "t", "http://test.org");
        elem.getElement().addElement(DocumentHelper.createQName("hello", DocumentHelper.createNamespace("d", "http://hello.org"))).setText("world");
        elem.sign("bob", signer);
        final File outputFile = new File("target/testdata/signedelements/complexns.xml");
        XMLTools.writeFile(outputFile, elem.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);

    }

    public void testCreateHtml() throws XMLException, NonExistingSignerException, UserCancellationException {
        SignedElement elem = new SignedElement("html");
        elem.getElement().addElement("head").addElement("title").setText("hello world");
        elem.getElement().addElement("body").addElement("h1").setText("hello world");
        elem.sign("bob", signer);
        final File outputFile = new File("target/testdata/signedelements/complex.html");
        XMLTools.writeFile(outputFile, elem.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);

    }

    public void testCreateSimpleFromElement() throws XMLException, NonExistingSignerException, UserCancellationException {
        org.dom4j.Element test = DocumentHelper.createElement("test");
        SignedElement elem = new SignedElement(test);
        elem.sign("bob", signer);
        final File outputFile = new File("target/testdata/signedelements/simplefromelem.xml");
        XMLTools.writeFile(outputFile, elem.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);

    }

    public void testCreateSimpleWithNSFromElement() throws XMLException, NonExistingSignerException, UserCancellationException {
        org.dom4j.Element test = DocumentHelper.createElement(DocumentHelper.createQName("test", DocumentHelper.createNamespace("t", "http://test.org")));

        SignedElement elem = new SignedElement(test);
        elem.sign("bob", signer);
        final File outputFile = new File("target/testdata/signedelements/simplewithnsfromelem.xml");
        XMLTools.writeFile(outputFile, elem.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);

    }


    private void assertValidEnvelopedSignature(Document doc) throws XMLSecurityException {
        try {
            XMLSignature sig = new EnvelopedSignature(doc.getRootElement());
        } catch (InvalidSignatureException e) {
            assertTrue("Signature Failed: " + e.getLocalizedMessage(), false);
        }
    }

    private Signer signer;
}
