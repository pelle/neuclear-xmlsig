package org.neuclear.xml.xmlsec;

import junit.framework.TestCase;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.XMLTools;

import java.io.File;
import java.io.IOException;

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

$Id: RefTest.java,v 1.8 2004/03/08 23:51:04 pelle Exp $
$Log: RefTest.java,v $
Revision 1.8  2004/03/08 23:51:04  pelle
More improvements on the XMLSignature. Now uses the Transforms properly, References properly.
All the major elements have been refactored to be cleaner and more correct.

Revision 1.7  2004/03/05 23:47:17  pelle
Attempting to make Reference and SignedInfo more compliant with the standard.
SignedInfo can now contain more than one reference.
Reference is on the way to becoming more flexible and two support more than one transform.
I am adding Crypto Channels to commons to help this out and to hopefully speed things up as well.

Revision 1.6  2004/03/02 18:39:57  pelle
Done some more minor fixes within xmlsig, but mainly I've removed the old Source and Store patterns and sub packages. This is because
they really are no longer necessary with the new non naming naming system.

Revision 1.5  2004/02/19 00:28:00  pelle
Discovered several incompatabilities with the xmlsig implementation. Have been working on getting it working.
Currently there is still a problem with enveloping signatures and it seems enveloped signatures done via signers.

Revision 1.4  2004/01/15 00:01:46  pelle
Problem fixed with Enveloping signatures.

Revision 1.3  2004/01/14 16:34:27  pelle
New model of references and signatures now pretty much works.
I am still not 100% sure on the created enveloping signatures. I need to do more testing.

Revision 1.2  2004/01/14 06:42:38  pelle
Got rid of the verifyXXX() methods

Revision 1.1  2004/01/13 23:37:59  pelle
Refactoring parts of the core of XMLSignature. There shouldnt be any real API changes.

*/

/**
 * User: pelleb
 * Date: Jan 13, 2004
 * Time: 9:49:09 PM
 */
public class RefTest extends TestCase {
    public RefTest(String string) {
        super(string);
    }

    public void testExternalReference() throws XMLException, CryptoException, IOException, DocumentException {
        File rfile = new File("project.xml");
        final String uri = rfile.toURL().toExternalForm();
        Reference ref = new Reference(uri);
        assertNotNull(ref);
        assertNull(ref.getReferencedElement());
        assertEquals(uri, ref.getUri());
        try {
            Reference ref2 = new Reference(DocumentHelper.parseText(ref.asXML()).getRootElement());
        } catch (InvalidSignatureException e) {
            assertTrue(false);
        }

    }

    public void testEnvelopedReference() throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText("<test>hello<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo/></Signature></test>");
        Reference ref = new Reference(doc.getRootElement(), true);
        doc.getRootElement().element("Signature").element("SignedInfo").add(ref.getElement());

        assertNotNull(ref);
        assertNotNull(ref.getReferencedElement());
        assertTrue(Utility.isEmpty(ref.getUri()));
        try {
            Reference ref2 = new Reference(DocumentHelper.parseText(doc.asXML()).getRootElement().element("Signature").element("SignedInfo").element("Reference"));
            assertNotNull(ref2.getReferencedElement());
            assertEquals("test", ref2.getReferencedElement().getName());
        } catch (InvalidSignatureException e) {
            assertTrue(false);
        }


    }

    public void testEnvelopingReference() throws DocumentException, XMLException, CryptoException, InvalidSignatureException {
        Document doc = DocumentHelper.parseText("<Signature><SignedInfo/><Object Id=\"one\"><test>hello</test></Object></Signature>");
        Reference ref = new Reference(doc.getRootElement().element("Object"), false);
        doc.getRootElement().element("SignedInfo").add(ref.getElement());
        assertNotNull(XMLTools.getByID(doc, "one"));
        assertNotNull(ref.getReferencedElement());
        assertNotNull(ref);
        assertEquals("#one", ref.getUri());

        Document doc2 = DocumentHelper.parseText(doc.asXML());
        try {
            Reference ref2 = new Reference(doc2.getRootElement().element("SignedInfo").element("Reference"));
            assertNotNull(ref.getReferencedElement());
            assertEquals(ref.getUri(), ref2.getUri());
            assertEquals("Object", ref2.getReferencedElement().getName());
        } catch (InvalidSignatureException e) {
            assertTrue(false);
        }


    }

}
