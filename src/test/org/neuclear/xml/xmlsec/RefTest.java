package org.neuclear.xml.xmlsec;

import junit.framework.TestCase;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.xml.XMLException;

import java.io.File;
import java.net.MalformedURLException;

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

$Id: RefTest.java,v 1.1 2004/01/13 23:37:59 pelle Exp $
$Log: RefTest.java,v $
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

    public void testExternalReference() throws XMLException, CryptoException, MalformedURLException {
        File rfile=new File("src/testdata/homegrown/signature-enveloped-rsa.xml");
        final String uri = rfile.toURL().toExternalForm();
        Reference ref=new Reference(uri);
        assertNotNull(ref);
        assertNotNull(ref.getDigest());
        assertEquals(uri,ref.getUri());
        System.out.println(ref.asXML());
    }

    public void testEnvelopedReference() throws DocumentException, XMLException, CryptoException {
        Document doc=DocumentHelper.parseText("<test id=\"one\">hello</test>");
        Reference ref=new Reference(doc.getRootElement(),Reference.XMLSIGTYPE_ENVELOPED);
        assertNotNull(ref);
        assertNotNull(ref.getDigest());
        assertEquals("#one",ref.getUri());
        System.out.println(ref.asXML());
    }

}
