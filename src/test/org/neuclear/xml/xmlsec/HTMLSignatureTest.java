package org.neuclear.xml.xmlsec;

import junit.framework.TestCase;
import org.dom4j.Document;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;
import org.neuclear.commons.crypto.signers.TestCaseSigner;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.XMLTools;

import java.io.*;

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

$Id: HTMLSignatureTest.java,v 1.1 2004/04/16 23:54:03 pelle Exp $
$Log: HTMLSignatureTest.java,v $
Revision 1.1  2004/04/16 23:54:03  pelle
Added HTMLSignature with tests and associated changes in StandaloneSigner

*/

/**
 * User: pelleb
 * Date: Apr 16, 2004
 * Time: 10:19:37 PM
 */
public class HTMLSignatureTest extends TestCase {
    public HTMLSignatureTest(String s) {
        super(s);
    }

    protected void setUp() throws Exception {
        signer = new TestCaseSigner();
    }

    public void testSignHTMLDocument() throws FileNotFoundException, XMLException, NonExistingSignerException, UserCancellationException {
        InputStream is = new BufferedInputStream(new FileInputStream("src/testdata/html/bobsmith.html"));
        XMLSignature sig = new HTMLSignature("bob", signer, is);
        assertNotNull(sig);
        final File file = new File("target/testdata/html/bobsmithsig.html");
        file.getParentFile().mkdirs();
        XMLTools.writeFile(file, sig.getPrimaryReferenceElement());

        Document doc = XMLTools.loadDocument(file);
        assertValidEnvelopedSignature(doc);

    }

    private void assertValidEnvelopedSignature(Document doc) throws XMLSecurityException {
        try {
            XMLSignature sig = new EnvelopedSignature(doc.getRootElement());
            assertTrue("Signature Verified", true);
        } catch (InvalidSignatureException e) {
            assertTrue("Signature Failed", false);
        }
    }


    private Signer signer;
}
