package org.neuclear.xml.xmlsec;

import junit.framework.TestCase;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.InvalidPassphraseException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.TestCaseSigner;

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

$Id: XMLSignerTest.java,v 1.3 2004/03/08 23:51:04 pelle Exp $
$Log: XMLSignerTest.java,v $
Revision 1.3  2004/03/08 23:51:04  pelle
More improvements on the XMLSignature. Now uses the Transforms properly, References properly.
All the major elements have been refactored to be cleaner and more correct.

Revision 1.2  2004/01/14 06:42:38  pelle
Got rid of the verifyXXX() methods

Revision 1.1  2004/01/13 23:37:59  pelle
Refactoring parts of the core of XMLSignature. There shouldnt be any real API changes.

*/

/**
 * User: pelleb
 * Date: Jan 13, 2004
 * Time: 8:50:32 PM
 */
public class XMLSignerTest extends TestCase {

    public XMLSignerTest(String string) throws InvalidPassphraseException {
        super(string);
        signer = new TestCaseSigner();
    }

    public void testSign() throws DocumentException, XMLSecurityException, NonExistingSignerException, UserCancellationException {
        Document doc = DocumentHelper.parseText("<hello>test</hello>");

        XMLSignature sig = new XMLSignature("neu://bob@test", signer, doc.getRootElement(), true);
        assertTrue(true);
    }

    private final TestCaseSigner signer;
}
