package org.neuclear.xml.verifiers;

import org.dom4j.Document;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.XMLTools;
import org.neuclear.xml.xmlsec.XMLSecTools;
import org.neuclear.commons.crypto.CryptoException;

import java.io.InputStream;
import java.security.PublicKey;

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

$Id: Verifier.java,v 1.1 2003/11/11 16:33:30 pelle Exp $
$Log: Verifier.java,v $
Revision 1.1  2003/11/11 16:33:30  pelle
Initial revision

Revision 1.2  2003/11/09 03:27:09  pelle
More house keeping and shuffling about mainly pay

Revision 1.1  2003/09/26 23:52:47  pelle
Changes mainly in receiver and related fun.
First real neuclear stuff in the payment package. Added TransferContract and AssetControllerReceiver.

*/

/**
 * 
 * User: pelleb
 * Date: Sep 23, 2003
 * Time: 4:18:18 PM
 */
public class Verifier {

    public Object verify(InputStream in, PublicKey pub) throws XMLException, CryptoException {
        Document doc = XMLTools.loadDocument(in);
        XMLSecTools.verifySignature(doc.getRootElement(), pub);
        return null;
    }

}
