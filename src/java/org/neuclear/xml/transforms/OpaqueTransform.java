package org.neuclear.xml.transforms;
/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 21, 2003
 * Time: 2:53:07 PM
 * $Id: OpaqueTransform.java,v 1.1 2003/11/11 16:33:24 pelle Exp $
 * $Log: OpaqueTransform.java,v $
 * Revision 1.1  2003/11/11 16:33:24  pelle
 * Initial revision
 *
 * Revision 1.2  2003/02/22 16:54:29  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.1  2003/01/21 22:01:43  pelle
 * Added a bunch of test cases for Transforms.
 * Also several new transforms are there.
 * I have a feeling I didn't think this through, so dont use the Transform bit yet.
 * NB. None of it is used yet by the actual signing process so dont worry.
 *
 */

import org.dom4j.Element;
import org.dom4j.Node;
import org.neuclear.xml.xmlsec.XMLSecurityException;

public class OpaqueTransform extends Transform {
    public Object transformNode(Object in) {
        return null;
    }

    public OpaqueTransform() {
        super(ALGORITHM);
    }

    public OpaqueTransform(Element elem) throws XMLSecurityException {
        super(elem);
    }
    public static final String ALGORITHM="uri:neuclear-test-opaque-transform";
    {
        TransformerFactory.registerTransformer(ALGORITHM,OpaqueTransform.class);
    }
}
