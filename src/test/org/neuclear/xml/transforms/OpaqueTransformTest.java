package org.neuclear.xml.transforms;


/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 21, 2003
 * Time: 3:12:00 PM
 * $Id: OpaqueTransformTest.java,v 1.1 2003/11/11 16:33:31 pelle Exp $
 * $Log: OpaqueTransformTest.java,v $
 * Revision 1.1  2003/11/11 16:33:31  pelle
 * Initial revision
 *
 * Revision 1.1  2003/01/21 22:01:44  pelle
 * Added a bunch of test cases for Transforms.
 * Also several new transforms are there.
 * I have a feeling I didn't think this through, so dont use the Transform bit yet.
 * NB. None of it is used yet by the actual signing process so dont worry.
 *
 */

import org.dom4j.Element;

public class OpaqueTransformTest extends AbstractTransformTest {
    public OpaqueTransformTest(String s) {
        super(s);
    }

    public Transform createTransform() {
        return new OpaqueTransform();
    }

    public Element getExpectedResult() {
        return null;
    }
}
