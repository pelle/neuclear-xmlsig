package org.neuclear.xml.c14;

import junit.framework.TestCase;

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

$Id: SimpleCanonicalizationTest.java,v 1.1 2004/03/02 23:30:44 pelle Exp $
$Log: SimpleCanonicalizationTest.java,v $
Revision 1.1  2004/03/02 23:30:44  pelle
Renamed SignatureInfo to SignedInfo as that is the name of the Element.
Made some changes in the Canonicalizer to make all the output verify in Aleksey's xmlsec library.
Unfortunately this breaks example 3 of merlin-eight's canonicalization interop tests, because dom4j afaik
can't tell the difference between <test/> and <test xmlns=""/>.
Changed XMLSignature it is now has less repeated code.

*/

/**
 * User: pelleb
 * Date: Mar 2, 2004
 * Time: 9:08:25 PM
 */
public class SimpleCanonicalizationTest extends TestCase {

    public void testCanonical() {

    }

    private static final String orig = "";
}
