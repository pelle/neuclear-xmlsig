package org.neuclear.xml.soap;

import org.apache.cactus.ServletTestCase;
import org.apache.cactus.WebRequest;
import org.neuclear.commons.crypto.Base64;

import javax.servlet.ServletException;
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

$Id: XMLInputStreamServletTest.java,v 1.2 2003/11/28 00:12:36 pelle Exp $
$Log: XMLInputStreamServletTest.java,v $
Revision 1.2  2003/11/28 00:12:36  pelle
Getting the NeuClear web transactions working.

Revision 1.1  2003/11/24 16:49:25  pelle
Added Cactus testing structure.


*/

public class XMLInputStreamServletTest extends ServletTestCase {
    public static final String TESTSTRING = "test one two three";


    public void beginBase64(final WebRequest theRequest) {
        theRequest.addParameter("neuclear-request", Base64.encode(TESTSTRING.getBytes()), "POST");
        theRequest.setContentType("application/x-www-form-urlencoded");
        theRequest.setURL("http://users.neuclear.org", "/test", "/Service",
                null, null);
    }

    public void testBase64() throws IOException, ServletException {
        assertEquals(request.getContentType(), "application/x-www-form-urlencoded");
        final MockXMLInputStreamServlet servlet = new MockXMLInputStreamServlet();
        servlet.init(config);
        servlet.service(request, response);
        assertEquals(TESTSTRING, servlet.getLastInput());

    }
}
