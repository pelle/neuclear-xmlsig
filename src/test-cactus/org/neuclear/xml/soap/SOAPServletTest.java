package org.neuclear.xml.soap;

import org.apache.cactus.ServletTestCase;
import org.apache.cactus.WebRequest;
import org.neuclear.commons.NeuClearException;
import org.neuclear.xml.XMLException;


import javax.servlet.ServletException;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;

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

$Id: SOAPServletTest.java,v 1.2 2003/12/12 12:32:49 pelle Exp $
$Log: SOAPServletTest.java,v $
Revision 1.2  2003/12/12 12:32:49  pelle
Working on getting the SOAPServletTest working under cactus

Revision 1.1  2003/11/24 23:37:33  pelle
Testcase for SOAPServlet

*/

/**
 * User: pelleb
 * Date: Nov 24, 2003
 * Time: 4:39:55 PM
 */
public class SOAPServletTest extends ServletTestCase{

   public void beginReceiveSOAP(WebRequest theRequest) throws GeneralSecurityException, NeuClearException, XMLException, IOException {

        theRequest.setContentType("text/xml");
        theRequest.addHeader("SOAPAction:","/Receive");
        theRequest.setURL("http://users.neuclear.org", "/test", "/Service",
                null, null);
       ByteArrayOutputStream bos=new ByteArrayOutputStream();
       SOAPTools.createSoapRequestString(bos,"<test/");
       theRequest.setUserData(new ByteArrayInputStream(bos.toByteArray()));
     }

    public void testReceiveSOAP() throws ServletException, IOException {
        EchoSOAPServlet servlet = new EchoSOAPServlet();
        servlet.init(config);
        servlet.service(request, response);
        assertNotNull(servlet.getLast());

    }
}
