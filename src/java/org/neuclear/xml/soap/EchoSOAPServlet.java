package org.neuclear.xml.soap;

import org.dom4j.Element;

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

$Id: EchoSOAPServlet.java,v 1.2 2003/12/12 12:32:49 pelle Exp $
$Log: EchoSOAPServlet.java,v $
Revision 1.2  2003/12/12 12:32:49  pelle
Working on getting the SOAPServletTest working under cactus

Revision 1.1  2003/11/24 23:33:15  pelle
More Cactus unit testing going on.

*/

/**
 * User: pelleb
 * Date: Nov 24, 2003
 * Time: 4:35:18 PM
 */
public class EchoSOAPServlet extends SOAPServlet {

    protected Element handleSOAPRequest(Element request, String soapAction) throws SOAPException {
        last=request;
        return request;
    }

    public Element getLast() {
        return last;
    }

    private Element last;
}
