package org.neuclear.xml.soap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

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

$Id: MockXMLInputStreamServlet.java,v 1.2 2003/11/24 23:33:15 pelle Exp $
$Log: MockXMLInputStreamServlet.java,v $
Revision 1.2  2003/11/24 23:33:15  pelle
More Cactus unit testing going on.

Revision 1.1  2003/11/24 16:49:25  pelle
Added Cactus testing structure.


*/

public class MockXMLInputStreamServlet extends XMLInputStreamServlet {
    protected void handleInputStream(final InputStream is, final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (is == null) {
            lastInput = null;
            return;
        }
        final BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        lastInput = reader.readLine();

    }

    public String getLastInput() {
        return lastInput;
    }

    private String lastInput = null;

}
