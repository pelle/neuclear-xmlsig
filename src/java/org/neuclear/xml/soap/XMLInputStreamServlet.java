package org.neuclear.xml.soap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

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

$Id: XMLInputStreamServlet.java,v 1.1 2003/11/11 16:33:23 pelle Exp $
$Log: XMLInputStreamServlet.java,v $
Revision 1.1  2003/11/11 16:33:23  pelle
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
 * Date: Sep 25, 2003
 * Time: 1:07:57 PM
 */
public abstract class XMLInputStreamServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><head><title>SOAP Servlet</title></head><body>");
        out.println("<h3>");
        out.println(getClass().getName());
        out.println(" doesnt support GET</h3>");
        out.println("</body></html>");
        out.flush();
        out.close();


    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if (request.getContentType().equals("text/xml")) {
            InputStream is = request.getInputStream();
            handleInputStream(is, request, response);
        }
    }

    protected abstract void handleInputStream(InputStream is, HttpServletRequest request, HttpServletResponse response) throws IOException;
}
