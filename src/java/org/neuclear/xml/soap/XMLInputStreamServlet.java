package org.neuclear.xml.soap;

import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.Base64;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
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

$Id: XMLInputStreamServlet.java,v 1.4 2003/11/28 00:12:36 pelle Exp $
$Log: XMLInputStreamServlet.java,v $
Revision 1.4  2003/11/28 00:12:36  pelle
Getting the NeuClear web transactions working.

Revision 1.3  2003/11/22 00:23:18  pelle
All unit tests in commons, id and xmlsec now work.
AssetController now successfully processes payments in the unit test.
Payment Web App has working form that creates a TransferRequest presents it to the signer
and forwards it to AssetControlServlet. (Which throws an XML Parser Exception) I think the XMLReaderServlet is bust.

Revision 1.2  2003/11/21 04:44:30  pelle
EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
Otherwise You will Finaliate.
Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
This should hopefully make everything more stable (and secure).

Revision 1.1.1.1  2003/11/11 16:33:23  pelle
Moved over from neudist.org
Moved remaining common utilities into commons

Revision 1.2  2003/11/09 03:27:09  pelle
More house keeping and shuffling about mainly pay

Revision 1.1  2003/09/26 23:52:47  pelle
Changes mainly in receiver and related fun.
First real neuclear stuff in the payment package. Added TransferContract and AssetControllerReceiver.

*/

/**
 * User: pelleb
 * Date: Sep 25, 2003
 * Time: 1:07:57 PM
 */
public abstract class XMLInputStreamServlet extends HttpServlet {
    public void init(ServletConfig servletConfig) throws ServletException {
        ctx = servletConfig.getServletContext();
    }

    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        final PrintWriter out = response.getWriter();
        out.println("<html><head><title>SOAP Servlet</title></head><body>");
        out.println("<h3>");
        out.println(getClass().getName());
        out.println(" doesnt support GET</h3>");
        out.println("</body></html>");
        out.flush();
        out.close();


    }

    protected void doPost(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream is = null;

            if (request.getContentType().equals("text/xml")) {
                ctx.log("XMLSIG: Got xml encoded neuclear-request");
                is = request.getInputStream();
            }
            if (!Utility.isEmpty(request.getParameter("neuclear-request"))) {
                ctx.log("XMLSIG: Got form encoded neuclear-request");
                is = new ByteArrayInputStream(Base64.decode(request.getParameter("neuclear-request")));
            }
            if (is != null)
                handleInputStream(is, request, response);
            else {
                PrintWriter writer = response.getWriter();
                final boolean isXML = request.getContentType().equals("text/xml");
                if (isXML) {
                    response.setContentType("text/xml");
                } else {
                    response.setContentType("text/html");
                    writer.print("<html><head><title>XMLInputStreamServlet Error</title></head><body>");
                }
                writer.println("<h1>Error: Empty Request</h1><h3>");
                writer.println("</h3><pre>");


            }
        } catch (Exception e) {
            PrintWriter writer = response.getWriter();
            final boolean isXML = request.getContentType().equals("text/xml");
            if (isXML) {
                response.setContentType("text/xml");
            } else {
                response.setContentType("text/html");
                writer.print("<html><head><title>XMLInputStreamServlet Error</title></head><body>");
            }
            writer.println("<h1>Error</h1><h3>");
            writer.println(e.getLocalizedMessage());
            writer.println("</h3><pre>");
            e.printStackTrace(writer);
            writer.println("</pre>");
        }

    }


    protected abstract void handleInputStream(InputStream is, HttpServletRequest request, HttpServletResponse response) throws IOException;

    protected ServletContext ctx;

}
