package org.neuclear.xml.soap;

/**
 * @author pelleb
 * @version $Revision: 1.1 $
 */

/*
 *  The NeuClear Project and it's libraries are
 *  (c) 2002-2004 Antilles Software Ventures SA
 *  For more information see: http://neuclear.org
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.neuclear.commons.NeuClearException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public final class RESTTools {
    private RESTTools() {
    }


    public static Element restRequestElement(final String endpoint, final Element request) throws NeuClearException {
        try {
            return restRequestElement(new URL(endpoint), request);
        } catch (MalformedURLException e) {
            throw new NeuClearException(e);
        }
    }

    public static InputStream restRequest(final String endpoint, final String request) throws NeuClearException {
        try {
            return restRequest(new URL(endpoint), request);
        } catch (MalformedURLException e) {
            throw new NeuClearException(e);
        }
    }

    public static Element restRequestElement(final URL endpoint, final Element request) throws NeuClearException {
        try {
            return restRequestElement(endpoint.openConnection(), request);
        } catch (IOException e) {
            throw new NeuClearException(e);
        }

    }

    public static InputStream restRequest(final URL endpoint, final String request) throws NeuClearException {
        try {
            return restRequest(endpoint.openConnection(), request);
        } catch (IOException e) {
            throw new NeuClearException(e);
        }
    }

    public static InputStream restRequest(final URLConnection conn, final Element request) throws NeuClearException {
        return restRequest(conn, request.asXML());
    }

    public static InputStream restRequest(final URLConnection conn, final String request) throws NeuClearException {
        try {
            //Set Headers
            conn.setDoOutput(true);
            conn.setDoInput(true);
            if (conn instanceof HttpURLConnection) {
                ((HttpURLConnection) conn).setRequestMethod("POST");
                ((HttpURLConnection) conn).setRequestProperty("Content-type", "text/xml");
            }
            final OutputStream out = conn.getOutputStream();
            out.write(request.getBytes());
            out.close();

            return conn.getInputStream();
//            final InputStream stream = conn.getInputStream();
//            final ByteArrayOutputStream bos=new ByteArrayOutputStream();
//            byte b[]=new byte[1024];
//            int c=stream.read(b);
//            while(c>=0){
//                bos.write(b,0,c);
//                c=stream.read(b);
//            }
//            final byte[] bytes = bos.toByteArray();
//            System.out.println(new String(bytes));
//            return new ByteArrayInputStream(bytes);
        } catch (IOException e) {
            throw new NeuClearException(e);
        }
    }


    public static Element restRequestElement(final URLConnection conn, final Element request) throws NeuClearException, IOException {
        try {
            final BufferedReader in = new BufferedReader(new InputStreamReader(restRequest(conn, request)));
            final SAXReader reader = new SAXReader();
            final Document document = reader.read(in);
            in.close();
            return document.getRootElement();
        } catch (DocumentException e) {
            throw new NeuClearException(e);
        }
    }


}
