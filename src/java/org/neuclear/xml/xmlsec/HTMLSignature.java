package org.neuclear.xml.xmlsec;

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
import org.dom4j.Element;
import org.dom4j.io.DOMReader;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.BrowsableSigner;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;
import org.w3c.tidy.Tidy;

import java.io.InputStream;
import java.util.List;

/**
 * This is a standard Enveloped Signature with only one Reference object.
 */
public class HTMLSignature extends XMLSignature {
    /**
     * Creates a standard Enveloped Signature within the given Element.
     * Uses the provided Signer and Alias to sign it.
     *
     * @param name
     * @param signer
     * @param is
     * @throws XMLSecurityException
     * @throws org.neuclear.commons.crypto.passphraseagents.UserCancellationException
     *
     * @throws org.neuclear.commons.crypto.signers.NonExistingSignerException
     *
     * @see org.neuclear.commons.crypto.signers.Signer
     */
    public HTMLSignature(String name, Signer signer, InputStream is) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        this(name, signer, parseHTML(is));
    }

    private static Document parseHTML(InputStream is) {
        Tidy tidy = new Tidy();
        tidy.setXmlOut(true);
        org.w3c.dom.Document dom = tidy.parseDOM(is, null);
        DOMReader reader = new DOMReader();
        Document doc = reader.read(dom);
        return doc;
    }

    public HTMLSignature(String name, Signer signer, Document doc) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        super(name, signer);
        Element html = doc.getRootElement();
        createHTMLBadge(html);
        si.getElement().addAttribute("style", DIGESTSTYLE);
        si.setEnvelopedReference(html);
        html.add(getElement());
        sign(name, signer);
        sigval.addAttribute("style", SIGSTYLE);
        final Element ki = getElement().element("KeyInfo");
        if (ki != null) ki.addAttribute("style", KEYSTYLE);
    }


    public HTMLSignature(BrowsableSigner signer, Document doc) throws XMLSecurityException, UserCancellationException {
        super(new SignedInfo(SignedInfo.SIG_ALG_RSA, 1));
        Element html = doc.getRootElement();
        createHTMLBadge(html);
        si.getElement().addAttribute("style", DIGESTSTYLE);
        si.setEnvelopedReference(html);
        html.add(getElement());
        sign(signer);
        sigval.addAttribute("style", SIGSTYLE);
        final Element ki = getElement().element("KeyInfo");
        if (ki != null) ki.addAttribute("style", KEYSTYLE);
    }

    /**
     * Creates a standard Enveloped Signature within the given Element.
     * Uses the provided Signer and Alias to sign it.
     *
     * @param signer
     * @param is
     * @throws XMLSecurityException
     * @throws org.neuclear.commons.crypto.passphraseagents.UserCancellationException
     *
     * @see org.neuclear.commons.crypto.signers.Signer
     */
    public HTMLSignature(BrowsableSigner signer, InputStream is) throws XMLSecurityException, UserCancellationException {
        this(signer, parseHTML(is));
    }


    private void createHTMLBadge(Element elem) {
        Element head = elem.element("head");
        Element body = elem.element("body");
//        body.addElement("hr");
        Element title = body.addElement("p");
        title.addAttribute("id", "dsigtitle");
        title.addAttribute("style", TITLESTYLE);
        title.setText("This page has been digitally signed.");
        body.addText("\n");
    }

    protected void verifyReferencesStructure() throws InvalidReferencesException {
        List refs = si.getReferences();
        if (refs.size() != 1)
            throw new InvalidReferencesException(refs.size());
        if (!Utility.isEmpty(si.getPrimaryReference().getUri()))
            throw new InvalidReferencesException();

    }

    private static final String TITLESTYLE = "background:#00B; font-family:sans-serif; font-size: small;color:white";
    private static final String SIGSTYLE = "background:#EEF; font-family:monospace; font-size: xx-small; color:#004;display:block";
    private static final String KEYSTYLE = "display:none";
//    private static final String DIGESTSTYLE = "display:none";
//    private static final String KEYSTYLE = "background:#EFE; font-family:monospace; font-size: xx-small; color:#040;display:block;white-space:pre";
    private static final String DIGESTSTYLE = "background:#FEE; font-family:monospace; font-size: xx-small; color:#400;display:block";
}
