package org.neuclear.xml.xmlsec;

import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;

import java.security.KeyPair;
import java.util.List;

/**
 * This is a standard Enveloped Signature with only one Reference object.
 */
public class ExternalSignature extends XMLSignature {
    public ExternalSignature(Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(elem);
    }

    /**
     * Creates a Signature with a reference to an external URL.
     *
     * @param name
     * @param signer
     * @param url
     * @throws XMLSecurityException
     * @throws UserCancellationException
     * @throws NonExistingSignerException
     */
    public ExternalSignature(String name, Signer signer, String url) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        super(name, signer);
        if (getElement().getDocument() == null)
            DocumentHelper.createDocument(getElement());
        si.addExternalReference(url);
        sign(name, signer);
    }

    public ExternalSignature(KeyPair kp, String url) throws XMLSecurityException {
        super(kp.getPublic());
        if (getElement().getDocument() == null)
            DocumentHelper.createDocument(getElement());
        si.addExternalReference(url);
        sign(kp);
    }

    protected void verifyReferencesStructure() throws InvalidReferencesException {
        List refs = si.getReferences();
        if (refs.size() != 1)
            throw new InvalidReferencesException(refs.size());
        if (Utility.isEmpty(si.getPrimaryReference().getUri()))
            throw new InvalidReferencesException();

    }

}
