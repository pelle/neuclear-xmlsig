package org.neuclear.xml.xmlsec;

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
public class EnvelopedSignature extends XMLSignature {
    public EnvelopedSignature(Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(XMLSecTools.getSignatureElement(elem));
    }

    public EnvelopedSignature(String name, Signer signer, Element elem) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        super(name, signer);
        si.setEnvelopedReference(elem);
        elem.add(getElement());
        sign(name, signer);
    }

    public EnvelopedSignature(KeyPair kp, Element elem) throws XMLSecurityException {
        super(kp.getPublic());
        si.setEnvelopedReference(elem);
        elem.add(getElement());
        sign(kp);
    }

    protected void verifyReferencesStructure() throws InvalidReferencesException {
        List refs = si.getReferences();
        if (refs.size() != 1)
            throw new InvalidReferencesException(refs.size());
        if (!Utility.isEmpty(si.getPrimaryReference().getUri()))
            throw new InvalidReferencesException();

    }
}
