package org.neuclear.xml.xmlsec;

import org.dom4j.Element;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.BrowsableSigner;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;

import java.security.KeyPair;
import java.util.List;

/**
 * This is a standard Enveloped Signature with only one Reference object.
 */
public class EnvelopedSignature extends XMLSignature {
    /**
     * Verifies the given element. The Element can be either the Signature element embedded within another element or
     * the parent element it self.
     *
     * @param elem
     * @throws XMLSecurityException
     * @throws InvalidSignatureException
     */
    public EnvelopedSignature(Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(XMLSecTools.getSignatureElement(elem));
    }

    /**
     * Creates a standard Enveloped Signature within the given Element.
     * Uses the provided Signer and Alias to sign it.
     *
     * @param name
     * @param signer
     * @param elem
     * @throws XMLSecurityException
     * @throws UserCancellationException
     * @throws NonExistingSignerException
     * @see Signer
     */
    public EnvelopedSignature(String name, Signer signer, Element elem) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        super(name, signer);
        si.setEnvelopedReference(elem);
        elem.add(getElement());
        sign(name, signer);
    }

    /**
     * Creates a standard Enveloped Signature within the given Element.
     * Uses the provided Signer and Alias to sign it.
     *
     * @param signer
     * @param elem
     * @throws XMLSecurityException
     * @throws UserCancellationException  
     * @throws NonExistingSignerException
     * @see Signer
     */
    public EnvelopedSignature(BrowsableSigner signer, Element elem) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        super(new SignedInfo(SignedInfo.SIG_ALG_RSA, 1));
        si.setEnvelopedReference(elem);
        elem.add(getElement());
        sign(signer);
    }


    /**
     * Creates a standard Enveloped Signature within the given Element.
     * Uses the provided KeyPair to sign it.
     *
     * @param kp
     * @param elem
     * @throws XMLSecurityException
     */
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
