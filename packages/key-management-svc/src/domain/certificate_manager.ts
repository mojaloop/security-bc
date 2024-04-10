"use strict";

import crypto from "crypto";
import forge, { pki } from "node-forge";

import { CertificatesHelper } from "@mojaloop/security-bc-client-lib";
import { ISecureCertificateStorage } from "./isecure_storage";
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { ICSRRequest, IDecodedCertificateInfo, IPublicCertificate } from "@mojaloop/security-bc-public-types-lib";

interface KeyPairResult {
    privateKeyPem: string;
    cert: IPublicCertificate;
}
export class CertificateManager {
    private _caPubKeyPem: string;
    private _caPrivateKeyPem: string;
    private _caPubCert: forge.pki.Certificate;
    private _caPrivateKey: forge.pki.PrivateKey;
    private _ca_store: pki.CAStore = pki.createCaStore();
    private _secureStorage: ISecureCertificateStorage;
    private _logger: ILogger;

    constructor(secureStorage: ISecureCertificateStorage, logger: ILogger) {
        this._secureStorage = secureStorage;
        this._logger = logger.createChild(this.constructor.name);
    }

    async init() {
        const {privateKeyPem, cert} = await this._checkKeyOrGenerateCAKeyPair(this._secureStorage, this._logger);
        this._caPubKeyPem = cert.pubCertificatePem;
        this._caPrivateKeyPem = privateKeyPem;

        this._caPubCert = forge.pki.certificateFromPem(this._caPubKeyPem);
        this._caPrivateKey = forge.pki.privateKeyFromPem(this._caPrivateKeyPem);

        this._ca_store.addCertificate(pki.certificateFromPem(this._caPubKeyPem));
    }

    async signAndStorePublicCertFromCSR(csrRequestId: string, csrRequest: ICSRRequest): Promise<IPublicCertificate> {
        const csrPem = csrRequest.csrPEM;
        const participantId = csrRequest.participantId;
        const participantCSR = forge.pki.certificationRequestFromPem(csrPem);

        if (participantCSR.publicKey === null) {
            throw new Error("CSR public key is null.");
        }

        if (!participantCSR.verify()) {
            throw new Error("CSR verification failed.");
        }

        const newParticipantCert = forge.pki.createCertificate();
        newParticipantCert.serialNumber = this._generateSerialNumber();
        newParticipantCert.validity.notBefore = new Date();
        newParticipantCert.validity.notAfter = new Date();
        newParticipantCert.validity.notAfter.setFullYear(newParticipantCert.validity.notBefore.getFullYear() + 2); // 2 year validity

        newParticipantCert.setSubject(participantCSR.subject.attributes); // use the same subject as the CSR
        newParticipantCert.setIssuer(this._caPubCert.subject.attributes); // use the CA subject as the issuer
        newParticipantCert.publicKey = participantCSR.publicKey;

        const extensions = [
            {
                name: "basicConstraints",
                cA: false
            },
            {
                name: "keyUsage",
                keyCertSign: true,
                digitalSignature: true,
                nonRepudiation: true,
                keyEncipherment: true,
                dataEncipherment: true,
            },
        ];
        newParticipantCert.setExtensions(extensions);

        newParticipantCert.sign(this._caPrivateKey, forge.md.sha256.create());
        const clientCertPem = forge.pki.certificateToPem(newParticipantCert);

        const subjectString = newParticipantCert.subject.attributes.map(attr => `${attr.shortName}=${attr.value}`).join(", ");
        const decodedCertInfo: IDecodedCertificateInfo = {
            subject: subjectString,
            issuer: newParticipantCert.issuer.getField("CN").value,
            validFrom: newParticipantCert.validity.notBefore.toISOString(),
            validTo: newParticipantCert.validity.notAfter.toISOString(),
            serialNumber: newParticipantCert.serialNumber,
            signatureAlgorithm: newParticipantCert.signature.algorithm,
            extensions
        };

        const pubCert: IPublicCertificate = {
            csrRequestId,
            keyFingerprint: forge.md.sha1.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(newParticipantCert)).getBytes()).digest().toHex(),
            participantId: participantId,
            certType: "DFSP",
            pubCertificatePem: clientCertPem,
            decodedCertInfo,
            createdDate: Date.now(),
        };
        const certId = await this._secureStorage.storePublicCert(participantId, pubCert);
        pubCert.id = certId;
        return pubCert;
    }

    getHubCAPubCert(): string {
        return this._caPubKeyPem;
    }

    verifyCert(certPem: string): boolean {
        const cert = pki.certificateFromPem(certPem);
        return pki.verifyCertificateChain(this._ca_store, [cert]);
    }

    async _checkKeyOrGenerateCAKeyPair(secureStorage: ISecureCertificateStorage, logger: ILogger): Promise<KeyPairResult> {
        try {
            const privateKeyPem = await secureStorage.fetchCAHubPrivateKey();
            const cert = await secureStorage.fetchCAHubPublicCert();
            if (!cert) {
                throw new Error("CA Hub public certificate not found in secure storage.");
            }
            return { privateKeyPem, cert };
        } catch (error) {
            // If the CA private key and public key are not found in the secure storage, generate a new keypair
            const certHelper = new CertificatesHelper();
            // Generate a keypair
            const keys = forge.pki.rsa.generateKeyPair(4096);
            const signingKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
            const certPem = certHelper.createX590CertificateAuthorityCert(

                signingKeyPem,
                // commonName, country, state, locality, orgName, orgUnit,
                "vNextHub CA", "US", "Virginia", "Blacksburg", "Mojaloop", "vNextHub CA",
                10);

            await secureStorage.storeCAHubPrivateKey(signingKeyPem);

            const cert = forge.pki.certificateFromPem(certPem);
            const decodedCertInfo: IDecodedCertificateInfo = {
                subject: cert.subject.getField("CN").value,
                issuer: cert.issuer.getField("CN").value,
                validFrom: cert.validity.notBefore.toISOString(),
                validTo: cert.validity.notAfter.toISOString(),
                serialNumber: cert.serialNumber,
                signatureAlgorithm: cert.signature.algorithm,
                extensions: cert.extensions
            };

            const pubCert: IPublicCertificate = {
                participantId: secureStorage.getCAHubID(),
                keyFingerprint: forge.md.sha1.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex(),
                pubCertificatePem: certPem,
                certType: "HUB_CA",
                createdDate: Date.now(),
                decodedCertInfo,
            };
            await secureStorage.storeCAHubRootCert(pubCert);
            logger.createChild("CertificateManager._checkKeyOrGenerateCAKeyPair").info("Generated new CA keypair and stored in secure storage.");
            return { privateKeyPem: signingKeyPem, cert: pubCert };
        }
    }

    _generateSerialNumber(): string {
        // Combine current timestamp with a random component
        const timestamp = Date.now();
        const randomComponent = crypto.randomBytes(8).toString("hex");
        return `${timestamp.toString(16)}${randomComponent}`;
    }
}
