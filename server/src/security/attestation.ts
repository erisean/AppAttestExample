import * as cbor from 'cbor'
import { fromBER } from 'asn1js'
import { Certificate as PKICertificate }  from 'pkijs'
import { createHash, X509Certificate } from 'crypto'

const APPLE_ROOT_CA_CERTIFICATE_SUBJECT = 'Apple App Attestation CA 1'
const APPLE_APP_ATTESTATION_ROOT_CA = new X509Certificate('-----BEGIN CERTIFICATE-----\nMIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD\n-----END CERTIFICATE-----');
const OID_EXTENSION = '1.2.840.113635.100.8.2'
const APP_ATTEST_AAGUID_DEV = Buffer.from('appattestdevelop').toString('hex')
const APP_ATTEST_AAGUID_PROD = Buffer.concat([Buffer.from('appattest'), Buffer.from([0x00,0x00,0x00,0x00,0x00,0x00,0x00])]).toString('hex')

interface AttestationParameters {
    attestation: string,
    challenge: string,
    keyId: string,
    bundleId: string,
    teamId: string,
    allowDev: boolean
}

interface Attestation {
    fmt: string,
    attStmt: AttestationStatement,
    authData: Buffer
}

interface AttestationStatement {
    x5c: Buffer[],
    receipt: Buffer
}

interface AttestationResult {
    keyId: string,
    publicKey: Buffer | string,
    receipt: Buffer,
    environment: string
}

export function verifyAttestation(params: AttestationParameters): AttestationResult { 

    try {

        // Decode the attestation
        const buffer = Buffer.from(params.attestation, 'base64')
        if(!buffer) { throw new Error('Failed to create buffer!'); }
    
        const decoded = cbor.decodeAllSync(buffer)
        if(!decoded) { throw new Error('Failed to decode buffer!'); }
        if(decoded.length != 1) { throw new Error('Unexpected decoded length!'); }
    
        const attestation: Attestation = decoded[0];
        if(!attestation) { throw new Error('Failed create attestation object!'); }
        if(
            attestation.fmt != 'apple-appattest'
            || attestation.attStmt.x5c.length != 2
            || !attestation.authData
            || !attestation.attStmt.receipt
        ) { 
            throw new Error('Invalid Attestation') 
        }

        // 1. verify that the x5c array contains the intermediate and leaf certificates for App Attest
        const certs = attestation.attStmt.x5c.map((val) => new X509Certificate(val))
        if(certs.length != 2) { throw new Error('Wrong Number of Certificates') }
    
        const intermediateCert = certs.find((val) => val.subject.includes(APPLE_ROOT_CA_CERTIFICATE_SUBJECT))
        if(!intermediateCert) { throw new Error('No CA certificate') }
        if(!intermediateCert.verify(APPLE_APP_ATTESTATION_ROOT_CA.publicKey)) { throw new Error('Invalid Intermediate Certificate!'); }
    
        const clientCertificate = certs.find((val) => !val.subject.includes(APPLE_ROOT_CA_CERTIFICATE_SUBJECT))
        if(!clientCertificate) { throw new Error('No Client certificate'); }
        if(!clientCertificate.verify(intermediateCert.publicKey)) { throw new Error('Invalid Leaf Certificate!'); }


        // 2a. create clientDataHash as the SHA256 hash of the one-time challenge
        const clientDataHash = createHash('sha256').update(params.challenge).digest();


        // 2b. append hash to the end of the auth data
        const authHash = Buffer.concat([attestation.authData, clientDataHash]);


        // 3. generate a new SHA256 hash of the composite item to create nonce
        const nonceHash = createHash('sha256').update(authHash).digest('hex');


        // 4a. obtain value of the credCert extension with OID 1.2.840.113635.100.8.2
        const asn1Sequence = fromBER(clientCertificate.raw).result
        const credCert = new PKICertificate({ schema: asn1Sequence })


        // 4b. decode the sequence and extract the single octet string it contains
        const extension = credCert.extensions?.find( (val) => val.extnID === OID_EXTENSION )
        if(!extension) { throw new Error('Failed to find credCert extension'); }
        const octetString = Buffer.from(extension.parsedValue.valueBlock.value[0].valueBlock.value[0].valueBlock.valueHex).toString('hex')
        if (!octetString) { throw new Error('Failed to create new octet from extension'); }


        // 4c. verify string equals nonce
        if(octetString !== nonceHash) { throw new Error('Nonce not equal.'); }


        // 5a. create SHA256 Hash of the public key in credCert with X9.62 uncompressed point format
        const publicKeyBuffer = Buffer.from(credCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)
        const publicKeyHash = createHash('sha256').update(publicKeyBuffer.toString('hex'), 'hex').digest('base64')


        // 5b. verify public key hash matches the key identifier from the app
        if(publicKeyHash !== params.keyId) { throw new Error('Public Key does not match KeyId'); }


        // 6a. compute SHA256 hash of app's app ID
        const appHash = createHash('sha256').update(`${params.teamId}.${params.bundleId}`).digest('base64');


        // 6b. verify app hash is the same authData's RP ID hash
        if(appHash !== attestation.authData.subarray(0, 32).toString('base64')) { throw new Error('Invalid App Id'); }


        // 7. verify that the authenticator data's counter field equals 0
        if(attestation.authData.subarray(33, 37).readInt32BE() !== 0) { throw new Error('Invalid counter field'); }


        // 8. verify the authenticator data's aaguid field is correct for either dev or prod
        const aaguid = attestation.authData.subarray(37, 53).toString('hex');

        let isDev: boolean;
        if(params.allowDev) {
            if(aaguid !== APP_ATTEST_AAGUID_DEV && aaguid !== APP_ATTEST_AAGUID_PROD) {
                throw new Error('Invalid aaguid')
            }
            isDev = aaguid === APP_ATTEST_AAGUID_DEV
        } else {
            if(aaguid !== APP_ATTEST_AAGUID_PROD) {
                throw new Error('Invalid aaguid')
            }
            isDev = false
        }


        // 9. verify that the authenticator data's credentialId field is the same as the key identifier
        const credIdLen = attestation.authData.subarray(53, 55).readInt16BE();
        const credId = attestation.authData.subarray(55, credIdLen + 55).toString('base64');
        if(credId !== params.keyId) { throw new Error('Invalid Credential Id') }


        return  {
            keyId: params.keyId,
            publicKey: clientCertificate.publicKey.export({ type: 'spki', format: 'pem'}),
            receipt: attestation.attStmt.receipt,
            environment: isDev ? 'development' : 'production'
        }

    } catch(error) {
        throw error;
    }
}