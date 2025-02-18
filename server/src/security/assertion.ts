import * as cbor from 'cbor'
import { createHash, createVerify } from 'crypto'

interface Assertion {
    signature: Buffer,
    authenticatorData: Buffer
}

interface AssertionParameters {
    assertion: Buffer,
    payload: any,
    publicKey: string | Buffer,
    bundleId: string,
    teamId: string,
    signCount: number
}

interface AssertionResult {
    signCount: number
}

export function verifyAssertion(params: AssertionParameters): AssertionResult {
    try {
        // Decode the assertion
        const assertion = cbor.decodeAllSync(params.assertion)[0];

        // 1. compute clientDataHash as the sha256 hash of client data
        const clientDataHash = createHash('sha256').update(params.payload).digest();

        // 2. concatenate authenticatorData and clientDataHash and apply hash over result to form nonce
        const nonce = createHash('sha256').update(Buffer.concat([assertion.authenticatorData, clientDataHash])).digest();

        // 3. use public key that you store from the attestation object to verify that the assertion's signature is valid for nonce
        const verify = createVerify('sha256').update(nonce);
        if(!verify.verify(params.publicKey, assertion.signature)) { throw new Error('Invalid assertion signature'); }

        // 4a. compute sha256 hash of the client's app id
        const id = `${params.teamId}.${params.bundleId}`
        const clientAppIdHash = createHash('sha256').update(`${params.teamId}.${params.bundleId}`).digest('base64');

        // 4b. verify it matches the rpId in the authenticator data
        if(clientAppIdHash !== assertion.authenticatorData.subarray(0, 32).toString('base64')) { throw new Error('Invalid app id') }

        // 5. verify that the authenticator data's counter is greater than the value from the previous assertion
        const nextSignCount = assertion.authenticatorData.subarray(33, 37).readInt32BE();
        if(nextSignCount <= params.signCount) { throw new Error('Invalid sign count') }

        return {
            signCount: nextSignCount
        }

    } catch(error) {
        throw error
    }
}