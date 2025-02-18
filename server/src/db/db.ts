// MIT License

// Copyright (c) 2024 David Übelacker

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

interface Attestation {
    keyId: string;
    publicKey: string | Buffer<ArrayBufferLike>;
    signCount: number;
  }
  
  const CHALLANGES: Record<string, string> = {};
  const ATTESTATIONS: Record<string, Attestation> = {};
  
  const db = {
    findChallenge: (challenge: string): string | undefined => CHALLANGES[challenge],
    storeChallenge: (challenge: string): void => { CHALLANGES[challenge] = challenge; },
    deleteChallenge: (challenge: string): void => { delete CHALLANGES[challenge]; },
    storeAttestation: (attestation: Attestation): void => {
      if (ATTESTATIONS[attestation.keyId]) {
        ATTESTATIONS[attestation.keyId] = { ...ATTESTATIONS[attestation.keyId], ...attestation };
      } else {
        ATTESTATIONS[attestation.keyId] = attestation;
      }
    },
    findAttestation: (keyId: string): Attestation | undefined => ATTESTATIONS[keyId]
  };
  
  export default db;