import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";
import { randomBytes } from "crypto";
import db from "./db/db";
import { verifyAttestation } from "./security/attestation";
import { verifyAssertion } from "./security/assertion";

dotenv.config();

const app: Express = express();
const port = process.env.PORT || 3000;

app.get("/", (req: Request, res: Response) => {
  res.send("App Attest Example!");
});

app.get("/restricted/", (req: Request, res: Response) => {

  // Top Secret Data for Our App Only!
  res.send({
    secureData: "Top secret information"
  })

});

app.get("/challenge/", (req: Request, res: Response) => {
  const challenge = randomBytes(32).toString('base64');
  db.storeChallenge(challenge)
  res.status(200).send(challenge)
});

app.post("/verifyAttestation/", (req: Request, res: Response) => {
  try {
    const attestation = req.body['attestation'] as string
    const challenge = req.body['challenge'] as string
    const keyId = req.body['keyId'] as string

    // ensure that a previous challenge is included in the request
    if(!db.findChallenge(challenge)) { 
      throw new Error('No matching challenge found')
    } 

    // challenges are one time use
    db.deleteChallenge(challenge)

    // verify attestation is valid, using Apple's 9 steps 
    const result = verifyAttestation({
      attestation: attestation,
      challenge: challenge,
      keyId: keyId,
      bundleId: process.env.BUNDLE_ID!,
      teamId: process.env.TEAM_ID!,
      allowDev: true
    })

    // save the public key decoded from the attestation
    db.storeAttestation({
      keyId: keyId,
      publicKey: result.publicKey,
      signCount: 0
    })

    res.sendStatus(204);

  } catch(error: any) {
    console.error(`error stack: ${error.stack}`)
    res.sendStatus(401);
  }
});

app.get("/auth/restricted/", (req: Request, res: Response) => {

  try {
    const keyId = req.headers['keyid'] as string;
    const assertion = req.headers['assertion'] as string;
    const challenge = req.headers['challenge'] as string;

    if(!db.findChallenge(challenge)) {
      throw new Error('invalid challenge');
    }

    db.deleteChallenge(challenge);

    const attestation = db.findAttestation(keyId);
    if(!attestation) {
      throw new Error('No Attestation!');
    }

    const result = verifyAssertion({
      assertion: Buffer.from(assertion, 'base64'),
      payload: JSON.stringify(req.body),
      publicKey: attestation.publicKey,
      bundleId: process.env.BUNDLE_ID!,
      teamId: process.env.TEAM_ID!,
      signCount: attestation.signCount,
    });

    db.storeAttestation({keyId: keyId, publicKey: attestation.publicKey, signCount: result.signCount });

    res.status(200).send({
      secureData: "Top secret information"
    });
  } catch(error) {
    res.status(401).send({error: error})
  }
});

app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
});