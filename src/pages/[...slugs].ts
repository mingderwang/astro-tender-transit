// pages/[...slugs].ts
import { Elysia, t } from "elysia";
import { swagger } from "@elysiajs/swagger";

import {
  // Authentication
  generateAuthenticationOptions,
  // Registration
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
} from "@simplewebauthn/server";

import { base64UrlEncode } from "../utils";

type Store = {
  counter: number;
};

const { RP_ID = "localhost" } = process.env;
const rpID = RP_ID;
const username = "ming";
const devices: any = [];

function generateChallenge() {
  const challenge = new Uint8Array(86); // 32 bytes = 256 bits
  crypto.getRandomValues(challenge);
  return challenge;
}

const opts: GenerateRegistrationOptionsOpts = {
  rpName: "SimpleWebAuthn Example",
  rpID,
  userName: username,
  timeout: 60000,
  attestationType: "none",
  challenge: generateChallenge(),
  /**
   * Passing in a user's list of already-registered authenticator IDs here prevents users from
   * registering the same device multiple times. The authenticator will simply throw an error in
   * the browser if it's asked to perform registration when one of these ID's already resides
   * on it.
   */
  excludeCredentials: devices.map((dev: any) => ({
    id: dev.credentialID,
    type: "public-key",
    transports: dev.transports,
  })),
  authenticatorSelection: {
    residentKey: "discouraged",
    /**
     * Wondering why user verification isn't required? See here:
     *
     * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
     */
    userVerification: "preferred",
  },
  /**
   * Support the two most common algorithms: ES256, and RS256
   */
  supportedAlgorithmIDs: [-7, -257],
};

const app = new Elysia()
  .state("counter", 0)
  .get("/count", ({ store }) => store.counter++)
  .get("passkey/challenge", () => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const encoded = base64UrlEncode(challenge);

    return {
      text: encoded,
      challenge: challenge,
    };
  })
  .get("/generate-registration-options", () => {
    const options = generateAuthenticationOptions(opts);
    return options;
  })
  .get("/generate-authentication-options", () => {
    const options = generateAuthenticationOptions(opts);
    return options;
  })
  .post("/verify-registration", ({ body, error }) => {

  })
  .post("/verify-authentication", ({ body, error }) => {
    
  })
  .use(swagger())
  .post(
    "/user/profile",
    ({ body, error }) => {
      if (body.age < 18) return error(400, "Oh no");

      if (body.name === "Nagisa") return error(418);

      return body;
    },
    {
      body: t.Object({
        name: t.String(),
        age: t.Number(),
      }),
    }
  );

export type App = typeof app;

const handle = ({ request }: { request: Request }) => app.handle(request);

export const GET = handle;
export const POST = handle;
export const PATCH = handle;
