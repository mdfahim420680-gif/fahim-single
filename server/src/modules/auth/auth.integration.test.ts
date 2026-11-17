import test from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { env } from '../../config/env';
import { createExpressApp } from '../../app';
import { signAuthToken } from '../../middleware/auth.middleware';
import { UserModel } from '../users/user.model';
import { AuthSessionModel, UserAuthProviderModel } from './authIdentity.model';
import {
  confirmOAuthLinkAccount,
  resolveOrChallengeOAuthUser,
  unlinkProviderForUser,
} from './auth.service';

async function withHttpServer(fn: (baseUrl: string) => Promise<void>) {
  const app = createExpressApp();
  const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = (server.address() as AddressInfo).port;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
}

async function withMockReadyDb(fn: () => Promise<void>) {
  const desc = Object.getOwnPropertyDescriptor(mongoose.connection, 'readyState');
  Object.defineProperty(mongoose.connection, 'readyState', { value: 1, configurable: true });
  try {
    await fn();
  } finally {
    if (desc) {
      Object.defineProperty(mongoose.connection, 'readyState', desc);
    } else {
      Object.defineProperty(mongoose.connection, 'readyState', { value: 0, configurable: true });
    }
  }
}

function chainableQuery<T>(result: T) {
  return {
    select() {
      return this;
    },
    lean() {
      return Promise.resolve(result);
    },
    then<TResult1 = T, TResult2 = never>(
      onfulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | null,
      onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
    ) {
      return Promise.resolve(result).then(onfulfilled, onrejected);
    },
  };
}

test('GET /api/auth/providers returns 200 without DB and includes Dev + Shared Cloud Run callback URLs', async () => {
  await withHttpServer(async (baseUrl) => {
    const resp = await fetch(`${baseUrl}/api/auth/providers`);
    assert.equal(resp.status, 200);
    const body = (await resp.json()) as {
      ok: boolean;
      providers: {
        emailPassword: boolean;
        google: boolean;
        facebook: boolean;
        googleConfigured: boolean;
        facebookConfigured: boolean;
      };
      callbacks: {
        google: { devCallbackUrl: string; sharedCallbackUrl: string };
        facebook: { devCallbackUrl: string; sharedCallbackUrl: string };
      };
      branding: { effectiveBrandName: string; loginTitle: string };
    };

    const devOrigin = env.APP_URL.replace(/\/$/, '');
    const expectedSharedOrigin = devOrigin.includes('ais-dev-')
      ? devOrigin.replace('ais-dev-', 'ais-pre-')
      : env.CLIENT_URL && env.CLIENT_URL !== devOrigin
        ? env.CLIENT_URL.replace(/\/$/, '')
        : devOrigin;

    assert.equal(body.ok, true);
    assert.equal(body.providers.emailPassword, true);
    assert.equal(typeof body.providers.googleConfigured, 'boolean');
    assert.equal(typeof body.providers.facebookConfigured, 'boolean');
    assert.equal(body.callbacks.google.devCallbackUrl, `${devOrigin}/api/auth/oauth/google/callback`);
    assert.equal(body.callbacks.google.sharedCallbackUrl, `${expectedSharedOrigin}/api/auth/oauth/google/callback`);
    assert.equal(body.callbacks.facebook.devCallbackUrl, `${devOrigin}/api/auth/oauth/facebook/callback`);
    assert.equal(body.callbacks.facebook.sharedCallbackUrl, `${expectedSharedOrigin}/api/auth/oauth/facebook/callback`);
    assert.ok(body.branding.effectiveBrandName.length > 0);
  });
});

test('POST /api/auth/identify normalizes valid email and returns HTTP 400 for malformed email without enumeration', async () => {
  await withHttpServer(async (baseUrl) => {
    const validResp = await fetch(`${baseUrl}/api/auth/identify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: '  Alex.Customer@Example.COM  ' }),
    });
    assert.equal(validResp.status, 200);
    const validBody = (await validResp.json()) as { ok: boolean; email: string; step: string };
    assert.equal(validBody.ok, true);
    assert.equal(validBody.email, 'alex.customer@example.com');
    assert.equal(validBody.step, 'credentials');

    const badResp = await fetch(`${baseUrl}/api/auth/identify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'not-an-email' }),
    });
    assert.equal(badResp.status, 400);
  });
});

test('OAuth safe account linking requires explicit password confirmation instead of silent auto-linking', async () => {
  const passwordHash = await bcrypt.hash('NovaraPass123', 6);
  const localUser = {
    _id: '507f1f77bcf86cd799439011',
    name: 'Tasnim Rahman',
    givenName: 'Tasnim',
    familyName: 'Rahman',
    email: 'tasnim@example.com',
    role: 'customer',
    status: 'active',
    isVerified: true,
    passwordHash,
    authProvider: 'local',
    initialAuthProvider: 'local',
    oauthProviders: {} as { googleId?: string; facebookId?: string },
    avatarUrl: '',
    avatarSources: { google: '', facebook: '', uploaded: '' },
    saveCalled: false,
    async save() {
      this.saveCalled = true;
      return this;
    },
  };

  const origFindOne = UserModel.findOne;
  const origFindById = UserModel.findById;

  try {
    (UserModel as unknown as Record<string, unknown>).findOne = (query: Record<string, unknown>) => {
      if ('oauthProviders.googleId' in query) {
        return chainableQuery(
          localUser.oauthProviders.googleId === query['oauthProviders.googleId'] ? localUser : null,
        );
      }
      if (query.email === 'tasnim@example.com') {
        return chainableQuery(localUser);
      }
      return chainableQuery(null);
    };
    (UserModel as unknown as Record<string, unknown>).findById = (id: string) =>
      chainableQuery(id === localUser._id ? localUser : null);

    // Step 1: OAuth sign-in matching existing local email must NOT auto-link; returns link_required
    const challenge = await resolveOrChallengeOAuthUser({
      provider: 'google',
      providerId: 'google-sub-999',
      email: 'tasnim@example.com',
      name: 'Tasnim Rahman',
      picture: 'https://lh3.googleusercontent.com/a/photo',
      emailVerified: true,
    });

    assert.equal(challenge.status, 'link_required');
    if (challenge.status !== 'link_required') throw new Error('Expected link_required');
    assert.equal(challenge.provider, 'google');
    assert.equal(challenge.existingHasPassword, true);
    assert.equal(challenge.existingInitialProvider, 'local');
    assert.equal(localUser.saveCalled, false);

    // Step 2: Wrong password rejects linking cleanly
    await assert.rejects(
      confirmOAuthLinkAccount({
        linkToken: challenge.pendingLinkToken,
        password: 'WrongPassword99',
      }),
      /Incorrect password/,
    );
    assert.equal(localUser.oauthProviders.googleId, undefined);

    // Step 3: Correct password links Google while preserving initialAuthProvider: 'local'
    const linked = await confirmOAuthLinkAccount({
      linkToken: challenge.pendingLinkToken,
      password: 'NovaraPass123',
    });

    assert.equal(localUser.saveCalled, true);
    assert.equal(localUser.oauthProviders.googleId, 'google-sub-999');
    assert.equal(linked.user.initialAuthProvider, 'local');
    assert.equal(linked.user.linkedProviders?.google, true);
    assert.equal(linked.user.linkedProviders?.local, true);
    assert.ok(linked.token.length > 20);
  } finally {
    UserModel.findOne = origFindOne;
    UserModel.findById = origFindById;
  }
});

test('unlinkProviderForUser blocks unlinking the last sign-in method and allows unlinking when another method exists', async () => {
  const socialOnlyUser = {
    _id: '507f1f77bcf86cd799439022',
    name: 'Google Buyer',
    email: 'buyer@example.com',
    role: 'customer',
    status: 'active',
    isVerified: true,
    passwordHash: undefined as string | undefined,
    initialAuthProvider: 'google',
    oauthProviders: { googleId: 'g-only' } as { googleId?: string; facebookId?: string },
    avatarUrl: 'https://lh3.googleusercontent.com/a/g-only',
    avatarSources: { google: 'https://lh3.googleusercontent.com/a/g-only', facebook: '', uploaded: '' },
    async save() {
      return this;
    },
  };

  const origFindById = UserModel.findById;
  try {
    (UserModel as unknown as Record<string, unknown>).findById = () => chainableQuery(socialOnlyUser);

    await assert.rejects(
      unlinkProviderForUser(socialOnlyUser._id, 'google'),
      /before unlinking your only sign-in method/,
    );

    // Adding a password enables safe unlinking
    socialOnlyUser.passwordHash = 'hashed-pw';
    const serialized = await unlinkProviderForUser(socialOnlyUser._id, 'google');
    assert.equal(serialized.linkedProviders?.google, false);
    assert.equal(serialized.linkedProviders?.local, true);
    assert.equal(serialized.initialAuthProvider, 'google');
  } finally {
    UserModel.findById = origFindById;
  }
});

test('authenticateRequired rejects revoked AuthSession tokens and admin analytics requires admin permission', async () => {
  const origSessionFindOne = AuthSessionModel.findOne;
  const origUserFindById = UserModel.findById;
  const origProviderFind = UserAuthProviderModel.find;

  try {
    await withMockReadyDb(async () => {
      const revokedSid = 'sid-revoked-001';
      const activeSid = 'sid-active-002';

      (AuthSessionModel as unknown as Record<string, unknown>).findOne = ({ sessionId }: { sessionId: string }) =>
        chainableQuery(
          sessionId === revokedSid
            ? { sessionId: revokedSid, revokedAt: new Date(), expiresAt: new Date(Date.now() + 60_000) }
            : { sessionId: activeSid, revokedAt: null, expiresAt: new Date(Date.now() + 60_000), lastSeenAt: new Date() },
        );

      const customerDoc = {
        _id: '507f1f77bcf86cd799439033',
        name: 'Regular Customer',
        email: 'customer@example.com',
        role: 'customer',
        status: 'active',
        isVerified: true,
        customPermissions: [],
      };
      (UserModel as unknown as Record<string, unknown>).findById = () => chainableQuery(customerDoc);

      const revokedJwt = signAuthToken(
        { _id: customerDoc._id, role: 'customer', email: customerDoc.email },
        { sessionId: revokedSid },
      );
      const activeCustomerJwt = signAuthToken(
        { _id: customerDoc._id, role: 'customer', email: customerDoc.email },
        { sessionId: activeSid },
      );

      await withHttpServer(async (baseUrl) => {
        // Revoked session rejected with 401 SESSION_REVOKED
        const revResp = await fetch(`${baseUrl}/api/auth/me`, {
          headers: { Authorization: `Bearer ${revokedJwt}` },
        });
        assert.equal(revResp.status, 401);
        const revBody = (await revResp.json()) as { code: string };
        assert.equal(revBody.code, 'SESSION_REVOKED');

        // Unauthenticated admin analytics call returns 401
        const unauthAdmin = await fetch(`${baseUrl}/api/admin/users/authentication-stats`);
        assert.equal(unauthAdmin.status, 401);

        // Customer role calling admin analytics returns 403 FORBIDDEN
        const forbiddenAdmin = await fetch(`${baseUrl}/api/admin/users/authentication-stats`, {
          headers: { Authorization: `Bearer ${activeCustomerJwt}` },
        });
        assert.equal(forbiddenAdmin.status, 403);
      });
    });
  } finally {
    AuthSessionModel.findOne = origSessionFindOne;
    UserModel.findById = origUserFindById;
    UserAuthProviderModel.find = origProviderFind;
  }
});
