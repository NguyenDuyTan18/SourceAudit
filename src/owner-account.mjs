import { randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { link, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const derive = promisify(scrypt);
const options = { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 };
const usernamePattern = /^[a-z0-9_.-]{3,64}$/;
const dummySalt = randomBytes(16);
const dummyHash = randomBytes(64);

export function normalizeOwnerUsername(value) {
  return (value ?? '').trim().toLowerCase();
}

export function validOwnerUsername(username) {
  return usernamePattern.test(username);
}

export function validOwnerPassword(password) {
  return typeof password === 'string' && Buffer.byteLength(password) <= 256 &&
    Array.from(password).length >= 15 && !/[\x00-\x1f\x7f]/.test(password);
}

export function createOwnerStore(file) {
  const directory = path.dirname(file);

  async function readOwner() {
    let record;
    try { record = JSON.parse(await readFile(file, 'utf8')); }
    catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
    if (record?.version !== 1 || typeof record.username !== 'string' ||
        !validOwnerUsername(record.username) || typeof record.salt !== 'string' || !/^[a-f0-9]{32}$/.test(record.salt) ||
        typeof record.hash !== 'string' || !/^[a-f0-9]{128}$/.test(record.hash)) throw new Error('Invalid owner account record');
    return record;
  }

  return {
    async hasOwner() { return Boolean(await readOwner()); },
    async register(username, password) {
      const salt = randomBytes(16);
      const hash = await derive(password, salt, 64, options);
      const record = { version: 1, username, salt: salt.toString('hex'), hash: hash.toString('hex') };
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const temporary = path.join(directory, '.owner-' + randomUUID());
      try {
        await writeFile(temporary, JSON.stringify(record), { mode: 0o600, flag: 'wx' });
        // Publish the completed file without replacing an account created by another request.
        await link(temporary, file);
        return true;
      } catch (error) {
        if (error.code === 'EEXIST') return false;
        throw error;
      } finally {
        await rm(temporary, { force: true });
      }
    },
    async verify(username, password) {
      if (!validOwnerUsername(username) || !validOwnerPassword(password)) return false;
      const owner = await readOwner();
      const salt = owner ? Buffer.from(owner.salt, 'hex') : dummySalt;
      const expected = owner ? Buffer.from(owner.hash, 'hex') : dummyHash;
      const actual = await derive(password, salt, 64, options);
      return timingSafeEqual(actual, expected) && owner?.username === username;
    },
  };
}

export const OWNER_ID = 'owner';
const MEMBER_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const MAX_MEMBERS = 100;

/**
 * Owner (admin) stays in `owner.json`; members invited by the owner live in `users.json` next to it.
 * `verify` returns the signed-in identity, or null.
 */
export function createAccountStore(ownerFile) {
  const owner = createOwnerStore(ownerFile);
  const directory = path.dirname(ownerFile);
  const membersFile = path.join(directory, 'users.json');
  let writing = Promise.resolve();

  async function readOwnerRecord() {
    try { return JSON.parse(await readFile(ownerFile, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async function readMembers() {
    let data;
    try { data = JSON.parse(await readFile(membersFile, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
    if (data?.version !== 1 || !Array.isArray(data.users)) throw new Error('Invalid member account file');
    for (const user of data.users) {
      if (!MEMBER_ID.test(user?.id) || !validOwnerUsername(user.username) || !/^[a-f0-9]{32}$/.test(user.salt) ||
          !/^[a-f0-9]{128}$/.test(user.hash)) throw new Error('Invalid member account record');
    }
    return data.users;
  }
  async function writeMembers(users) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const temporary = path.join(directory, '.users-' + randomUUID());
    try {
      await writeFile(temporary, JSON.stringify({ version: 1, users }), { mode: 0o600, flag: 'wx' });
      await rename(temporary, membersFile);
    } finally { await rm(temporary, { force: true }); }
  }
  // Serialize read-modify-write cycles on users.json.
  function mutate(change) {
    const next = writing.then(async () => {
      const users = await readMembers();
      const result = await change(users);
      if (result.changed) await writeMembers(result.users);
      return result.value;
    });
    writing = next.catch(() => {});
    return next;
  }

  return {
    hasOwner: owner.hasOwner,
    register: owner.register,
    async verify(username, password) {
      if (!validOwnerUsername(username) || !validOwnerPassword(password)) return null;
      const ownerRecord = await readOwnerRecord();
      let identity = null; let salt = dummySalt; let expected = dummyHash;
      if (ownerRecord?.username === username) {
        identity = { userId: OWNER_ID, username, role: 'admin' };
        salt = Buffer.from(ownerRecord.salt, 'hex'); expected = Buffer.from(ownerRecord.hash, 'hex');
      } else {
        const member = (await readMembers()).find((user) => user.username === username);
        if (member) {
          identity = { userId: member.id, username, role: 'user' };
          salt = Buffer.from(member.salt, 'hex'); expected = Buffer.from(member.hash, 'hex');
        }
      }
      const actual = await derive(password, salt, 64, options);
      return timingSafeEqual(actual, expected) && identity ? identity : null;
    },
    async listUsers() {
      const ownerRecord = await readOwnerRecord();
      const members = await readMembers();
      return [
        ...(ownerRecord ? [{ id: OWNER_ID, username: ownerRecord.username, role: 'admin' }] : []),
        ...members.map(({ id, username, createdAt }) => ({ id, username, role: 'user', createdAt })),
      ];
    },
    async exists(userId) {
      if (userId === OWNER_ID) return owner.hasOwner();
      return (await readMembers()).some((user) => user.id === userId);
    },
    /** Returns the new member, or a string reason: 'taken' | 'full'. */
    async createUser(username, password) {
      const salt = randomBytes(16);
      const hash = await derive(password, salt, 64, options);
      const ownerRecord = await readOwnerRecord();
      return mutate(async (users) => {
        if (ownerRecord?.username === username || users.some((user) => user.username === username)) return { value: 'taken' };
        if (users.length >= MAX_MEMBERS) return { value: 'full' };
        const user = { id: randomUUID(), username, salt: salt.toString('hex'), hash: hash.toString('hex'), createdAt: new Date().toISOString() };
        return { changed: true, users: [...users, user], value: { id: user.id, username, role: 'user', createdAt: user.createdAt } };
      });
    },
    async deleteUser(userId) {
      return mutate(async (users) => {
        const remaining = users.filter((user) => user.id !== userId);
        return remaining.length === users.length ? { value: false } : { changed: true, users: remaining, value: true };
      });
    },
  };
}
