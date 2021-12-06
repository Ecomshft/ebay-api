const redis = require("redis");
const crypto = require("crypto");
const bluebird = require("bluebird");
const cryptojs = require("crypto-js");

const HOUR_IN_SECONDS = 3600;

// Adding promises to redis
// https://stackoverflow.com/a/54844935

// https://cloud.google.com/community/tutorials/nodejs-redis-on-appengine
const client = (() => {
  if (process.env.REDIS_PORT) {
    bluebird.promisifyAll(redis);
    const authParams: {
      [index: string]: any;
    } = {};
    if (process.env.REDIS_KEY) {
      authParams.auth_pass = process.env.REDIS_KEY;
      authParams.return_buffers = true;
    }
    return redis.createClient(
      process.env.REDIS_PORT,
      process.env.REDIS_HOST,
      authParams
    );
  }
})();

const hash = (text: any) =>
  crypto.createHash("sha256").update(text).digest("hex");

// https://github.com/brix/crypto-js#plain-text-encryption
const encryptAccessToken = (accessToken: any) =>
  cryptojs.AES.encrypt(accessToken, process.env.ACCESS_TOKEN_SECRET).toString();

const decryptAccessToken = (encryptedToken: any) =>
  cryptojs.AES.decrypt(
    encryptedToken,
    process.env.ACCESS_TOKEN_SECRET
  ).toString(cryptojs.enc.Utf8);

export const setAccessToken = async (refreshToken: any, accessToken: any) => {
  if (!client) {
    return;
  }
  const hashedRefreshToken = hash(refreshToken);
  const encryptedAccessToken = encryptAccessToken(accessToken);
  // Auto remove it after an hour -> https://redis.io/commands/set
  await client.setAsync(
    hashedRefreshToken,
    encryptedAccessToken,
    "EX",
    HOUR_IN_SECONDS
  );
};

export const getAccessToken = async (refreshToken: any) => {
  if (!client) {
    return;
  }
  const hashedRefreshToken = hash(refreshToken);
  const encryptedToken = await client.getAsync(hashedRefreshToken);
  if (encryptedToken) {
    return decryptAccessToken(encryptedToken);
  }
};

export const clearAccessToken = async (refreshToken: any) => {
  if (!client) {
    return;
  }
  const hashedRefreshToken = hash(refreshToken);
  await client.del(hashedRefreshToken);
};
