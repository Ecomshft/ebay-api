const redis = require("redis");
const crypto = require("crypto");
const bluebird = require("bluebird");
const cryptojs = require("crypto-js");

const HOUR_IN_SECONDS = 3600;

// Adding promises to redis
// https://stackoverflow.com/a/54844935

// https://cloud.google.com/community/tutorials/nodejs-redis-on-appengine
const client = (() => {
  bluebird.promisifyAll(redis);
  let redisClient = redis.createClient();
  if (process.env.REDIS_PORT) {
    const authParams: {
      [index: string]: any;
    } = {};
    if (process.env.REDIS_KEY) {
      authParams.auth_pass = process.env.REDIS_KEY;
      authParams.return_buffers = true;
    }
    redisClient = redis.createClient(
      process.env.REDIS_PORT,
      process.env.REDIS_HOST,
      authParams
    );
  }
  return redisClient;
})();

const hash = (text: any) =>
  crypto.createHash("sha256").update(text).digest("hex");
const defaultKeyWord = "12345";
// https://github.com/brix/crypto-js#plain-text-encryption
const encryptAccessToken = (accessToken: any) =>
  cryptojs.AES.encrypt(
    accessToken,
    process.env.EBAY_ACCESS_TOKEN_SECRET ?? defaultKeyWord
  ).toString();

const decryptAccessToken = (encryptedToken: any) =>
  cryptojs.AES.decrypt(
    encryptedToken,
    process.env.EBAY_ACCESS_TOKEN_SECRET ?? defaultKeyWord
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
    2 * (HOUR_IN_SECONDS - 120 ) //set expiry to be after 1 hour 58 minutes
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
