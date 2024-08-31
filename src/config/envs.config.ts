import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  DATABASE_URL: string;
  MONGO_USERNAME: string;
  MONGO_PASSWORD: string;
  JWTSECRET: string;
}

const envSchema = joi
  .object({
    PORT: joi.number().required(),
    DATABASE_URL: joi.string().required(),
    MONGO_USERNAME: joi.string().required(),
    MONGO_PASSWORD: joi.string().required(),
    JWTSECRET: joi.string().required(),
  })
  .unknown(true);

const { error, value } = envSchema.validate(process.env);

if (error) throw new Error(`Config validation error: ${error.message}`);

const envVars: EnvVars = value;

export const envs = {
  port: envVars.PORT,
  jwt_secret: envVars.JWTSECRET,
};
