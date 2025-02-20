import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  JWTSECRET: string;
  NATS_SERVICE: string[];
}

const envSchema = joi
  .object({
    PORT: joi.number().required(),
    JWTSECRET: joi.string().required(),
    NATS_SERVICE: joi.array().items(joi.string()).required(),
  })
  .unknown(true);

const { error, value } = envSchema.validate({
  ...process.env,
  NATS_SERVICE: process.env.NATS_SERVICE?.split(','),
});

if (error) throw new Error(`Config validation error: ${error.message}`);

const envVars: EnvVars = value;

export const envs = {
  port: envVars.PORT,
  jwt_secret: envVars.JWTSECRET,
  nats_service: envVars.NATS_SERVICE,
};
