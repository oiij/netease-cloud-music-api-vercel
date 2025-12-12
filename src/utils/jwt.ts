import process from 'node:process'
import { createCipheriv, createDecipheriv } from 'node:crypto'
import type { DecodeOptions, JwtPayload, SignOptions, VerifyOptions } from 'jsonwebtoken'
import jwt from 'jsonwebtoken'
import { nanoid } from 'nanoid'

const jwtKey = process.env.PRIVATE_KEY ?? nanoid()
const cryptoKey = process.env.CRYPTO_KEY ?? nanoid(32)
const cryptoIv = process.env.CRYPTO_IV ?? nanoid(16)
export function useJWT<T extends object>(encrypt?: boolean) {
  function aesEncrypt(data: string) {
    const cipher = createCipheriv('aes-256-cbc', cryptoKey, cryptoIv)
    return (cipher.update(data, 'utf8', 'hex') + cipher.final('hex'))
  }
  function aesDecrypt(data: string) {
    const decipher = createDecipheriv('aes-256-cbc', cryptoKey, cryptoIv)
    return (decipher.update(data, 'hex', 'utf8') + decipher.final('utf8'))
  }
  function sign(data: T, options?: SignOptions) {
    const jwtString = jwt.sign(data, jwtKey, {
      algorithm: 'HS256',
      expiresIn: '1d',
      ...options,
    })
    return encrypt ? aesEncrypt(jwtString) : jwtString
  }

  function verify(token: string, options?: VerifyOptions): Promise<JwtPayload & T | undefined> {
    return new Promise((resolve, reject) => {
      jwt.verify(encrypt ? aesDecrypt(token) : token, jwtKey, { complete: false, ...options }, (err, jwtData) => {
        return err ? reject(err) : resolve(jwtData as any)
      })
    })
  }
  function decode(token: string, options?: DecodeOptions): JwtPayload & T | null | undefined {
    return jwt.decode(encrypt ? aesDecrypt(token) : token, { ...options }) as any
  }
  return {
    sign,
    verify,
    decode,
  }
}
