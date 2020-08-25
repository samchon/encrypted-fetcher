import crypto from "crypto";
import { randint } from "tstl/algorithm/random";

/**
 * Utility class for AES Encryption.
 * 
 *   - AES-128/256
 *   - CBC mode
 *   - PKCS#5 Padding
 *   - Base64 Encoding
 * 
 * @author Jeongho Nam - https://github.com/samchon
 */
export namespace AesPkcs5
{
    /**
     * Encode data
     * 
     * @param data Target data
     * @param key Key value of the encryption.
     * @param iv Initializer Vector for the encryption
     * @return Encoded data
     */
    export function encode(data: string, key: string, iv: string): string
    {
        let bytes: number = key.length * 8;
        let cipher: crypto.Cipher = crypto.createCipheriv(`AES-${bytes}-CBC`, key, iv);

        return cipher.update(data, "utf8", "base64") + cipher.final("base64");
    }
 
    /**
     * Decode data.
     * 
     * @param data Target data
     * @param key Key value of the decryption.
     * @param iv Initializer Vector for the decryption
     * @return Decoded data.
     */
    export function decode(data: string, key: string, iv: string): string
    {
        let bytes: number = key.length * 8;
        let decipher: crypto.Decipher = crypto.createDecipheriv(`AES-${bytes}-CBC`, key, iv);

        return decipher.update(data, "base64", "utf8") + decipher.final("utf8");
    }

    /**
     * Generate random encryption key.
     * 
     * @param length Length of the encryption key,
     * @return Random key.
     */
    export function random(length: 16 | 32): string
    {
        let ret: string = "";
        for (let i: number = 0; i < length; ++i)
        {
            let index: number = randint(0, CHARACTERS.length - 1);
            ret += CHARACTERS[index];
        }
        return ret;
    }
    const CHARACTERS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
}