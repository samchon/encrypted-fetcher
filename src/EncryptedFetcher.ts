import { AesPkcs5 } from "./AesPkcs5";
import { HttpError } from "./HttpError";
import { IPassword } from "./IPassword";

// POLYFILL FOR NODE
if (typeof global === "object"
    && typeof global.process === "object" 
    && typeof global.process.versions === "object"
    && typeof global.process.versions.node !== undefined)
(global as any).fetch = require("node-fetch");

/**
 * Rest API Fetcher with AES Encryption
 * 
 *   - AES-128/256
 *   - CBC mode
 *   - PKCS#5 Padding
 *   - Base64 Encoding
 * 
 * @template Headers Type of additional headers if you required.
 * @author Jeongho Nam - https://github.com/samchon
 */
export class EncryptedFetcher<Headers extends object = {}>
{
    /**
     * Host address of the target server.
     */
    public readonly host: string;

    /**
     * Additional headers if you required.
     */
    protected headers_?: Headers;

    private readonly password_: IPassword | IPassword.Closure;

    /* -----------------------------------------------------------
        CONSTRUCTORS
    ----------------------------------------------------------- */
    /**
     * Initializer Constructor
     * 
     * @param host Host address of the target server.
     * @param password Password for the encryption.
     * @param headers Additional headers if you required.
     */
    public constructor(host: string, password: IPassword | IPassword.Closure, headers?: Headers)
    {
        this.host = host;
        this.password_ = password;
        this.headers_ = headers;
    }

    /* -----------------------------------------------------------
        NETWORK COMMUNICATION
    ----------------------------------------------------------- */
    /**
     * Fetch data from server with encryption.
     * 
     * @param method HTTP method.
     * @param path Target path.
     * @param input Request parameters.
     * @return Response data from the server.
     */
    protected async fetch<Input extends Record<string, string>, Output>(method: "GET" | "DELETE", path: string, input?: Input): Promise<Output>;
    
    /**
     * Fetch data from server with encryption.
     * 
     * @param method HTTP method.
     * @param path Target path.
     * @param input Request data.
     * @return Response data from the server.
     */
    protected async fetch<Input extends object, Output>(method: "POST"|"PATCH"|"PUT", path: string, input?: Input): Promise<Output>;

    protected async fetch<Input, Output>
        (method: "GET" | "DELETE" | "POST" | "PATCH" | "PUT", path: string, input?: Input): Promise<Output>
    {
        //----
        // REQUEST
        //----
        // ENCRYPT REQUEST-BODY
        let sendData: string | undefined = undefined;
        if (input)
            if (method === "GET" || method === "DELETE")
            {
                let index: number = path.lastIndexOf("?");
                path += ((index === -1) ? "?" : "&")
                    + new URLSearchParams(<any>input as Record<string, string>).toString();
            }
            else
            {
                sendData = JSON.stringify(input);
                const password: IPassword = this.password_ instanceof Function
                    ? this.password_(sendData, true)
                    : this.password_;
                sendData = AesPkcs5.encode(sendData, password.key, password.iv);
            }

        // INTIALIZE REQUEST
        const init: RequestInit = {
            method: method,
            body: sendData,
            headers: <any>this.headers_
        };

        //----
        // RESPONSE
        //----
        // DO FETCH
        const response: Response = await fetch(`${this.host}${path}`, init);
        let replyData: string = await response.text();

        // CHECK STATUS CODE
        if (response.status !== 200 && response.status !== 201)
            throw new HttpError(method, path, response.status, replyData);

        // FINALIZATION WITH DECODING
        const password: IPassword = this.password_ instanceof Function
            ? this.password_(replyData, false)
            : this.password_;
        replyData = AesPkcs5.decode(replyData, password.key, password.iv);
        return JSON.parse(replyData);
    }
}