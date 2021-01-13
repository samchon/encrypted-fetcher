export interface IPassword
{
    key: string;
    iv: string;
}
export namespace IPassword
{
    export type Closure = (content: string, isEncode: boolean) => IPassword;
}