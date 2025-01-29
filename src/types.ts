export type ShareType = "deviceShare" | "serverShare" | "recoveryShare";

export interface Share {
  type: ShareType;
  x: number;
  y: Uint8Array | string;
  version: number;
  hash: string;
}
