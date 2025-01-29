import crypto from "crypto";
import { GF256 } from "./gf256";
import { Share, ShareType } from "./types";

export class KeySharing {
  static getSecureRandomByte(): number {
    return crypto.randomBytes(1)[0];
  }

  static calculateShareHash(share: Share): string {
    const hash = crypto.createHash("sha256");
    hash.update(Buffer.from([share.x]));
    hash.update(share.y as Uint8Array);
    hash.update(share.type);
    return hash.digest("hex");
  }

  static split(privateKey: Uint8Array): Share[] {
    const shares: Share[] = [];
    const shareTypes: ShareType[] = [
      "deviceShare",
      "serverShare",
      "recoveryShare",
    ];
    const version = 1;

    for (let byteIndex = 0; byteIndex < privateKey.length; byteIndex++) {
      const coefficients = new Uint8Array(2);
      coefficients[0] = privateKey[byteIndex];
      coefficients[1] = this.getSecureRandomByte();

      for (let i = 1; i <= 3; i++) {
        if (!shares[i - 1]) {
          shares[i - 1] = {
            type: shareTypes[i - 1],
            x: i,
            y: new Uint8Array(privateKey.length),
            version,
            hash: "",
          };
        }

        let evaluation = new Uint8Array([0]);
        for (let j = 0; j < coefficients.length; j++) {
          const term = GF256.multiply(coefficients[j], GF256.pow(i, j));
          evaluation = GF256.add(evaluation, term);
        }

        (shares[i - 1].y as Uint8Array)[byteIndex] = evaluation[0];
      }
    }

    return shares.map((share) => ({
      ...share,
      hash: this.calculateShareHash(share),
    }));
  }

  static verifyShare(share: Share): boolean {
    if (!share.hash) return false;
    const calculatedHash = this.calculateShareHash(share);
    return crypto.timingSafeEqual(
      Buffer.from(calculatedHash, "hex"),
      Buffer.from(share.hash, "hex")
    );
  }

  static reconstruct(shares: Share[]): Uint8Array {
    if (shares.length < 2) {
      throw new Error("Need at least 2 shares to reconstruct");
    }

    const invalidShares = shares.filter((share) => !this.verifyShare(share));
    if (invalidShares.length > 0) {
      throw new Error("Invalid or tampered shares detected");
    }

    const versions = new Set(shares.map((share) => share.version));
    if (versions.size > 1) {
      throw new Error("Incompatible share versions");
    }

    const secretLength = (shares[0].y as Uint8Array).length;
    const reconstructed = new Uint8Array(secretLength);

    for (let byteIndex = 0; byteIndex < secretLength; byteIndex++) {
      let result = new Uint8Array([0]);

      for (let i = 0; i < shares.length; i++) {
        let term = new Uint8Array([(shares[i].y as Uint8Array)[byteIndex]]);

        for (let j = 0; j < shares.length; j++) {
          if (i !== j) {
            const numerator = GF256.subtract(0, shares[j].x);
            const denominator = GF256.subtract(shares[i].x, shares[j].x);
            const factor = GF256.multiply(
              numerator,
              GF256.inverse(denominator)
            );
            term = GF256.multiply(term, factor);
          }
        }

        result = GF256.add(result, term);
      }

      reconstructed[byteIndex] = result[0];
    }

    return reconstructed;
  }

  static generateCompatibleShare(
    privateKey: Uint8Array,
    existingShares: Share[],
    shareType: ShareType
  ): Share {
    if (existingShares.length < 2) {
      throw new Error(
        "Need at least 2 existing shares to generate compatible share"
      );
    }

    const invalidShares = existingShares.filter(
      (share) => !this.verifyShare(share)
    );
    if (invalidShares.length > 0) {
      throw new Error("Invalid or tampered shares detected");
    }

    const versions = new Set(existingShares.map((share) => share.version));
    if (versions.size > 1) {
      throw new Error("Incompatible share versions");
    }

    const newShare: Share = {
      type: shareType,
      x: shareType === "deviceShare" ? 1 : shareType === "serverShare" ? 2 : 3,
      y: new Uint8Array(privateKey.length),
      version: existingShares[0].version,
      hash: "",
    };

    for (let byteIndex = 0; byteIndex < privateKey.length; byteIndex++) {
      let result = new Uint8Array([0]);

      for (let i = 0; i < existingShares.length; i++) {
        let term = new Uint8Array([
          (existingShares[i].y as Uint8Array)[byteIndex],
        ]);

        for (let j = 0; j < existingShares.length; j++) {
          if (i !== j) {
            const numerator = GF256.subtract(newShare.x, existingShares[j].x);
            const denominator = GF256.subtract(
              existingShares[i].x,
              existingShares[j].x
            );
            const factor = GF256.multiply(
              numerator,
              GF256.inverse(denominator)
            );
            term = GF256.multiply(term, factor);
          }
        }

        result = GF256.add(result, term);
      }

      (newShare.y as Uint8Array)[byteIndex] = result[0];
    }

    newShare.hash = this.calculateShareHash(newShare);
    return newShare;
  }
}
