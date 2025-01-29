import { config } from "dotenv";
import { KeySharing } from "./keySharing";
import { Share } from "./types";

config();

export class KeyManager {
  static splitKey(
    privateKey: string,
    totalShares: number,
    threshold: number
  ): Share[] {
    try {
      if (!privateKey) {
        throw new Error("Private key is required");
      }

      if (totalShares < threshold) {
        throw new Error(
          "Total shares must be greater than or equal to threshold"
        );
      }

      if (threshold < 2) {
        throw new Error("Threshold must be at least 2");
      }

      const privateKeyBytes = new TextEncoder().encode(privateKey);
      const shares = KeySharing.split(privateKeyBytes);

      return shares.map((share) => ({
        ...share,
        y: Buffer.from(share.y as Uint8Array).toString("hex"),
      }));
    } catch (error) {
      throw new Error(`Failed to split key: ${(error as Error).message}`);
    }
  }

  static combineShares(shares: Share[]): string {
    try {
      if (!Array.isArray(shares) || shares.length < 2) {
        throw new Error("At least 2 valid shares are required");
      }

      const processedShares = shares.map((share) => ({
        ...share,
        y: new Uint8Array(Buffer.from(share.y as string, "hex")),
      }));

      const reconstructedBytes = KeySharing.reconstruct(processedShares);
      return new TextDecoder().decode(reconstructedBytes);
    } catch (error) {
      throw new Error(`Failed to combine shares: ${(error as Error).message}`);
    }
  }

  static generateNewShareFromTwo(share1: Share, share2: Share): Share {
    try {
      if (!share1 || !share2) {
        throw new Error("Two valid shares are required");
      }

      const processedShare1 = {
        ...share1,
        y: new Uint8Array(Buffer.from(share1.y as string, "hex")),
      };

      const processedShare2 = {
        ...share2,
        y: new Uint8Array(Buffer.from(share2.y as string, "hex")),
      };

      const existingTypes = [processedShare1.type, processedShare2.type];
      const allTypes = ["deviceShare", "serverShare", "recoveryShare"] as const;
      const missingType = allTypes.find(
        (type) => !existingTypes.includes(type)
      );

      if (!missingType) {
        throw new Error("Could not determine missing share type");
      }

      const newShare = KeySharing.generateCompatibleShare(
        processedShare1.y,
        [processedShare1, processedShare2],
        missingType
      );

      return {
        ...newShare,
        y: Buffer.from(newShare.y as Uint8Array).toString("hex"),
      };
    } catch (error) {
      throw new Error(
        `Failed to generate new share: ${(error as Error).message}`
      );
    }
  }
}
