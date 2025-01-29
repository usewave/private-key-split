const { KeySharing } = require("./keySharing");

require("dotenv").config();

class KeyManager {
  /**
   * Split a private key into multiple shares
   * @param {string} privateKey - The private key to split
   * @param {number} totalShares - Total number of shares to create
   * @param {number} threshold - Minimum number of shares needed to reconstruct
   * @returns {Array} Array of shares
   */
  static splitKey(privateKey, totalShares, threshold) {
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

      // Convert the private key string to Uint8Array
      const privateKeyBytes = new TextEncoder().encode(privateKey);

      // Create shares using KeySharing
      const shares = KeySharing.split(privateKeyBytes);

      // Convert shares to a more readable format for storage/transmission
      return shares.map((share) => ({
        ...share, // This preserves the hash and version fields
        y: Buffer.from(share.y).toString("hex"),
      }));
    } catch (error) {
      throw new Error(`Failed to split key: ${error.message}`);
    }
  }

  /**
   * Combine shares to reconstruct the private key
   * @param {Array} shares - Array of shares to combine
   * @returns {string} The reconstructed private key
   */
  static combineShares(shares) {
    try {
      if (!Array.isArray(shares) || shares.length < 2) {
        throw new Error("At least 2 valid shares are required");
      }

      // Convert the hex-encoded shares back to Uint8Array format while preserving metadata
      const processedShares = shares.map((share) => ({
        ...share, // This preserves the hash and version fields
        y: new Uint8Array(Buffer.from(share.y, "hex")),
      }));

      // Reconstruct the secret
      const reconstructedBytes = KeySharing.reconstruct(processedShares);

      // Convert back to string
      return new TextDecoder().decode(reconstructedBytes);
    } catch (error) {
      throw new Error(`Failed to combine shares: ${error.message}`);
    }
  }

  /**
   * Generate a new secret using exactly two existing shares
   * @param {Object} share1 - First share
   * @param {Object} share2 - Second share
   * @returns {Object} A new valid share that can be used with the original shares
   */
  static generateNewShareFromTwo(share1, share2) {
    try {
      if (!share1 || !share2) {
        throw new Error("Two valid shares are required");
      }

      // Convert hex-encoded shares back to Uint8Array format while preserving metadata
      const processedShare1 = {
        ...share1, // This preserves the hash and version fields
        y: new Uint8Array(Buffer.from(share1.y, "hex")),
      };

      const processedShare2 = {
        ...share2, // This preserves the hash and version fields
        y: new Uint8Array(Buffer.from(share2.y, "hex")),
      };

      // Determine which share type is missing
      const existingTypes = [processedShare1.type, processedShare2.type];
      const allTypes = ["deviceShare", "serverShare", "recoveryShare"];
      const missingType = allTypes.find(
        (type) => !existingTypes.includes(type)
      );

      // Generate a compatible share
      const newShare = KeySharing.generateCompatibleShare(
        processedShare1.y, // we can use either share's y value as the private key
        [processedShare1, processedShare2],
        missingType
      );

      // Convert the new share to hex format for storage/transmission
      return {
        ...newShare, // This preserves the hash and version fields
        y: Buffer.from(newShare.y).toString("hex"),
      };
    } catch (error) {
      throw new Error(`Failed to generate new share: ${error.message}`);
    }
  }
}

module.exports = KeyManager;
