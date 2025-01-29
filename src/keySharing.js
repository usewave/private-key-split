const crypto = require("crypto");
const { GF256 } = require("./gf256");

class KeySharing {
  /**
   * Generate a cryptographically secure random byte
   * @returns {number} Random byte between 0-255
   */
  static getSecureRandomByte() {
    return crypto.randomBytes(1)[0];
  }

  /**
   * Calculate share hash for integrity verification
   * @param {Object} share - Share object
   * @returns {string} Hash of the share
   */
  static calculateShareHash(share) {
    const hash = crypto.createHash("sha256");
    hash.update(Buffer.from([share.x]));
    hash.update(share.y);
    hash.update(share.type);
    return hash.digest("hex");
  }

  /**
   * Split a private key into shares with integrity protection
   * @param {Uint8Array} privateKey - The key to split
   * @returns {Array} Array of protected shares
   */
  static split(privateKey) {
    const shares = [];
    const shareTypes = ["deviceShare", "serverShare", "recoveryShare"];
    const version = 1; // For future compatibility

    // Generate a random polynomial for each byte
    for (let byteIndex = 0; byteIndex < privateKey.length; byteIndex++) {
      const coefficients = new Uint8Array(2);
      coefficients[0] = privateKey[byteIndex];
      // Use cryptographically secure random number
      coefficients[1] = this.getSecureRandomByte();

      // Generate share for each participant
      for (let i = 1; i <= 3; i++) {
        if (!shares[i - 1]) {
          shares[i - 1] = {
            type: shareTypes[i - 1],
            x: i,
            y: new Uint8Array(privateKey.length),
            version,
          };
        }

        let evaluation = new Uint8Array([0]);
        for (let j = 0; j < coefficients.length; j++) {
          const term = GF256.multiply(coefficients[j], GF256.pow(i, j));
          evaluation = GF256.add(evaluation, term);
        }

        shares[i - 1].y[byteIndex] = evaluation[0];
      }
    }

    // Add integrity protection to shares
    return shares.map((share) => ({
      ...share,
      hash: this.calculateShareHash(share),
    }));
  }

  /**
   * Verify share integrity
   * @param {Object} share - Share to verify
   * @returns {boolean} True if share is valid
   */
  static verifyShare(share) {
    if (!share.hash) return false;
    const calculatedHash = this.calculateShareHash(share);
    return crypto.timingSafeEqual(
      Buffer.from(calculatedHash, "hex"),
      Buffer.from(share.hash, "hex")
    );
  }

  /**
   * Reconstruct secret from shares with integrity verification
   * @param {Array} shares - Array of shares
   * @returns {Uint8Array} Reconstructed secret
   */
  static reconstruct(shares) {
    if (shares.length < 2) {
      throw new Error("Need at least 2 shares to reconstruct");
    }

    // Verify share integrity
    const invalidShares = shares.filter((share) => !this.verifyShare(share));
    if (invalidShares.length > 0) {
      throw new Error("Invalid or tampered shares detected");
    }

    // Verify share versions match
    const versions = new Set(shares.map((share) => share.version));
    if (versions.size > 1) {
      throw new Error("Incompatible share versions");
    }

    const secretLength = shares[0].y.length;
    const reconstructed = new Uint8Array(secretLength);

    // Reconstruct each byte
    for (let byteIndex = 0; byteIndex < secretLength; byteIndex++) {
      let result = new Uint8Array([0]);

      // Lagrange interpolation
      for (let i = 0; i < shares.length; i++) {
        let term = new Uint8Array([shares[i].y[byteIndex]]);

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

  /**
   * Generate a compatible share with integrity protection
   * @param {Uint8Array} privateKey - Original private key
   * @param {Array} existingShares - Existing shares
   * @param {string} shareType - Type of share to generate
   * @returns {Object} New compatible share
   */
  static generateCompatibleShare(privateKey, existingShares, shareType) {
    if (existingShares.length < 2) {
      throw new Error(
        "Need at least 2 existing shares to generate compatible share"
      );
    }

    // Verify existing shares
    const invalidShares = existingShares.filter(
      (share) => !this.verifyShare(share)
    );
    if (invalidShares.length > 0) {
      throw new Error("Invalid or tampered shares detected");
    }

    // Verify share versions match
    const versions = new Set(existingShares.map((share) => share.version));
    if (versions.size > 1) {
      throw new Error("Incompatible share versions");
    }

    const newShare = {
      type: shareType,
      x: shareType === "deviceShare" ? 1 : shareType === "serverShare" ? 2 : 3,
      y: new Uint8Array(privateKey.length),
      version: existingShares[0].version,
    };

    for (let byteIndex = 0; byteIndex < privateKey.length; byteIndex++) {
      let result = new Uint8Array([0]);

      // Lagrange interpolation at the new x-coordinate
      for (let i = 0; i < existingShares.length; i++) {
        let term = new Uint8Array([existingShares[i].y[byteIndex]]);

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

      newShare.y[byteIndex] = result[0];
    }

    // Add integrity protection
    newShare.hash = this.calculateShareHash(newShare);
    return newShare;
  }
}

module.exports = { KeySharing, GF256 };
