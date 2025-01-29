const KeyManager = require("./keyManager");
require("dotenv").config();

async function main() {
  try {
    // Get the private key from environment variables
    const privateKey = process.env.PRIVATE_KEY;
    if (!privateKey) {
      throw new Error("PRIVATE_KEY not found in environment variables");
    }

    console.log("Original Private Key:", privateKey);

    // Split the key into 3 shares, requiring 2 to reconstruct
    const shares = KeyManager.splitKey(privateKey, 3, 2);
    console.log("\nGenerated Shares:", shares);

    // Reconstruct using 2 shares
    const reconstructedKey = KeyManager.combineShares(shares.slice(0, 2));
    console.log("\nReconstructed Key:", reconstructedKey);

    // Generate a new share using two existing shares
    const newShare = KeyManager.generateNewShareFromTwo(shares[0], shares[1]);
    console.log("\nNewly Generated Share:", newShare);

    // Verify the new share works with original shares
    const reconstructedWithNew = KeyManager.combineShares([
      shares[0],
      shares[1],
      newShare,
    ]);
    console.log("\nReconstructed Key with New Share:", reconstructedWithNew);
  } catch (error) {
    console.error("Error:", error.message);
  }
}

main();
