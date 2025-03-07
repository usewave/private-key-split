import { config } from "dotenv";
import { KeyManager } from "./keyManager";

config();

async function main() {
  try {
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
    // const reconstructedKey = KeyManager.combineShares(dummShare as any);
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
    console.error("Error:", (error as Error).message);
  }
}

main();
