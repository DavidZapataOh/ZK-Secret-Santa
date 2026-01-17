import { Barretenberg, Fr } from "@aztec/bb.js";
import { ethers } from "ethers";

const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function modP(x: bigint): bigint {
  x %= P;
  if (x < 0n) x += P;
  return x;
}

function frFromBigIntModP(x: bigint): Fr {
  const y = modP(x);
  const yHex = "0x" + y.toString(16).padStart(64, "0");
  return Fr.fromString(yHex);
}

function frFromHexModP(hex: string): Fr {
  return frFromBigIntModP(BigInt(hex));
}

function pkFromDecimal(dec: string): string {
  const x = BigInt(dec);
  return "0x" + x.toString(16).padStart(64, "0");
}

async function main() {
  const [skDec, addressHex, eventIdHex] = process.argv.slice(2);
  const skHex = pkFromDecimal(skDec);

  const digest = ethers.keccak256(
    ethers.concat([ethers.getBytes(addressHex), ethers.getBytes(eventIdHex)])
  );

  const key = new ethers.SigningKey(skHex);
  const sig = key.sign(digest);

  const rFr = frFromHexModP(sig.r);
  const sFr = frFromHexModP(sig.s);

  const bb = await Barretenberg.new();
  const H = await bb.poseidon2Hash([rFr, sFr]);
  const nullS = await bb.poseidon2Hash([sFr]);

  const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32"],
    [H.toBuffer(), nullS.toBuffer()]
  );

  process.stdout.write(encoded);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
