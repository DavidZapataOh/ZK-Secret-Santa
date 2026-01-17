import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend } from "@aztec/bb.js";
import { ethers } from "ethers";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const circuitPath = path.resolve(__dirname, "../circuits/receiver/target/receiver.json");
const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf-8"));

function toPrivKeyHex(pk: string): string {
  if (pk.startsWith("0x")) return ethers.hexlify(ethers.zeroPadValue(pk, 32));
  const bi = BigInt(pk);
  return ethers.hexlify(ethers.zeroPadValue(ethers.toBeHex(bi), 32));
}

function splitHiLo128(xHex: string): { hi: string; lo: string } {
  const x = BigInt(xHex);
  const loMask = (1n << 128n) - 1n;
  const hi = x >> 128n;
  const lo = x & loMask;
  return { hi: hi.toString(), lo: lo.toString() };
}

async function main() {
  const [pkStr, addrStr, eventIdStr, nullSStr] = process.argv.slice(2);

  const privKey = toPrivKeyHex(pkStr);

  const addr = ethers.getBytes(addrStr);
  if (addr.length !== 20) throw new Error("address must be 20 bytes");

  const eventId = ethers.getBytes(eventIdStr);
  if (eventId.length !== 32) throw new Error("eventId must be 32 bytes");

  const digest = ethers.keccak256(ethers.concat([addr, eventId]));

  const sk = new ethers.SigningKey(privKey);
  const sig = sk.sign(digest);

  const rBytes = ethers.getBytes(sig.r);
  const sBytes = ethers.getBytes(sig.s);
  const sig64 = ethers.concat([rBytes, sBytes]);

  const pub = ethers.getBytes(ethers.SigningKey.computePublicKey(privKey, false));
  const pubX = pub.slice(1, 33);
  const pubY = pub.slice(33, 65);

  const { hi: eventHi, lo: eventLo } = splitHiLo128(eventIdStr);
  const addressField = BigInt(addrStr).toString();

  const input = {
    sig: Array.from(ethers.getBytes(sig64)),
    pub_key_x: Array.from(pubX),
    pub_key_y: Array.from(pubY),

    address: addressField,
    event_hi: eventHi,
    event_lo: eventLo,
    null_s: BigInt(nullSStr).toString()
  };

  const noir = new Noir(circuit);
  const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 });

  const { witness } = await noir.execute(input);

  const originalLog = console.log;
  console.log = () => {};
  const { proof, publicInputs } = await backend.generateProof(witness, { keccak: true });
  console.log = originalLog;

  const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "bytes32[]"],
    [proof, publicInputs]
  );

  process.stdout.write(encoded);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
