import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend, Barretenberg, Fr } from "@aztec/bb.js";
import { ethers } from "ethers";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const circuitPath = path.resolve(__dirname, "../circuits/sender/target/sender.json");
const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf-8"));

const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function modP(x: bigint): bigint {
  x %= P;
  if (x < 0n) x += P;
  return x;
}

function frFromHexModP(hex: string): Fr {
  const y = modP(BigInt(hex));
  const yHex = "0x" + y.toString(16).padStart(64, "0");
  return Fr.fromString(yHex);
}

function toPrivKeyHex(pk: string): string {
  if (pk.startsWith("0x")) return ethers.hexlify(ethers.zeroPadValue(pk, 32));
  const bi = BigInt(pk);
  return ethers.hexlify(ethers.zeroPadValue(ethers.toBeHex(bi), 32));
}

function fieldDecFromHex(hexOrDec: string): string {
  if (hexOrDec.startsWith("0x")) return BigInt(hexOrDec).toString();
  return BigInt(hexOrDec).toString();
}

function splitHiLo128(xHex: string): { hi: string; lo: string } {
  const x = BigInt(xHex);
  const loMask = (1n << 128n) - 1n;
  const hi = x >> 128n;
  const lo = x & loMask;
  return { hi: hi.toString(), lo: lo.toString() };
}

async function main() {
  const args = process.argv.slice(2);

  const pkStr = args[0];
  const addrStr = args[1];
  const eventIdStr = args[2];
  const rootPStr = args[3];
  const rootCStr = args[4];

  const depthP = Number(args[5]);
  const sibP = args.slice(6, 6 + 20);

  const depthC = Number(args[26]);
  const sibC = args.slice(27, 27 + 20);

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

  const bb = await Barretenberg.new();
  const sFr = frFromHexModP(sig.s);
  const nullS = await bb.poseidon2Hash([sFr]);

  const input = {
    sig: Array.from(ethers.getBytes(sig64)),
    pub_key_x: Array.from(pubX),
    pub_key_y: Array.from(pubY),
    address: Array.from(addr),

    proof_p_siblings: sibP.map(fieldDecFromHex),
    proof_p_depth_eff: depthP,

    proof_c_siblings: sibC.map(fieldDecFromHex),
    proof_c_depth_eff: depthC,

    r: "1",
    event_hi: eventHi,
    event_lo: eventLo,
    root_p: fieldDecFromHex(rootPStr),
    root_c: fieldDecFromHex(rootCStr),
    null_s: nullS.toString()
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
