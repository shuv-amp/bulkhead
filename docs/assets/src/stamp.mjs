// Prefix every stdin line with the wall-clock time it arrived, in ms.
import { createInterface } from "node:readline";
for await (const l of createInterface({ input: process.stdin })) console.log(`${Date.now()}\t${l}`);
