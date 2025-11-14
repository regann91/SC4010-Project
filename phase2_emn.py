import os,random,hashlib,time,math,struct
from collections import Counter
from Crypto.PublicKey import RSA

class SHA256CTR:
    def __init__(self,seed_int):
        self.seed = seed_int.to_bytes((seed_int.bit_length() + 7) // 8 or 1,"big")
        self.counter = 0

    def read(self,n):
        out = bytearray()
        while len(out) < n:
            ctr_bytes = struct.pack(">Q",self.counter)
            blob = self.seed + ctr_bytes
            out.extend(hashlib.sha256(blob).digest())
            self.counter += 1
        result = bytes(out[:n])
        return result


class EMN_PRNG:
    def __init__(self,P_seed=None,injection_frequency=4):
        import random
        if P_seed is None:
            P_seed = int.from_bytes(os.urandom(32),"big")
        self.P = random.Random(P_seed) 
        self.f = int(injection_frequency)
        self.S = self.P.getrandbits(256)  
        self.cycle = 0

    def _sha256_int(self,a_int):
        b = a_int.to_bytes((a_int.bit_length() + 7) // 8 or 1,"big")
        return int.from_bytes(hashlib.sha256(b).digest(),"big")

    def next_output(self):
        self.cycle += 1
        R = self.P.getrandbits(256)

        if self.f > 0 and (self.cycle % self.f) == 0:
            E = int.from_bytes(os.urandom(32),"big")
            self.S = self._sha256_int(self.S ^ E)

        O = self.S ^ R
        self.S = self.P.getrandbits(256)
        return O


def shannon_entropy(data_bytes):
    if not data_bytes:
        return 0.0
    counts = Counter(data_bytes)
    L = len(data_bytes)
    ent = 0.0
    for c in counts.values():
        p = c / L
        ent -= p * math.log2(p)
    return ent


class EMNExperiment:
    def __init__(self,num_keys=10,injection_frequency=4,key_size=1024,verbose=True):
        self.num_keys = int(num_keys)
        self.f = int(injection_frequency)
        self.key_size = int(key_size)
        self.verbose = bool(verbose)

        self.results = {
            "keys": [],
            "fingerprints": [],
            "outputs": [],
            "mix_counts": [],
            "entropies": [],
            "times": []
        }

    def _randfunc_from_int(self,seed_int):
        ctr = SHA256CTR(seed_int)
        return ctr.read

    def run(self):
        if self.verbose:
            print("=== Phase 2: EMN-CSPRNG driven RSA key generation ===")
            print(f"no. of keys     : {self.num_keys}")
            print(f"injection freq f: {self.f}")
            print(f"key size        : {self.key_size} bits")
            print()

        emn = EMN_PRNG(P_seed=None,injection_frequency=self.f)

        for i in range(self.num_keys):
            if self.verbose:
                print(f"Generating key {i+1}/{self.num_keys} ...")

            t0 = time.time()
            O = emn.next_output()
            t1 = time.time() - t0
            injected = (emn.cycle % self.f == 0) if self.f > 0 else False
            randfunc = self._randfunc_from_int(O)
            key = RSA.generate(self.key_size,randfunc=randfunc)
            fp = hashlib.sha256(f"{key.n}:{key.e}".encode()).hexdigest()
            mod_bytes = key.n.to_bytes((key.n.bit_length() + 7) // 8,"big")
            ent = shannon_entropy(mod_bytes)

            self.results["keys"].append(key)
            self.results["fingerprints"].append(fp)
            self.results["outputs"].append(O)
            self.results["mix_counts"].append(injected)
            self.results["entropies"].append(ent)
            self.results["times"].append(t1)

            if self.verbose:
                print(f"  fingerprint : {fp[:16]}...")
                print(f"  injected this cycle? : {injected}")
                print(f"  output O (hex[:16]) : {hex(O)[:18]}...")
                print(f"  modulus entropy     : {ent:.4f} bits/byte")
                print(f"  gen time            : {t1:.4f}s")
                print()

        return self.results

    def analyze(self):
        print("--- Analysis ---")
        fps = self.results["fingerprints"]
        ents = self.results["entropies"]
        times = self.results["times"]
        injected_flags = self.results["mix_counts"]

        total = self.num_keys
        unique = len(set(fps))
        duplicates = total - unique

        print("\n1) Key uniqueness")
        print(f"   Total: {total}")
        print(f"   Unique: {unique}")
        print(f"   Duplicates: {duplicates}")
        print("   Result:","All unique" if duplicates == 0 else "Duplicates present")

        avg_ent = sum(ents) / len(ents) if ents else 0.0
        print("\n2) Entropy (modulus)")
        print(f"   Average: {avg_ent:.4f} bits/byte")
        print(f"   Min: {min(ents):.4f}")
        print(f"   Max: {max(ents):.4f}")
        print("   Target (random data) ~ 8.0 bits/byte")
        quality = "High" if avg_ent >= 7.9 else "Moderate" if avg_ent >= 7.5 else "Low"
        print(f"   Quality: {quality}")

        avg_time = sum(times) / len(times) if times else 0.0
        injections = sum(1 for v in injected_flags if v)
        print("\n3) Performance")
        print(f"   Avg generation time : {avg_time:.4f}s")
        print(f"   Total cycles with injection observed: {injections} / {self.num_keys}")

        print("\n4) Shared factor (GCD) check")
        mods = [k.n for k in self.results["keys"]]
        shared = 0
        import math
        for i in range(len(mods)):
            for j in range(i + 1,len(mods)):
                if math.gcd(mods[i],mods[j]) > 1:
                    shared += 1
                    print(f"   Keys {i+1} & {j+1} share a common factor!")

        if shared == 0:
            print("   No shared prime factors detected among generated keys.")
        else:
            print(f"   Total pairs sharing factors: {shared}")

        print("\nConclusion:")
        if duplicates > 0:
            print("  Low entropy or deterministic seeding caused duplicate keys.")
        elif shared > 0:
            print("  Some keys share factors — critical weakness.")
        elif avg_ent < 7.5:
            print("  Modulus entropy below threshold — weak randomness.")
        else:
            print("  No major weaknesses detected (within this test set).")

        print("\n" + "=" * 70)


def main():
    # input params here 
    nk = 10              # no. of keys
    f = 4                # inject OS entropy every f cycles
    bits = 1024          # key size

    print("\nStarting EMN experiment (deterministic RSA via O = S xor R)\n")
    exp = EMNExperiment(num_keys=nk,injection_frequency=f,key_size=bits,verbose=True)
    exp.run()
    exp.analyze()


if __name__ == "__main__":
    main()