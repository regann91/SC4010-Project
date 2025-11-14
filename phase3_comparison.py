import time,hashlib,math,random
from Crypto.PublicKey import RSA
from collections import Counter
from phase1_baseline import LowEntropySim,ShannonEntropy,NISTTests


def shannon_entropy_from_mod(n):
    return ShannonEntropy.shannon(n)

class Phase3Compare:
    def __init__(self,num_keys=10,key_size=1024,baseline_func=None,emn_func=None):
        self.n = int(num_keys)
        self.ks = int(key_size)
        self.baseline_func = baseline_func
        self.emn_func = emn_func
        self.stats = {
            "baseline": {"fps": [],"ents": [],"times": [],"mods": [],"nist": []},
            "emn":      {"fps": [],"ents": [],"times": [],"mods": [],"nist": []},
        }

    def _run_side(self,label,randfunc):
        print(f"\n=== {label.upper()} RNG ({self.n} keys) ===")
        s = self.stats[label]

        for i in range(self.n):
            print(f"Generating key {i+1}/{self.n} ...")
            t0 = time.time()
            key = RSA.generate(self.ks,randfunc=randfunc())
            t1 = time.time() - t0
            fp = hashlib.sha256(f"{key.n}:{key.e}".encode()).hexdigest()
            mod_bytes = key.n.to_bytes((key.n.bit_length() + 7) // 8,"big")
            ent = shannon_entropy_from_mod(mod_bytes)
            s["fps"].append(fp)
            s["ents"].append(ent)
            s["times"].append(t1)
            s["mods"].append(key.n)
            bits = NISTTests._to_bits(key.n)
            s["nist"].append({
                "freq": NISTTests.frequency(bits),
                "block": NISTTests.block_frequency(bits),
                "runs": NISTTests.runs(bits),
                "lrun": NISTTests.longest_run(bits),
                "apent": NISTTests.approximate_entropy(bits)
            })

            print(f"  fingerprint : {fp[:16]}...")
            print(f"  entropy     : {ent:.4f} bits/byte")
            print(f"  time        : {t1:.4f}s")
            print()

    def run(self):
        self._run_side("baseline",self.baseline_func)
        self._run_side("emn",self.emn_func)

    def analyze(self):
        print("=== Phase 3: Comparative Evaluation ===")

        for label in ["baseline","emn"]:
            s = self.stats[label]
            uniq = len(set(s["fps"]))
            dup  = len(s["fps"]) - uniq

            print(f"\n[{label.upper()}]")
            print(f"  Total keys     : {len(s['fps'])}")
            print(f"  Unique keys    : {uniq}")
            print(f"  Duplicates     : {dup}")
            print(f"  Entropy avg    : {sum(s['ents'])/len(s['ents']):.4f}")
            print(f"  Entropy min    : {min(s['ents']):.4f}")
            print(f"  Entropy max    : {max(s['ents']):.4f}")
            print(f"  Avg time/key   : {sum(s['times'])/len(s['times']):.4f}s")

            shared = 0
            mods = s["mods"]
            for i in range(len(mods)):
                for j in range(i+1,len(mods)):
                    if math.gcd(mods[i],mods[j]) > 1:
                        shared += 1
            if shared == 0:
                print("  Shared factors : none detected")
            else:
                print(f"  Shared factors : {shared} pairs")

            passes = 0
            total = len(s["nist"]) * 5
            for entry in s["nist"]:
                if entry["freq"]  >= 0.01: passes += 1
                if entry["block"] >= 0.01: passes += 1
                if entry["runs"]  >= 0.01: passes += 1
                if entry["lrun"]  >= 0.01: passes += 1
                if entry["apent"] >= 0.01: passes += 1

            print(f"  NIST pass rate : {passes}/{total} ({passes/total:.2%})")

        b = self.stats["baseline"]
        e = self.stats["emn"]

        print("Overall conclusions:")
        if len(set(b["fps"])) != len(b["fps"]):
            print("* Baseline RNG shows collisions → low entropy.")
        else:
            print("* Baseline RNG produced unique keys (in this run).")

        if len(set(e["fps"])) == len(e["fps"]):
            print("* EMN-enhanced RNG keys are all unique.")
        else:
            print("* EMN showed unexpected duplication (unlikely).")

        avg_b = sum(b["ents"]) / len(b["ents"])
        avg_e = sum(e["ents"]) / len(e["ents"])
        if avg_e > avg_b:
            print(f"* EMN achieved higher modulus entropy ({avg_e:.3f} vs {avg_b:.3f}).")
        else:
            print(f"* Baseline entropy unexpectedly higher ({avg_b:.3f} vs {avg_e:.3f}).")

        tb = sum(b["times"]) / len(b["times"])
        te = sum(e["times"]) / len(e["times"])
        if te > tb:
            print(f"* EMN incurs extra computation (+{te-tb:.4f}s per key).")
        else:
            print(f"* EMN ran slightly faster (likely normal variance).")

def main():
    sim = LowEntropySim(bits=16)
    def baseline_randfunc():
        seed = sim.get_seed()
        random.seed(seed)
        def rf(n):
            return random.getrandbits(8 * n).to_bytes(n,"big")
        return rf
    
    from phase2_emn import EMN_PRNG,SHA256CTR
    emn = EMN_PRNG(P_seed=None,injection_frequency=4)
    def emn_randfunc():
        O = emn.next_output()
        ctr = SHA256CTR(O)
        return ctr.read

    cmp = Phase3Compare(
        num_keys=10,
        key_size=1024,
        baseline_func=baseline_randfunc,
        emn_func=emn_randfunc
    )

    cmp.run()
    cmp.analyze()


if __name__ == "__main__":
    main()
