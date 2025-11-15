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
            "baseline": {"fps": [],"ents": [],"times": [],"mods": [],"nist": [],"predictability": []},
            "emn":      {"fps": [],"ents": [],"times": [],"mods": [],"nist": [],"predictability": []},
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
            chi_result = NISTTests.chi_square(bits, return_statistic=True)
            chi_stat, chi_p = chi_result if isinstance(chi_result, tuple) else (0.0, chi_result)
            
            # Calculate predictability using modulus bytes
            predictability_coef = NISTTests.predictability(mod_bytes)
            s["predictability"].append(predictability_coef)
            
            s["nist"].append({
                "freq": NISTTests.frequency(bits),
                "block": NISTTests.block_frequency(bits),
                "runs": NISTTests.runs(bits),
                "lrun": NISTTests.longest_run(bits),
                "apent": NISTTests.approximate_entropy(bits),
                "chi": chi_p,
                "chi_stat": chi_stat
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
            total = len(s["nist"]) * 6
            for entry in s["nist"]:
                if entry["freq"]  >= 0.01: passes += 1
                if entry["block"] >= 0.01: passes += 1
                if entry["runs"]  >= 0.01: passes += 1
                if entry["lrun"]  >= 0.01: passes += 1
                if entry["apent"] >= 0.01: passes += 1
                if entry["chi"]   >= 0.01: passes += 1

            print(f"  NIST pass rate : {passes}/{total} ({passes/total:.2%})")
            
            # Chi-square statistics
            chi_stats = [entry["chi_stat"] for entry in s["nist"]]
            chi_pvals = [entry["chi"] for entry in s["nist"]]
            print(f"  Chi-square stats:")
            print(f"    Avg χ² = {sum(chi_stats)/len(chi_stats):.4f}")
            print(f"    Avg p-value = {sum(chi_pvals)/len(chi_pvals):.4f}")
            
            # Predictability statistics
            pred_vals = s["predictability"]
            print(f"  Predictability (correlation):")
            print(f"    Avg r = {sum(pred_vals)/len(pred_vals):.6f}")
            print(f"    Min r = {min(pred_vals):.6f}")
            print(f"    Max r = {max(pred_vals):.6f}")
            print(f"    |Avg r| = {abs(sum(pred_vals)/len(pred_vals)):.6f} (closer to 0 is better)")

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

        # Chi square comparison
        avg_chi_b = sum([entry["chi_stat"] for entry in b["nist"]]) / len(b["nist"])
        avg_chi_e = sum([entry["chi_stat"] for entry in e["nist"]]) / len(e["nist"])
        if avg_chi_e < avg_chi_b:
            print(f"* EMN shows better chi-square statistics (avg χ² {avg_chi_e:.4f} vs {avg_chi_b:.4f}).")
        else:
            print(f"* Baseline shows better chi-square statistics (avg χ² {avg_chi_b:.4f} vs {avg_chi_e:.4f}).")

        # p-value comparison
        avg_p_b = sum([entry["chi"] for entry in b["nist"]]) / len(b["nist"])
        avg_p_e = sum([entry["chi"] for entry in e["nist"]]) / len(e["nist"])
        if avg_p_e > avg_p_b:
            print(f"* EMN shows higher chi-square p-values (avg p {avg_p_e:.4f} vs {avg_p_b:.4f}).")
        else:
            print(f"* Baseline shows higher chi-square p-values (avg p {avg_p_b:.4f} vs {avg_p_e:.4f}).")

        # Predictability comparison
        avg_pred_b = sum(b["predictability"]) / len(b["predictability"])
        avg_pred_e = sum(e["predictability"]) / len(e["predictability"])
        if abs(avg_pred_e) < abs(avg_pred_b):
            print(f"* EMN shows lower predictability (avg r {avg_pred_e:.6f} vs {avg_pred_b:.6f}).")
        else:
            print(f"* Baseline shows lower predictability (avg r {avg_pred_b:.6f} vs {avg_pred_e:.6f}).")

def main():
    sim = LowEntropySim(bits=16)
    def baseline_randfunc():
        seed = sim.get_seed()
        random.seed(seed)
        def rf(n):
            return random.getrandbits(8 * n).to_bytes(n,"big")
        return rf
    
    from phase2_emn import EMN_PRNG,SHA256CTR
    emn = EMN_PRNG(P_seed=None,injection_frequency=10)
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
