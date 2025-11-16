import time,hashlib,math
from Crypto.PublicKey import RSA
from phase1_baseline import MTBaseline, OSBaseline, ShannonEntropy, NISTTests
from phase2_emn import EMN_PRNG, SHA256CTR



def shannon_entropy_from_mod(n):
    return ShannonEntropy.shannon(n)

class Phase3Compare:
    def __init__(self,num_keys=10,key_size=1024,emn_func=None):
        self.n = int(num_keys)
        self.ks = int(key_size)
        self.stats = {}
        self.emn_func = emn_func

    def _run_experiment(self,label,experiment_class=None, randfunc=None):
        print(f"\n=== {label.upper()} ({self.n} keys) ===")
        s = {"fps": [], "ents": [], "times": [], "mods": [], "nist": [], "predictability": []}
        self.stats[label] = s

        # Phase1-based experiment for MT or OS
        if experiment_class is not None:
            experiment = experiment_class(n_keys=self.n, key_size=self.ks)
            experiment.run()
            for idx, (key, fp, ent, t1) in enumerate(experiment.results):
                mod_bytes = key.n.to_bytes((key.n.bit_length() + 7) // 8, "big")
                s["fps"].append(fp)
                s["ents"].append(ent)
                s["times"].append(t1)
                s["mods"].append(key.n)
                s["predictability"].append(NISTTests.predictability(mod_bytes))

                bits = NISTTests._to_bits(key.n)
                chi_stat, chi_p = NISTTests.chi_square(bits) # type: ignore
                s["nist"].append({
                    "freq": NISTTests.frequency(bits),
                    "block": NISTTests.block_frequency(bits),
                    "runs": NISTTests.runs(bits),
                    "lrun": NISTTests.longest_run(bits),
                    "apent": NISTTests.approximate_entropy(bits),
                    "chi": chi_p,
                    "chi_stat": chi_stat
                })

                print(f"Key {idx+1}: fingerprint {fp[:16]}..., entropy {ent:.4f}, time {t1:.4f}s")

        # Custom RNG (EMN)
        elif randfunc is not None:
            for i in range(self.n):
                # print(f"Generating key {i+1}/{self.n} ...")
                t0 = time.time()
                key = RSA.generate(self.ks, randfunc=randfunc())
                t1 = time.time() - t0

                fp = hashlib.sha256(f"{key.n}:{key.e}".encode()).hexdigest()
                public_n_in_bytes = key.n.to_bytes((key.n.bit_length() + 7) // 8, "big")
                ent = shannon_entropy_from_mod(public_n_in_bytes)
                s["fps"].append(fp)
                s["ents"].append(ent)
                s["times"].append(t1)
                s["mods"].append(key.n)

                bits = NISTTests._to_bits(key.n) # Get the key's public n and convert to bits
                chi_stat, chi_p = NISTTests.chi_square(bits) # type: ignore
                s["nist"].append({
                    "freq": NISTTests.frequency(bits),
                    "block": NISTTests.block_frequency(bits),
                    "runs": NISTTests.runs(bits),
                    "lrun": NISTTests.longest_run(bits),
                    "apent": NISTTests.approximate_entropy(bits),
                    "chi": chi_p,
                    "chi_stat": chi_stat
                })

                s["predictability"].append(NISTTests.predictability(public_n_in_bytes))

                print(f"Key {i+1}: Entropy={ent:.2f}, FP={fp[:8]}..., Time={t1:.4f}s")

    def run(self):
        # MT baseline
        self._run_experiment("mt", experiment_class=MTBaseline)
        # OS baseline
        self._run_experiment("os", experiment_class=OSBaseline)
        # EMN RNG
        self._run_experiment("emn", randfunc=self.emn_func)

    def analyze(self):
        print("=== Phase 3: Comparative Evaluation ===")

        def avg(lst):
            return sum(lst)/len(lst)

        def shared_count(mods):
            count = 0
            for i in range(len(mods)):
                for j in range(i+1, len(mods)):
                    if math.gcd(mods[i], mods[j]) > 1:
                        count += 1
            return count

        # References
        mt = self.stats["mt"]
        os_ = self.stats["os"]
        emn = self.stats["emn"]

        # --- Unique keys ---
        for label, s in [("MT", mt), ("OS", os_), ("EMN", emn)]:
            uniq = len(set(s["fps"]))
            total = len(s["fps"])
            if uniq == total:
                print(f"* {label} RNG: All {total} keys are unique → no immediate entropy issues.")
            else:
                dup = total - uniq
                print(f"* {label} RNG: {dup}/{total} duplicate keys → indicates low entropy in RNG.")

        # --- Entropy ---
        avg_mt = avg(mt["ents"])
        avg_os = avg(os_["ents"])
        avg_emn = avg(emn["ents"])
        print(f"* Shannon entropy (modulus): MT={avg_mt:.3f}, OS={avg_os:.3f}, EMN={avg_emn:.3f}")
        print(f"  Interpretation:")
        if avg_emn > max(avg_mt, avg_os):
            print("    EMN-enhanced RNG achieved the highest entropy → strongest randomness.")
        elif avg_mt > max(avg_os, avg_emn):
            print("    MT RNG shows highest entropy, EMN may not improve in this run.")
        else:
            print("    OS RNG shows highest entropy → strong system randomness baseline.")

        # --- Key generation time ---
        avg_time_mt = avg(mt["times"])
        avg_time_os = avg(os_["times"])
        avg_time_emn = avg(emn["times"])
        print(f"* Avg key generation time: MT={avg_time_mt:.4f}s, OS={avg_time_os:.4f}s, EMN={avg_time_emn:.4f}s")
        print(f"  Interpretation:")
        if avg_time_emn > max(avg_time_mt, avg_time_os):
            print("    EMN adds computational overhead due to enhancement mechanism.")
        else:
            print("    EMN ran comparably fast → low performance penalty.")

        # --- Chi-square stats ---
        chi_mt = avg([entry["chi_stat"] for entry in mt["nist"]])
        chi_os = avg([entry["chi_stat"] for entry in os_["nist"]])
        chi_emn = avg([entry["chi_stat"] for entry in emn["nist"]])
        print(f"* Avg Chi-square statistic: MT={chi_mt:.4f}, OS={chi_os:.4f}, EMN={chi_emn:.4f}")
        print(f"  Interpretation:")
        print("    Lower χ² closer to expected uniform → better distribution of bytes.")

        # --- Chi-square p-values ---
        p_mt = avg([entry["chi"] for entry in mt["nist"]])
        p_os = avg([entry["chi"] for entry in os_["nist"]])
        p_emn = avg([entry["chi"] for entry in emn["nist"]])
        print(f"* Avg Chi-square p-value: MT={p_mt:.4f}, OS={p_os:.4f}, EMN={p_emn:.4f}")
        print(f"  Interpretation:")
        for label, p_val in [("MT", p_mt), ("OS", p_os), ("EMN", p_emn)]:
            if p_val >= 0.01:
                print(f"    {label}: Passes χ² uniformity test (p={p_val:.4f})")
            else:
                print(f"    {label}: Fails χ² uniformity test (p={p_val:.4f}) → potential non-uniformity")

        # --- Predictability ---
        pred_mt = avg(mt["predictability"])
        pred_os = avg(os_["predictability"])
        pred_emn = avg(emn["predictability"])
        print(f"* Average predictability (correlation r): MT={pred_mt:.6f}, OS={pred_os:.6f}, EMN={pred_emn:.6f}")
        print(f"  Interpretation:")
        for label, r_val in [("MT", pred_mt), ("OS", pred_os), ("EMN", pred_emn)]:
            if abs(r_val) < 0.01:
                print(f"    {label}: Low predictability → successive outputs uncorrelated")
            else:
                print(f"    {label}: Higher correlation (r={r_val:.6f}) → some predictability detected")

        # --- Shared factors ---
        shared_mt = shared_count(mt["mods"])
        shared_os = shared_count(os_["mods"])
        shared_emn = shared_count(emn["mods"])
        print(f"* Shared factors among keys: MT={shared_mt}, OS={shared_os}, EMN={shared_emn}")
        print(f"  Interpretation:")
        for label, count in [("MT", shared_mt), ("OS", shared_os), ("EMN", shared_emn)]:
            if count == 0:
                print(f"    {label}: No keys share factors → safe against factor attacks")
            else:
                print(f"    {label}: {count} key pairs share factors → potential security risk")
def main():
    # EMN RNG setup
    emn = EMN_PRNG(P_seed=None, injection_frequency=10)

    def emn_randfunc():
        O = emn.next_output()
        ctr = SHA256CTR(O)
        return ctr.read

    cmp = Phase3Compare(num_keys=10, key_size=1024, emn_func=emn_randfunc)
    cmp.run()
    cmp.analyze()



if __name__ == "__main__":
    main()
