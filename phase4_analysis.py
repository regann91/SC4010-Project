import matplotlib.pyplot as plt
import math

def plot_entropy_comparison(cmp):
    baseline_ents = cmp.stats["baseline"]["ents"]
    emn_ents = cmp.stats["emn"]["ents"]

    plt.figure(figsize=(12,6))
    plt.hist(baseline_ents,bins=50,alpha=0.6,label="Baseline RNG")
    plt.hist(emn_ents,bins=50,alpha=0.6,label="EMN-enhanced RNG")
    plt.xlabel("Shannon Entropy (bits/byte)")
    plt.ylabel("Number of Keys")
    plt.title("Distribution of Modulus Entropy")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_nist_pass_rates(cmp):
    baseline_nist = cmp.stats["baseline"]["nist"]
    emn_nist = cmp.stats["emn"]["nist"]

    def calc_pass_rate(nist_list):
        total_tests = len(nist_list) * 5
        passed = 0
        for entry in nist_list:
            if entry["freq"]  >= 0.01: passed += 1
            if entry["block"] >= 0.01: passed += 1
            if entry["runs"]  >= 0.01: passed += 1
            if entry["lrun"]  >= 0.01: passed += 1
            if entry["apent"] >= 0.01: passed += 1
        return passed / total_tests

    baseline_rate = calc_pass_rate(baseline_nist)
    emn_rate = calc_pass_rate(emn_nist)

    plt.figure(figsize=(8,6))
    plt.bar(["Baseline RNG","EMN RNG"],[baseline_rate*100,emn_rate*100],color=["red","green"])
    plt.ylabel("NIST Test Pass Rate (%)")
    plt.title("NIST SP 800-22 Test Pass Rate Comparison")
    plt.ylim(0,100)
    plt.tight_layout()
    plt.show()

def analyze_implications(cmp):
    baseline_ents = cmp.stats["baseline"]["ents"]
    emn_ents = cmp.stats["emn"]["ents"]

    print("=== Phase 4: Implications Analysis ===")
    print("\nPython RNG Design:")
    if sum(baseline_ents)/len(baseline_ents) < 7.5:
        print("* Default Python RNG may provide insufficient entropy for cryptographic use in low-entropy environments.")
    else:
        print("* Python RNG performs reasonably well under current conditions.")

    print("\nEmbedded Cryptographic Systems:")
    shared = 0
    mods = cmp.stats["baseline"]["mods"]
    for i in range(len(mods)):
        for j in range(i+1,len(mods)):
            if mods[i] != mods[j] and math.gcd(mods[i],mods[j]) > 1:
                shared += 1
    if shared > 0:
        print(f"* Low-entropy systems risk key collisions and shared factors,compromising security ({shared} pairs detected).")
    else:
        print("* No shared factors detected; embedded systems should ensure high-entropy sources.")

    print("\nFuture Entropy Management Strategies:")
    print("* Consider using entropy-mixing enhancements like EMN to improve randomness.")
    print("* Monitor NIST test pass rates to detect weak randomness early.")
    print("* Ensure proper seeding at startup in low-entropy environments.")
