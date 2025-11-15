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
        total_tests = len(nist_list) * 6
        passed = 0
        for entry in nist_list:
            if entry["freq"]  >= 0.01: passed += 1
            if entry["block"] >= 0.01: passed += 1
            if entry["runs"]  >= 0.01: passed += 1
            if entry["lrun"]  >= 0.01: passed += 1
            if entry["apent"] >= 0.01: passed += 1
            if entry["chi"]   >= 0.01: passed += 1
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

def plot_chi_square_comparison(cmp):
    """Plot chi-square statistics for baseline vs EMN"""
    baseline_chi = [entry["chi_stat"] for entry in cmp.stats["baseline"]["nist"]]
    emn_chi = [entry["chi_stat"] for entry in cmp.stats["emn"]["nist"]]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Chi-square statistics distribution
    ax1.hist(baseline_chi, bins=20, alpha=0.6, label="Baseline RNG", color="red")
    ax1.hist(emn_chi, bins=20, alpha=0.6, label="EMN-enhanced RNG", color="green")
    ax1.axvline(255, color='black', linestyle='--', linewidth=1, label='Expected χ² (df=255)')
    ax1.set_xlabel("Chi-square Statistic (χ²)")
    ax1.set_ylabel("Frequency")
    ax1.set_title("Chi-square Test Statistics Distribution")
    ax1.legend()
    
    # P-values distribution
    baseline_pvals = [entry["chi"] for entry in cmp.stats["baseline"]["nist"]]
    emn_pvals = [entry["chi"] for entry in cmp.stats["emn"]["nist"]]
    
    ax2.hist(baseline_pvals, bins=20, alpha=0.6, label="Baseline RNG", color="red")
    ax2.hist(emn_pvals, bins=20, alpha=0.6, label="EMN-enhanced RNG", color="green")
    ax2.axvline(0.01, color='black', linestyle='--', linewidth=1, label='Significance Level (α=0.01)')
    ax2.set_xlabel("Chi-square P-value")
    ax2.set_ylabel("Frequency")
    ax2.set_title("Chi-square P-values Distribution")
    ax2.legend()
    
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
