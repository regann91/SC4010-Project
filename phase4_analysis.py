import matplotlib.pyplot as plt
import math

def plot_entropy_comparison(cmp):
    mt_ents = cmp.stats["mt"]["ents"]
    os_ents = cmp.stats["os"]["ents"]
    emn_ents = cmp.stats["emn"]["ents"]

    plt.figure(figsize=(12,6))
    plt.hist(mt_ents, bins=50, alpha=0.6, label="MT RNG")
    plt.hist(os_ents, bins=50, alpha=0.6, label="OS RNG")
    plt.hist(emn_ents, bins=50, alpha=0.6, label="EMN RNG")
    plt.xlabel("Shannon Entropy (bits/byte)")
    plt.ylabel("Number of Keys")
    plt.title("Distribution of Modulus Entropy")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_nist_pass_rates(cmp):

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
        return (passed / total_tests) * 100

    rates = {
        "MT RNG": calc_pass_rate(cmp.stats["mt"]["nist"]),
        "OS RNG": calc_pass_rate(cmp.stats["os"]["nist"]),
        "EMN RNG": calc_pass_rate(cmp.stats["emn"]["nist"])
    }


    plt.figure(figsize=(8,6))
    plt.bar(rates.keys(), rates.values(), color=["blue","orange","green"])
    plt.ylabel("NIST Test Pass Rate (%)")
    plt.title("NIST SP 800-22 Test Pass Rate Comparison")
    plt.ylim(0,100)
    plt.tight_layout()
    plt.show()

def plot_chi_square_comparison(cmp):
    """Plot chi-square statistics for MT vs OS vs EMN"""
    mt_chi = [entry["chi_stat"] for entry in cmp.stats["mt"]["nist"]]
    os_chi = [entry["chi_stat"] for entry in cmp.stats["os"]["nist"]]
    emn_chi = [entry["chi_stat"] for entry in cmp.stats["emn"]["nist"]]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Chi-square statistics distribution
    ax1.hist(mt_chi, bins=20, alpha=0.6, label="MT RNG", color="blue")
    ax1.hist(os_chi, bins=20, alpha=0.6, label="OS RNG", color="orange")
    ax1.hist(emn_chi, bins=20, alpha=0.6, label="EMN RNG", color="green")
    ax1.axvline(255, color='black', linestyle='--', linewidth=1, label='Expected χ² (df=255)')
    ax1.set_xlabel("Chi-square Statistic (χ²)")
    ax1.set_ylabel("Frequency")
    ax1.set_title("Chi-square Test Statistics Distribution")
    ax1.legend()
    
    # P-values distribution
    mt_p = [entry["chi"] for entry in cmp.stats["mt"]["nist"]]
    os_p = [entry["chi"] for entry in cmp.stats["os"]["nist"]]
    emn_p = [entry["chi"] for entry in cmp.stats["emn"]["nist"]]

    
    ax2.hist(mt_p, bins=20, alpha=0.6, label="MT RNG", color="blue")
    ax2.hist(os_p, bins=20, alpha=0.6, label="OS RNG", color="orange")
    ax2.hist(emn_p, bins=20, alpha=0.6, label="EMN RNG", color="green")
    ax2.axvline(0.01, color='black', linestyle='--', linewidth=1, label='Significance Level (α=0.01)')
    ax2.set_xlabel("Chi-square P-value")
    ax2.set_ylabel("Frequency")
    ax2.set_title("Chi-square P-values Distribution")
    ax2.legend()
    
    plt.tight_layout()
    plt.show()

def plot_predictability_comparison(cmp):
    """Plot predictability (correlation coefficient) for baseline vs EMN"""
    mt_pred = cmp.stats["mt"]["predictability"]
    os_pred = cmp.stats["os"]["predictability"]
    emn_pred = cmp.stats["emn"]["predictability"]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Histogram of correlation coefficients
    ax1.hist(mt_pred, bins=20, alpha=0.6, label="MT RNG", color="blue")
    ax1.hist(os_pred, bins=20, alpha=0.6, label="OS RNG", color="orange")
    ax1.hist(emn_pred, bins=20, alpha=0.6, label="EMN RNG", color="green")
    ax1.axvline(0, color='black', linestyle='--', linewidth=1, label='r = 0 (no correlation)')
    ax1.set_xlabel("Correlation Coefficient (r)")
    ax1.set_ylabel("Frequency")
    ax1.set_title("Predictability: Correlation Between Successive Outputs")
    ax1.legend()
    
    # Box plot comparison
    ax2.boxplot([mt_pred, os_pred, emn_pred], 
                labels=["MT RNG", "OS RNG", "EMN RNG"],
                showmeans=True,
                patch_artist=True)
    ax2.axhline(0, color='black', linestyle='--', linewidth=1, alpha=0.5)
    ax2.set_ylabel("Correlation Coefficient (r)")
    ax2.set_title("Predictability Distribution Comparison")
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.show()

def analyze_implications(cmp):
    print("=== Phase 4: Implications Analysis ===")
    print("\nPython RNG Design:")
    for label in ["mt","os","emn"]:
        ents = cmp.stats[label]["ents"]
        avg_ent = sum(ents)/len(ents)
        print(f"* {label.upper()} average Shannon entropy: {avg_ent:.3f} bits/byte")
        if avg_ent < 7.5:
            print(f"  → {label.upper()} may be weak for cryptographic use in low-entropy environments")
        else:
            print(f"  → {label.upper()} performs reasonably well for cryptography")

    print("\nEmbedded Cryptographic Systems:")
    for label in ["mt","os","emn"]:
        mods = cmp.stats[label]["mods"]
        shared = 0
        for i in range(len(mods)):
            for j in range(i+1,len(mods)):
                if mods[i] != mods[j] and math.gcd(mods[i],mods[j]) > 1:
                    shared += 1
        if shared > 0:
            print(f"* {label.upper()} keys share factors: {shared} pairs → risk of factor attacks")
        else:
            print(f"* {label.upper()} keys share no factors → secure against factor attacks")

    print("\nFuture Entropy Management Strategies:")
    print("* Consider using entropy-mixing enhancements like EMN to improve randomness.")
    print("* Monitor NIST test pass rates to detect weak randomness early.")
    print("* Ensure proper seeding at startup in low-entropy environments.")
